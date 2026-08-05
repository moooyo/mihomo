package capture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/tls"
)

// The monolith's capture hand-off rests on one property of mihomo's own
// connection type, and nothing in the tree asserts it: that a *BufferedConn
// whose ClientHello the sniffer has already peeked can be handed to a TLS
// server that knows nothing about any of that, and still complete a handshake.
//
// If it cannot, the capture path needs a manual prepend and every byte-count in
// the design moves. So this is checked here rather than discovered on a gateway.
//
// The property holds by construction -- Peek defers to bufio.Reader.Peek, which
// fills without advancing, and Read defers to bufio.Reader.Read, which drains
// the buffer before touching the socket (common/net/bufconn.go:49-60). The test
// exists because "by construction" is an argument about today's implementation,
// and this is the one place a rebase could silently take the architecture apart.

func testLeaf(t *testing.T, host string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{host},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// peekedSNI reports the SNI the way the capture hook will read it: off the
// buffered bytes, before anything has decided what to do with the connection.
// It is deliberately not a full parser -- the sniffer already owns that -- it
// only has to prove the bytes are readable without consuming them.
func peekedSNI(t *testing.T, c *N.BufferedConn, want string) {
	t.Helper()
	// 5-byte record header + handshake; 512 is comfortably past the SNI of a
	// hello this small, and Peek blocks until that many bytes arrive.
	head, err := c.Peek(512)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("peek: %v", err)
	}
	if len(head) == 0 {
		t.Fatal("peek returned no bytes: the sniffer would have nothing to match on")
	}
	if head[0] != 0x16 {
		t.Fatalf("first byte %#x, want 0x16 (TLS handshake record)", head[0])
	}
	// The SNI travels as a length-prefixed literal inside the extension block,
	// so a substring search over the peeked window is sufficient evidence that
	// the hostname is visible to a matcher at this point.
	if !contains(head, []byte(want)) {
		t.Fatalf("SNI %q not visible in the peeked window", want)
	}
}

func contains(haystack, needle []byte) bool {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return false
	}
outer:
	for i := 0; i+len(needle) <= len(haystack); i++ {
		for j := range needle {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return true
	}
	return false
}

// TestBufferedConnReplaysPeekedClientHello is the gating assertion for the
// in-process capture path.
func TestBufferedConnReplaysPeekedClientHello(t *testing.T) {
	const host = "capture.example.com"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		sni  string
		body []byte
		err  error
	}
	done := make(chan result, 1)

	go func() {
		raw, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer raw.Close()

		// This is the shape of handleTCPConn at the hook point: the connection
		// is buffered, the sniffer has peeked it, and nothing has been consumed.
		buffered := N.NewBufferedConn(raw)
		peekedSNI(t, buffered, host)
		if buffered.Buffered() == 0 {
			done <- result{err: errors.New("nothing buffered after Peek; the hello was consumed")}
			return
		}

		// The hand-off. The TLS server is handed the *BufferedConn, not the
		// socket underneath it, and is told nothing about the peek.
		var seen string
		server := tls.Server(buffered, &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(hi *tls.ClientHelloInfo) (*tls.Certificate, error) {
				seen = hi.ServerName
				leaf := testLeaf(t, host)
				return &leaf, nil
			},
		})
		if err := server.Handshake(); err != nil {
			done <- result{err: err}
			return
		}
		payload, err := io.ReadAll(io.LimitReader(server, 5))
		if err != nil {
			done <- result{err: err}
			return
		}
		_, _ = server.Write([]byte("pong"))
		_ = server.Close()
		done <- result{sni: seen, body: payload}
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	tlsClient := tls.Client(client, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if _, err := tlsClient.Write([]byte("hello")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(tlsClient, reply); err != nil {
		t.Fatalf("client read: %v", err)
	}

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("server side: %v", got.err)
		}
		if got.sni != host {
			t.Errorf("GetCertificate saw SNI %q, want %q", got.sni, host)
		}
		if string(got.body) != "hello" {
			t.Errorf("server read %q, want %q", got.body, "hello")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the server side")
	}
	if string(reply) != "pong" {
		t.Errorf("client read %q, want %q", reply, "pong")
	}
}

// TestBufferedConnReplaysAfterResetPeeked covers the exact call order
// handleTCPConn uses: ResetPeeked() runs before the sniffer, and the capture
// hook fires after it. ResetPeeked must clear only the flag, never the buffer --
// if it ever drops buffered bytes, capture loses the ClientHello and this fails.
func TestBufferedConnReplaysAfterResetPeeked(t *testing.T) {
	const host = "reset.example.com"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	errc := make(chan error, 1)
	go func() {
		raw, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer raw.Close()

		buffered := N.NewBufferedConn(raw)
		buffered.ResetPeeked() // tunnel.go:532, before the sniffer
		if _, err := buffered.Peek(512); err != nil && !errors.Is(err, io.EOF) {
			errc <- err
			return
		}
		if !buffered.Peeked() {
			errc <- errors.New("Peeked() false after Peek")
			return
		}
		buffered.ResetPeeked() // must not disturb what Peek buffered
		if n := buffered.Buffered(); n == 0 {
			errc <- errors.New("ResetPeeked dropped the buffered ClientHello")
			return
		}

		server := tls.Server(buffered, &tls.Config{
			MinVersion: tls.VersionTLS12,
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				leaf := testLeaf(t, host)
				return &leaf, nil
			},
		})
		errc <- server.Handshake()
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	tlsClient := tls.Client(client, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}

	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("server side: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out")
	}
}
