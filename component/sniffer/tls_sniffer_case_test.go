package sniffer

import (
	"encoding/hex"
	"strings"
	"testing"
)

// clientHelloWithSNI builds a minimal TLS ClientHello carrying one SNI value,
// so the case handling can be tested at the exact point the sniffer reads it.
func clientHelloWithSNI(t *testing.T, name string) []byte {
	t.Helper()
	host := []byte(name)

	// server_name extension: list length, name type 0, name length, name.
	sni := []byte{0x00, 0x00} // extension type: server_name
	body := []byte{0x00}      // name type: host_name
	body = append(body, byte(len(host)>>8), byte(len(host)))
	body = append(body, host...)
	list := append([]byte{byte(len(body) >> 8), byte(len(body))}, body...)
	sni = append(sni, byte(len(list)>>8), byte(len(list)))
	sni = append(sni, list...)

	extensions := sni
	// 2 version + 32 random + 1 session id len + 2 cipher len + 2 cipher
	// + 1 compression len + 1 compression + 2 extensions len
	hello := []byte{0x03, 0x03}
	hello = append(hello, make([]byte, 32)...)
	hello = append(hello, 0x00)                   // session id length
	hello = append(hello, 0x00, 0x02, 0x00, 0x2f) // one cipher suite
	hello = append(hello, 0x01, 0x00)             // one compression method
	hello = append(hello, byte(len(extensions)>>8), byte(len(extensions)))
	hello = append(hello, extensions...)

	handshake := []byte{0x01} // ClientHello
	handshake = append(handshake, byte(len(hello)>>16), byte(len(hello)>>8), byte(len(hello)))
	handshake = append(handshake, hello...)
	return handshake
}

// A client controls the case of the SNI it sends. Every domain rule in mihomo
// compares against a lower-cased payload without normalising the host, so an
// un-normalised SNI made rule matching depend on spelling: mixed case missed
// DOMAIN, DOMAIN-SUFFIX and DOMAIN-KEYWORD alike and fell through to MATCH.
//
// For a plain routing rule that is a misroute. Behind an interception gateway
// it is a complete bypass of the capture set, reachable with one connection.
func TestReadClientHelloNormalisesSNICase(t *testing.T) {
	for _, sent := range []string{
		"gs-loc.apple.com",
		"GS-LOC.APPLE.COM",
		"GS-LOC.Apple.COM",
		"Gs-Loc.Apple.Com",
	} {
		t.Run(sent, func(t *testing.T) {
			got, err := ReadClientHello(clientHelloWithSNI(t, sent))
			if err != nil {
				t.Fatalf("ReadClientHello(%q): %v (hello=%s)", sent, err,
					hex.EncodeToString(clientHelloWithSNI(t, sent))[:64])
			}
			if *got != "gs-loc.apple.com" {
				t.Fatalf("SNI %q was read as %q; rule matching would depend on how the client spelled it", sent, *got)
			}
			if *got != strings.ToLower(sent) {
				t.Fatalf("SNI %q normalised to %q, want %q", sent, *got, strings.ToLower(sent))
			}
		})
	}
}
