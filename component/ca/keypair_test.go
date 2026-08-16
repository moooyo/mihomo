package ca

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/tls"
	"github.com/stretchr/testify/require"
)

type keyPairTestClock struct {
	now time.Time
}

func (c *keyPairTestClock) Now() time.Time {
	return c.now
}

func (c *keyPairTestClock) Advance(duration time.Duration) {
	c.now = c.now.Add(duration)
}

func TestTLSKeyPairFileLoaderReloadsAfterAtomicSymlinkSwitch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("atomic symlink replacement requires Unix symlink semantics")
	}

	root := t.TempDir()
	certificateOne, privateKeyOne := newTestTLSKeyPair(t)
	certificateTwo, privateKeyTwo := newTestTLSKeyPair(t)
	writeTestTLSGeneration(t, root, "generation-one", certificateOne, privateKeyOne)
	writeTestTLSGeneration(t, root, "generation-two", certificateTwo, privateKeyTwo)
	replaceTestSymlink(t, filepath.Join(root, "current"), "generation-one")

	clock := &keyPairTestClock{now: time.Unix(1, 0)}
	loader, err := newTLSKeyPairFileLoader(
		filepath.Join(root, "current", "certificate.pem"),
		filepath.Join(root, "current", "private-key.pem"),
		time.Second,
		clock.Now,
	)
	require.NoError(t, err)

	loadedOne, err := loader.load()
	require.NoError(t, err)
	requireCertificatePEM(t, loadedOne, certificateOne)

	replaceTestSymlink(t, filepath.Join(root, "current"), "generation-two")
	clock.Advance(time.Second)
	loadedTwo, err := loader.load()
	require.NoError(t, err)
	requireCertificatePEM(t, loadedTwo, certificateTwo)
	// A certificate returned to an earlier handshake remains immutable after the
	// loader swaps its active pointer.
	requireCertificatePEM(t, loadedOne, certificateOne)
}

func TestTLSKeyPairFileLoaderKeepsOldPairUntilInvalidReplacementRecovers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("atomic file replacement requires Unix rename semantics")
	}

	root := t.TempDir()
	certificatePath := filepath.Join(root, "certificate.pem")
	privateKeyPath := filepath.Join(root, "private-key.pem")
	certificateOne, privateKeyOne := newTestTLSKeyPair(t)
	certificateTwo, privateKeyTwo := newTestTLSKeyPair(t)
	writeTestTLSFile(t, certificatePath, certificateOne)
	writeTestTLSFile(t, privateKeyPath, privateKeyOne)

	clock := &keyPairTestClock{now: time.Unix(1, 0)}
	loader, err := newTLSKeyPairFileLoader(certificatePath, privateKeyPath, time.Second, clock.Now)
	require.NoError(t, err)

	loadedOne, err := loader.load()
	require.NoError(t, err)
	requireCertificatePEM(t, loadedOne, certificateOne)

	// Replacing only the certificate creates a mismatched pair. The loader must
	// continue serving the last complete pair instead of publishing half of the
	// update or failing new handshakes.
	replaceTestTLSFile(t, certificatePath, certificateTwo)
	clock.Advance(time.Second)
	loadedWhileInvalid, err := loader.load()
	require.NoError(t, err)
	requireCertificatePEM(t, loadedWhileInvalid, certificateOne)

	// Completing the replacement changes the key inode at the same configured
	// path. The next bounded identity check must recover without a restart.
	replaceTestTLSFile(t, privateKeyPath, privateKeyTwo)
	clock.Advance(time.Second)
	loadedTwo, err := loader.load()
	require.NoError(t, err)
	requireCertificatePEM(t, loadedTwo, certificateTwo)
}

func TestTLSKeyPairFileLoaderReloadsInPlaceRewriteWithPreservedMetadata(t *testing.T) {
	root := t.TempDir()
	certificatePath := filepath.Join(root, "certificate.pem")
	privateKeyPath := filepath.Join(root, "private-key.pem")
	certificateOne, privateKeyOne, _, err := NewRandomTLSKeyPair(KeyPairTypeEd25519)
	require.NoError(t, err)
	certificateTwo, privateKeyTwo, _, err := NewRandomTLSKeyPair(KeyPairTypeEd25519)
	require.NoError(t, err)
	certificateOne, certificateTwo = equalLengthTestPEM(certificateOne, certificateTwo)
	privateKeyOne, privateKeyTwo = equalLengthTestPEM(privateKeyOne, privateKeyTwo)
	writeTestTLSFile(t, certificatePath, certificateOne)
	writeTestTLSFile(t, privateKeyPath, privateKeyOne)

	clock := &keyPairTestClock{now: time.Unix(1, 0)}
	loader, err := newTLSKeyPairFileLoader(certificatePath, privateKeyPath, time.Second, clock.Now)
	require.NoError(t, err)
	loadedOne, err := loader.load()
	require.NoError(t, err)
	requireCertificatePEM(t, loadedOne, certificateOne)

	certificateInfo, err := os.Stat(certificatePath)
	require.NoError(t, err)
	privateKeyInfo, err := os.Stat(privateKeyPath)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(certificatePath, []byte(certificateTwo), 0o600))
	require.NoError(t, os.WriteFile(privateKeyPath, []byte(privateKeyTwo), 0o600))
	require.NoError(t, os.Chtimes(certificatePath, certificateInfo.ModTime(), certificateInfo.ModTime()))
	require.NoError(t, os.Chtimes(privateKeyPath, privateKeyInfo.ModTime(), privateKeyInfo.ModTime()))
	certificateAfter, err := os.Stat(certificatePath)
	require.NoError(t, err)
	privateKeyAfter, err := os.Stat(privateKeyPath)
	require.NoError(t, err)
	require.True(t, os.SameFile(certificateInfo, certificateAfter))
	require.True(t, os.SameFile(privateKeyInfo, privateKeyAfter))
	require.Equal(t, certificateInfo.Size(), certificateAfter.Size())
	require.Equal(t, privateKeyInfo.Size(), privateKeyAfter.Size())
	require.True(t, certificateInfo.ModTime().Equal(certificateAfter.ModTime()))
	require.True(t, privateKeyInfo.ModTime().Equal(privateKeyAfter.ModTime()))

	clock.Advance(time.Second)
	loadedTwo, err := loader.load()
	require.NoError(t, err)
	requireCertificatePEM(t, loadedTwo, certificateTwo)
}

func TestLoadStableTLSKeyPairRetriesMixedSymlinkGeneration(t *testing.T) {
	root := t.TempDir()
	certificateOne, privateKeyOne := newTestTLSKeyPair(t)
	certificateTwo, privateKeyTwo := newTestTLSKeyPair(t)
	writeTestTLSGeneration(t, root, "generation-one", certificateOne, privateKeyOne)
	writeTestTLSGeneration(t, root, "generation-two", certificateTwo, privateKeyTwo)
	mixed := tlsKeyPairIdentity{
		certificate: mustInspectTLSFile(t, filepath.Join(root, "generation-one", "certificate.pem")),
		privateKey:  mustInspectTLSFile(t, filepath.Join(root, "generation-two", "private-key.pem")),
	}
	stable := tlsKeyPairIdentity{
		certificate: mustInspectTLSFile(t, filepath.Join(root, "generation-two", "certificate.pem")),
		privateKey:  mustInspectTLSFile(t, filepath.Join(root, "generation-two", "private-key.pem")),
	}
	inspections := 0
	loaded, _, err := loadStableTLSKeyPairWithInspector("certificate", "private-key", func(string, string) (tlsKeyPairIdentity, error) {
		inspections++
		if inspections == 1 {
			return mixed, nil
		}
		return stable, nil
	})
	require.NoError(t, err)
	require.Equal(t, 3, inspections)
	requireCertificatePEM(t, loaded, certificateTwo)
}

func TestTLSKeyPairLoaderKeepsInlinePEMBehavior(t *testing.T) {
	certificate, privateKey := newTestTLSKeyPair(t)
	loader, err := NewTLSKeyPairLoader(certificate, privateKey)
	require.NoError(t, err)

	loaded, err := loader()
	require.NoError(t, err)
	requireCertificatePEM(t, loaded, certificate)
}

func newTestTLSKeyPair(t *testing.T) (string, string) {
	t.Helper()
	certificate, privateKey, _, err := NewRandomTLSKeyPair(KeyPairTypeP256)
	require.NoError(t, err)
	return certificate, privateKey
}

func equalLengthTestPEM(left, right string) (string, string) {
	if len(left) < len(right) {
		left += strings.Repeat("\n", len(right)-len(left))
	} else if len(right) < len(left) {
		right += strings.Repeat("\n", len(left)-len(right))
	}
	return left, right
}

func mustInspectTLSFile(t *testing.T, path string) tlsFileIdentity {
	t.Helper()
	identity, err := inspectTLSFile(path)
	require.NoError(t, err)
	return identity
}

func requireCertificatePEM(t *testing.T, actual *tls.Certificate, certificatePEM string) {
	t.Helper()
	block, _ := pem.Decode([]byte(certificatePEM))
	require.NotNil(t, block)
	require.NotEmpty(t, actual.Certificate)
	require.Equal(t, block.Bytes, actual.Certificate[0])
}

func writeTestTLSGeneration(t *testing.T, root, name, certificate, privateKey string) {
	t.Helper()
	directory := filepath.Join(root, name)
	require.NoError(t, os.Mkdir(directory, 0o700))
	writeTestTLSFile(t, filepath.Join(directory, "certificate.pem"), certificate)
	writeTestTLSFile(t, filepath.Join(directory, "private-key.pem"), privateKey)
}

func writeTestTLSFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func replaceTestTLSFile(t *testing.T, path, content string) {
	t.Helper()
	temporaryPath := path + ".next"
	writeTestTLSFile(t, temporaryPath, content)
	require.NoError(t, os.Rename(temporaryPath, path))
}

func replaceTestSymlink(t *testing.T, path, target string) {
	t.Helper()
	temporaryPath := path + ".next"
	require.NoError(t, os.Symlink(target, temporaryPath))
	require.NoError(t, os.Rename(temporaryPath, path))
}
