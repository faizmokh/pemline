package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mkPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal pkcs8: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func mkPKCS1(t *testing.T, key *rsa.PrivateKey) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func mkEC(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal ec: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// assertEscaped verifies the contract of inlineKey: no real newlines,
// literal \n present, headers preserved, and unescaping round-trips.
func assertEscaped(t *testing.T, pemBytes []byte, header string) {
	t.Helper()
	out, err := inlineKey(pemBytes)
	if err != nil {
		t.Fatalf("inlineKey: %v", err)
	}
	if strings.Contains(out, "\n") {
		t.Errorf("output contains a real newline: %q", out)
	}
	if !strings.Contains(out, `\n`) {
		t.Errorf("output missing escaped \\n: %q", out)
	}
	if !strings.HasPrefix(out, header+`\n`) {
		t.Errorf("begin header not preserved: %q", out)
	}
	if !strings.HasSuffix(out, `\n`+strings.ReplaceAll(header, "BEGIN", "END")) {
		t.Errorf("end header not preserved: %q", out)
	}
	want := string(bytes.TrimSpace(pemBytes))
	if got := strings.ReplaceAll(out, `\n`, "\n"); got != want {
		t.Errorf("round-trip mismatch:\n got=%q\nwant=%q", got, want)
	}
}

func TestInlineKey_PKCS8_EC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	assertEscaped(t, mkPKCS8(t, key), "-----BEGIN PRIVATE KEY-----")
}

func TestInlineKey_PKCS8_ED25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = pub
	assertEscaped(t, mkPKCS8(t, priv), "-----BEGIN PRIVATE KEY-----")
}

func TestInlineKey_PKCS1_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	assertEscaped(t, mkPKCS1(t, key), "-----BEGIN RSA PRIVATE KEY-----")
}

func TestInlineKey_EC_SEC1(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	assertEscaped(t, mkEC(t, key), "-----BEGIN EC PRIVATE KEY-----")
}

func TestInlineKey_TrimsWhitespace(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := mkPKCS8(t, key)
	padded := append([]byte("\n\n  \n"), pemBytes...)
	padded = append(padded, []byte("\n  \n")...)

	out, err := inlineKey(padded)
	if err != nil {
		t.Fatalf("inlineKey: %v", err)
	}
	if strings.Contains(out, "\n") {
		t.Errorf("padding leaked into output as real newline: %q", out)
	}
}

func TestInlineKey_InvalidPEM(t *testing.T) {
	_, err := inlineKey([]byte("this is not a key"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not a valid PEM block") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestInlineKey_ValidPEMNotPrivateKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{PublicKey: &key.PublicKey}, &x509.Certificate{PublicKey: &key.PublicKey}, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	_, err = inlineKey(certPEM)
	if err == nil {
		t.Fatal("expected error for non-private-key PEM, got nil")
	}
	if !strings.Contains(err.Error(), "not a valid private key") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestReadInput_FileFlag(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := mkPKCS8(t, key)

	dir := t.TempDir()
	path := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := readInput(path)
	if err != nil {
		t.Fatalf("readInput: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(pemBytes)) {
		t.Errorf("file content mismatch")
	}
}

func TestReadInput_FileFlagMissingFile(t *testing.T) {
	_, err := readInput(filepath.Join(t.TempDir(), "does-not-exist.pem"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got: %v", err)
	}
}

func TestReadInput_Stdin(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := mkPKCS8(t, key)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig })

	go func() {
		_, _ = w.Write(pemBytes)
		_ = w.Close()
	}()

	got, err := readInput("")
	if err != nil {
		t.Fatalf("readInput: %v", err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(pemBytes)) {
		t.Errorf("stdin content mismatch")
	}
}
