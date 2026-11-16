package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunHealthcheck_VerifiesTLSAgainstCA(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "mock-upstream"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"mock-upstream"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}

	tmpDir := t.TempDir()
	caPath := filepath.Join(tmpDir, "ca.crt")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	leafPath := filepath.Join(tmpDir, "leaf.crt")
	if err := os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), 0o600); err != nil {
		t.Fatalf("write leaf.crt: %v", err)
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	srv.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{leafDER},
			PrivateKey:  leafKey,
		}},
	}
	srv.StartTLS()
	defer srv.Close()

	addr := srv.Listener.Addr().String()
	if err := runHealthcheck(addr, caPath, ""); err != nil {
		t.Fatalf("expected healthcheck with trusted CA to succeed: %v", err)
	}
	if err := runHealthcheck(addr, filepath.Join(tmpDir, "missing-ca.crt"), leafPath); err != nil {
		t.Fatalf("expected healthcheck falling back to pinned leaf cert to succeed: %v", err)
	}

	// Untrusted CA must fail certificate verification (ensures InsecureSkipVerify is not enabled).
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate other CA key: %v", err)
	}
	otherDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &otherKey.PublicKey, otherKey)
	if err != nil {
		t.Fatalf("create other CA cert: %v", err)
	}
	otherCAPath := filepath.Join(tmpDir, "other-ca.crt")
	if err := os.WriteFile(otherCAPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: otherDER}), 0o600); err != nil {
		t.Fatalf("write other-ca.crt: %v", err)
	}
	if err := runHealthcheck(addr, otherCAPath, ""); err == nil {
		t.Fatal("expected healthcheck with mismatched CA to fail TLS verification")
	}
}
