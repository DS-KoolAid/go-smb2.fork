package smb2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// createTestCert creates a test certificate with the specified signature algorithm
func createTestCert(sigAlg x509.SignatureAlgorithm) *x509.Certificate {
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    sigAlg,
	}

	var privKey any
	var pubKey any

	switch sigAlg {
	case x509.ECDSAWithSHA384, x509.ECDSAWithSHA512, x509.ECDSAWithSHA256:
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		privKey = key
		pubKey = &key.PublicKey
	default:
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		privKey = key
		pubKey = &key.PublicKey
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, pubKey, privKey)
	cert, _ := x509.ParseCertificate(certDER)
	return cert
}

func TestHashCertificate(t *testing.T) {
	tests := []struct {
		name        string
		sigAlg      x509.SignatureAlgorithm
		expectBytes int // SHA256=32, SHA384=48, SHA512=64
	}{
		{"SHA256WithRSA uses SHA-256", x509.SHA256WithRSA, 32},
		{"SHA384WithRSA uses SHA-384", x509.SHA384WithRSA, 48},
		{"SHA512WithRSA uses SHA-512", x509.SHA512WithRSA, 64},
		{"ECDSAWithSHA256 uses SHA-256", x509.ECDSAWithSHA256, 32},
		{"ECDSAWithSHA384 uses SHA-384", x509.ECDSAWithSHA384, 48},
		{"ECDSAWithSHA512 uses SHA-512", x509.ECDSAWithSHA512, 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createTestCert(tt.sigAlg)
			hash := HashCertificate(cert)

			if hash == nil {
				t.Fatal("HashCertificate returned nil")
			}
			if len(hash) != tt.expectBytes {
				t.Errorf("expected %d bytes, got %d", tt.expectBytes, len(hash))
			}
		})
	}
}

func TestHashCertificateNil(t *testing.T) {
	hash := HashCertificate(nil)
	if hash != nil {
		t.Error("expected nil for nil cert")
	}
}

func TestComputeChannelBindingToken(t *testing.T) {
	cert := createTestCert(x509.SHA256WithRSA)
	token := ComputeChannelBindingToken(cert)

	if token == nil {
		t.Fatal("ComputeChannelBindingToken returned nil")
	}

	// MD5 hash is always 16 bytes
	if len(token) != 16 {
		t.Errorf("expected 16-byte MD5 hash, got %d bytes", len(token))
	}
}

func TestComputeChannelBindingTokenNil(t *testing.T) {
	token := ComputeChannelBindingToken(nil)
	if token != nil {
		t.Error("expected nil for nil cert")
	}
}

func TestComputeChannelBindingFromConn(t *testing.T) {
	// Test with non-TLS connection
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	token := ComputeChannelBindingFromConn(client)
	if token != nil {
		t.Error("expected nil for non-TLS connection")
	}
}

func TestComputeChannelBindingTokenDeterministic(t *testing.T) {
	cert := createTestCert(x509.SHA256WithRSA)

	token1 := ComputeChannelBindingToken(cert)
	token2 := ComputeChannelBindingToken(cert)

	if string(token1) != string(token2) {
		t.Error("channel binding token should be deterministic for same cert")
	}
}

func TestComputeChannelBindingTokenDifferentCerts(t *testing.T) {
	cert1 := createTestCert(x509.SHA256WithRSA)
	cert2 := createTestCert(x509.SHA256WithRSA)

	token1 := ComputeChannelBindingToken(cert1)
	token2 := ComputeChannelBindingToken(cert2)

	if string(token1) == string(token2) {
		t.Error("different certs should produce different tokens")
	}
}
