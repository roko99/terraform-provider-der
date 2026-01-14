package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestCertPEMToDER(t *testing.T) {
	// Generate a test certificate
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	// Create a self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Test CertPEMToDER
	result, err := CertPEMToDER(certPEM)
	if err != nil {
		t.Fatalf("CertPEMToDER failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("CertPEMToDER returned empty result")
	}
}

func TestKeyPEMToDER(t *testing.T) {
	// Generate a test private key
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Convert to PKCS#1 PEM format (RSA PRIVATE KEY)
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// Test KeyPEMToDER
	result, err := KeyPEMToDER(keyPEM, []byte(""))
	if err != nil {
		t.Fatalf("KeyPEMToDER failed: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("KeyPEMToDER returned empty result")
	}

	// Should return PKCS#8 format
	parsedKey, err := x509.ParsePKCS8PrivateKey(result)
	if err != nil {
		t.Fatalf("Failed to parse PKCS#8 key: %v", err)
	}

	if _, ok := parsedKey.(*rsa.PrivateKey); !ok {
		t.Fatal("Parsed key is not an RSA private key")
	}
}
