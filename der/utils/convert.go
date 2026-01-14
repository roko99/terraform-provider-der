package utils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

// CertPEMToDER converts a PEM-encoded certificate to DER format
func CertPEMToDER(pemData []byte) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM certificate")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("expected CERTIFICATE block, got %s", block.Type)
	}

	// Parse to validate it's a valid certificate
	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return block.Bytes, nil
}

// KeyPEMToDER converts a PEM-encoded private key to DER format
func KeyPEMToDER(pemData []byte, password []byte) ([]byte, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM private key")
	}

	keyBytes := block.Bytes

	// Handle encrypted private keys
	if isEncryptedPEMBlock(block) {
		if len(password) == 0 {
			return nil, fmt.Errorf("private key is encrypted but no password provided")
		}

		decrypted, err := decryptPEMBlock(block, password)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
		keyBytes = decrypted
	}

	// Validate the key format and convert to standardized DER
	var err error
	var privKey crypto.PrivateKey

	switch block.Type {
	case "RSA PRIVATE KEY":
		// PKCS#1 format - parse and re-marshal as PKCS#8
		privKey, err = x509.ParsePKCS1PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
		}
		// Convert to PKCS#8 DER format for standardization
		keyBytes, err = x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal RSA key to PKCS#8: %w", err)
		}

	case "EC PRIVATE KEY":
		// SEC1 format - parse and re-marshal as PKCS#8
		privKey, err = x509.ParseECPrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %w", err)
		}
		// Convert to PKCS#8 DER format for standardization
		keyBytes, err = x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal EC key to PKCS#8: %w", err)
		}

	case "PRIVATE KEY":
		// Already in PKCS#8 format
		privKey, err = x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
		}
		// Validate that it's a supported key type
		switch privKey.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			// Supported types
		default:
			return nil, fmt.Errorf("unsupported private key type")
		}
		// No need to re-marshal, it's already in PKCS#8 DER format

	default:
		return nil, fmt.Errorf("unsupported private key format: %s (expected RSA PRIVATE KEY, EC PRIVATE KEY, or PRIVATE KEY)", block.Type)
	}

	return keyBytes, nil
}

// isEncryptedPEMBlock checks if a PEM block is encrypted
// Replaces deprecated x509.IsEncryptedPEMBlock
func isEncryptedPEMBlock(b *pem.Block) bool {
	return b.Headers["Proc-Type"] == "4,ENCRYPTED"
}

// decryptPEMBlock decrypts an encrypted PEM block
// Replaces deprecated x509.DecryptPEMBlock
// Note: Legacy PEM encryption is insecure and not recommended
func decryptPEMBlock(b *pem.Block, password []byte) ([]byte, error) {
	// Legacy PEM encryption is deprecated due to weak security
	// We return an error to encourage users to use PKCS#8 encrypted format
	if b.Headers["Proc-Type"] == "4,ENCRYPTED" {
		return nil, fmt.Errorf("encrypted PEM blocks are not supported; please use PKCS#8 encrypted format instead")
	}
	return b.Bytes, nil
}

// GenerateID creates a unique ID for the resource
func GenerateID(value string) string {
	if value == "" {
		return ""
	}
	hash := sha1.Sum([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(hash[:])
}
