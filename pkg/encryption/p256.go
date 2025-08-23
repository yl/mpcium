package encryption

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
)

type KeyData struct {
	PublicKeyHex  string
	PrivateKeyHex string
}

// ParseP256PrivateKey parses a P256 private key from either DER or hex format
func ParseP256PrivateKey(keyData []byte) (*ecdsa.PrivateKey, error) {
	// Try to parse as DER first
	if key, err := x509.ParsePKCS8PrivateKey(keyData); err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecdsaKey, nil
		}
	}

	// Try to parse as EC private key
	if key, err := x509.ParseECPrivateKey(keyData); err == nil {
		return key, nil
	}

	// Try to parse as hex string
	keyStr := strings.TrimSpace(string(keyData))
	if strings.HasPrefix(keyStr, "0x") {
		keyStr = keyStr[2:]
	}

	keyBytes, err := hex.DecodeString(keyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode hex string: %w", err)
	}

	// Try to parse as DER again with decoded hex
	if key, err := x509.ParsePKCS8PrivateKey(keyBytes); err == nil {
		if ecdsaKey, ok := key.(*ecdsa.PrivateKey); ok {
			return ecdsaKey, nil
		}
	}

	if key, err := x509.ParseECPrivateKey(keyBytes); err == nil {
		return key, nil
	}

	return nil, fmt.Errorf("failed to parse P256 private key from DER or hex format")
}

// SignWithP256 signs data using the P256 private key
func SignWithP256(privateKey *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	if privateKey.Curve == nil {
		return nil, fmt.Errorf("invalid private key: curve is nil")
	}

	hash := sha256.Sum256(data)

	// Use crypto/ecdsa.Sign to create a proper P256 signature
	// The signature will be in ASN.1 DER format
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature, nil
}

func GenerateP256Keys() (KeyData, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return KeyData{}, err
	}

	// Convert private key to PEM format
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return KeyData{}, err
	}

	// Convert public key to DER format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return KeyData{}, err
	}

	return KeyData{
		PublicKeyHex:  hex.EncodeToString(publicKeyBytes),
		PrivateKeyHex: hex.EncodeToString(privateKeyBytes),
	}, nil
}

// VerifyP256Signature verifies a P256 signature
func VerifyP256Signature(publicKey *ecdsa.PublicKey, data []byte, signature []byte) error {
	if publicKey == nil {
		return fmt.Errorf("public key is nil")
	}
	if publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("public key is not on P-256 curve")
	}
	if len(signature) == 0 {
		return fmt.Errorf("signature is empty")
	}

	hash := sha256.Sum256(data)

	if !ecdsa.VerifyASN1(publicKey, hash[:], signature) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
