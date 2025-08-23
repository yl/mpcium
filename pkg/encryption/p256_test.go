package encryption

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"testing"
)

func TestGenerateP256Keys(t *testing.T) {
	keyData, err := GenerateP256Keys()
	if err != nil {
		t.Fatalf("Failed to generate P256 keys: %v", err)
	}

	// Check that both keys are generated
	if keyData.PublicKeyHex == "" {
		t.Error("Public key hex is empty")
	}
	if keyData.PrivateKeyHex == "" {
		t.Error("Private key hex is empty")
	}

	// Verify the keys are valid hex
	if _, err := hex.DecodeString(keyData.PublicKeyHex); err != nil {
		t.Errorf("Public key is not valid hex: %v", err)
	}
	if _, err := hex.DecodeString(keyData.PrivateKeyHex); err != nil {
		t.Errorf("Private key is not valid hex: %v", err)
	}

	// Verify the keys can be parsed back
	privateKey, err := ParseP256PrivateKey([]byte(keyData.PrivateKeyHex))
	if err != nil {
		t.Errorf("Failed to parse generated private key: %v", err)
	}

	// Verify it's actually P256
	if privateKey.Curve != elliptic.P256() {
		t.Error("Generated key is not P256 curve")
	}

	// Verify public key matches
	publicKeyBytes, err := hex.DecodeString(keyData.PublicKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode public key hex: %v", err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		t.Errorf("Failed to parse generated public key: %v", err)
	}

	ecdsaPubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Public key is not ECDSA")
	}

	if ecdsaPubKey.Curve != elliptic.P256() {
		t.Error("Generated public key is not P256 curve")
	}
}

func TestParseP256PrivateKey_DER(t *testing.T) {
	// Generate a real P256 private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Convert to DER format
	derBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	// Parse it back
	parsedKey, err := ParseP256PrivateKey(derBytes)
	if err != nil {
		t.Fatalf("Failed to parse DER private key: %v", err)
	}

	// Verify it's the same key
	if !privateKey.Equal(parsedKey) {
		t.Error("Parsed key is not equal to original key")
	}
}

func TestParseP256PrivateKey_Hex(t *testing.T) {
	// Generate a real P256 private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Convert to DER format first, then to hex
	derBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	privateKeyHex := hex.EncodeToString(derBytes)

	// Parse it back
	parsedKey, err := ParseP256PrivateKey([]byte(privateKeyHex))
	if err != nil {
		t.Fatalf("Failed to parse hex private key: %v", err)
	}

	// Verify it's the same key
	if !privateKey.Equal(parsedKey) {
		t.Error("Parsed key is not equal to original key")
	}
}

func TestParseP256PrivateKey_InvalidInput(t *testing.T) {
	// Test with invalid hex
	_, err := ParseP256PrivateKey([]byte("invalid-hex"))
	if err == nil {
		t.Error("Expected error for invalid hex input")
	}

	// Test with empty input
	_, err = ParseP256PrivateKey([]byte{})
	if err == nil {
		t.Error("Expected error for empty input")
	}

	// Test with random bytes
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	_, err = ParseP256PrivateKey(randomBytes)
	if err == nil {
		t.Error("Expected error for random bytes input")
	}
}

func TestSignWithP256(t *testing.T) {
	// Generate test keys
	keyData, err := GenerateP256Keys()
	if err != nil {
		t.Fatalf("Failed to generate test keys: %v", err)
	}

	privateKey, err := ParseP256PrivateKey([]byte(keyData.PrivateKeyHex))
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	// Test data to sign
	testData := []byte("Hello, P256 signing!")

	// Sign the data
	signature, err := SignWithP256(privateKey, testData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature is empty")
	}

	// Verify the signature
	hash := sha256.Sum256(testData)
	if !ecdsa.VerifyASN1(&privateKey.PublicKey, hash[:], signature) {
		t.Error("Generated signature is invalid")
	}
}

func TestSignWithP256_InvalidKey(t *testing.T) {
	// Test with nil private key
	_, err := SignWithP256(nil, []byte("test"))
	if err == nil {
		t.Error("Expected error for nil private key")
	}

	// Test with private key that has nil curve
	invalidKey := &ecdsa.PrivateKey{}
	_, err = SignWithP256(invalidKey, []byte("test"))
	if err == nil {
		t.Error("Expected error for private key with nil curve")
	}
	if err.Error() != "invalid private key: curve is nil" {
		t.Errorf("Expected specific error message, got: %v", err)
	}
}

func TestSignWithP256_EmptyData(t *testing.T) {
	// Generate test keys
	keyData, err := GenerateP256Keys()
	if err != nil {
		t.Fatalf("Failed to generate test keys: %v", err)
	}

	privateKey, err := ParseP256PrivateKey([]byte(keyData.PrivateKeyHex))
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	// Test with empty data
	signature, err := SignWithP256(privateKey, []byte{})
	if err != nil {
		t.Fatalf("Failed to sign empty data: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature for empty data is empty")
	}
}

func TestParseP256PrivateKey_With0xPrefix(t *testing.T) {
	// Generate a real P256 private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Convert to DER format first, then to hex with 0x prefix
	derBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	privateKeyHex := "0x" + hex.EncodeToString(derBytes)

	// Parse it back
	parsedKey, err := ParseP256PrivateKey([]byte(privateKeyHex))
	if err != nil {
		t.Fatalf("Failed to parse hex private key with 0x prefix: %v", err)
	}

	// Verify it's the same key
	if !privateKey.Equal(parsedKey) {
		t.Error("Parsed key is not equal to original key")
	}
}

// TestParseP256PrivateKeyFromHex tests parsing the specific private key from hex
func TestParseP256PrivateKeyFromHex(t *testing.T) {
	// Your specific private key
	privateKeyHex := "307702010104205dbfd209d750b8c501818d0075ce0c23d1c59dabc33f0a8d4d3e52b30cbdbb20a00a06082a8648ce3d030107a14403420004cd9f1b35c241103eb25dbdcf0c93d8cbb444150fde72acecea2eafcee97e3c03aad1c8a8170960dcc2b921822cc6ac1795f4692c22b3ed71dab1deb9aee53018"

	keyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	privateKey, err := ParseP256PrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	if privateKey == nil {
		t.Fatal("Private key is nil")
	}

	if privateKey.Curve == nil {
		t.Fatal("Private key curve is nil")
	}

	if privateKey.Curve.Params().Name != "P-256" {
		t.Errorf("Expected P-256 curve, got %s", privateKey.Curve.Params().Name)
	}

	t.Logf("Successfully parsed P-256 private key")
	t.Logf("Curve: %s", privateKey.Curve.Params().Name)
	t.Logf("Private key D: %x", privateKey.D.Bytes())
}

// TestSignAndVerifyWithSpecificKey tests signing and verification with your specific key
func TestSignAndVerifyWithSpecificKey(t *testing.T) {
	// Your specific private key
	privateKeyHex := "307702010104205dbfd209d750b8c501818d0075ce0c23d1c59dabc33f0a8d4d3e52b30cbdbb20a00a06082a8648ce3d030107a14403420004cd9f1b35c241103eb25dbdcf0c93d8cbb444150fde72acecea2eafcee97e3c03aad1c8a8170960dcc2b921822cc6ac1795f4692c22b3ed71dab1deb9aee53018"

	keyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	privateKey, err := ParseP256PrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	// Test data (wallet ID)
	testData := []byte("test-wallet-p256")

	// Sign the data
	signature, err := SignWithP256(privateKey, testData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("Signature is empty")
	}

	t.Logf("Generated signature: %x", signature)
	t.Logf("Signature length: %d bytes", len(signature))

	// Verify the signature
	err = VerifyP256Signature(&privateKey.PublicKey, testData, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	t.Logf("Signature verified successfully")
}

// TestWalletIDSigningFlow tests the complete flow with different wallet IDs
func TestWalletIDSigningFlow(t *testing.T) {
	privateKeyHex := "307702010104205dbfd209d750b8c501818d0075ce0c23d1c59dabc33f0a8d4d3e52b30cbdbb20a00a06082a8648ce3d030107a14403420004cd9f1b35c241103eb25dbdcf0c93d8cbb444150fde72acecea2eafcee97e3c03aad1c8a8170960dcc2b921822cc6ac1795f4692c22b3ed71dab1deb9aee53018"

	testWalletIDs := []string{
		"test-wallet-p256",
		"aa7a8764-0899-45ad-9017-ec5a0ec5bfff", // From your logs
		"another-test-wallet",
		"wallet-123",
	}

	keyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	privateKey, err := ParseP256PrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	for _, walletID := range testWalletIDs {
		t.Run(walletID, func(t *testing.T) {
			data := []byte(walletID)

			// Sign
			signature, err := SignWithP256(privateKey, data)
			if err != nil {
				t.Fatalf("Failed to sign wallet ID %s: %v", walletID, err)
			}

			// Verify
			err = VerifyP256Signature(&privateKey.PublicKey, data, signature)
			if err != nil {
				t.Fatalf("Failed to verify signature for wallet ID %s: %v", walletID, err)
			}

			t.Logf("Wallet ID: %s", walletID)
			t.Logf("Signature: %x", signature)
		})
	}
}

// TestParseFromHexString tests parsing when the key is passed as a hex string
func TestParseFromHexString(t *testing.T) {
	privateKeyHex := "307702010104205dbfd209d750b8c501818d0075ce0c23d1c59dabc33f0a8d4d3e52b30cbdbb20a00a06082a8648ce3d030107a14403420004cd9f1b35c241103eb25dbdcf0c93d8cbb444150fde72acecea2eafcee97e3c03aad1c8a8170960dcc2b921822cc6ac1795f4692c22b3ed71dab1deb9aee53018"

	// Test passing hex string as bytes (simulating config loading)
	keyAsBytes := []byte(privateKeyHex)

	privateKey, err := ParseP256PrivateKey(keyAsBytes)
	if err != nil {
		t.Fatalf("Failed to parse private key from hex string: %v", err)
	}

	if privateKey.Curve.Params().Name != "P-256" {
		t.Errorf("Expected P-256 curve, got %s", privateKey.Curve.Params().Name)
	}

	// Test signing to ensure key works
	testData := []byte("test")
	signature, err := SignWithP256(privateKey, testData)
	if err != nil {
		t.Fatalf("Failed to sign with parsed key: %v", err)
	}

	if len(signature) == 0 {
		t.Fatal("Signature is empty")
	}

	t.Logf("Successfully parsed key from hex string and signed data")
}

// TestSignatureConsistency tests that the same data produces different signatures (due to randomness)
// but they all verify correctly
func TestSignatureConsistency(t *testing.T) {
	privateKeyHex := "307702010104205dbfd209d750b8c501818d0075ce0c23d1c59dabc33f0a8d4d3e52b30cbdbb20a00a06082a8648ce3d030107a14403420004cd9f1b35c241103eb25dbdcf0c93d8cbb444150fde72acecea2eafcee97e3c03aad1c8a8170960dcc2b921822cc6ac1795f4692c22b3ed71dab1deb9aee53018"

	keyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	privateKey, err := ParseP256PrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	testData := []byte("test-wallet-p256")
	signatures := make([][]byte, 5)

	// Generate multiple signatures
	for i := 0; i < 5; i++ {
		sig, err := SignWithP256(privateKey, testData)
		if err != nil {
			t.Fatalf("Failed to sign data (iteration %d): %v", i, err)
		}
		signatures[i] = sig

		// Verify each signature
		err = VerifyP256Signature(&privateKey.PublicKey, testData, sig)
		if err != nil {
			t.Fatalf("Failed to verify signature (iteration %d): %v", i, err)
		}

		t.Logf("Signature %d: %x", i, sig)
	}

	// Ensure signatures are different (ECDSA uses random nonce)
	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			if hex.EncodeToString(signatures[i]) == hex.EncodeToString(signatures[j]) {
				t.Errorf(
					"Signatures %d and %d are identical (should be different due to randomness)",
					i,
					j,
				)
			}
		}
	}

	t.Logf("All signatures are unique and verify correctly")
}

// TestPublicKeyExtraction tests extracting and using the public key
func TestPublicKeyExtraction(t *testing.T) {
	privateKeyHex := "307702010104205dbfd209d750b8c501818d0075ce0c23d1c59dabc33f0a8d4d3e52b30cbdbb20a00a06082a8648ce3d030107a14403420004cd9f1b35c241103eb25dbdcf0c93d8cbb444150fde72acecea2eafcee97e3c03aad1c8a8170960dcc2b921822cc6ac1795f4692c22b3ed71dab1deb9aee53018"

	keyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	privateKey, err := ParseP256PrivateKey(keyBytes)
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	publicKey := &privateKey.PublicKey

	// Verify public key properties
	if publicKey.Curve != elliptic.P256() {
		t.Errorf("Public key curve is not P-256")
	}

	// Test that we can marshal and unmarshal the public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	parsedPubKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		t.Fatalf("Failed to parse marshaled public key: %v", err)
	}

	ecdsaPubKey, ok := parsedPubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("Parsed public key is not ECDSA")
	}

	// Sign with original key, verify with reconstructed public key
	testData := []byte("test-data")
	signature, err := SignWithP256(privateKey, testData)
	if err != nil {
		t.Fatalf("Failed to sign: %v", err)
	}

	err = VerifyP256Signature(ecdsaPubKey, testData, signature)
	if err != nil {
		t.Fatalf("Failed to verify with reconstructed public key: %v", err)
	}

	t.Logf("Public key X: %x", publicKey.X.Bytes())
	t.Logf("Public key Y: %x", publicKey.Y.Bytes())
	t.Logf("Public key marshaled: %x", publicKeyBytes)
}
