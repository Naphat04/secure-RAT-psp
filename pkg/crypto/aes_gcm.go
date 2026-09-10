package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// Encrypt encrypts plaintext using AES-256-GCM.
// A unique 12-byte nonce is generated and prepended to the ciphertext.
// Format: [12 bytes Nonce][Ciphertext + 16 bytes Auth Tag]
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes standard
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	// gcm.Seal appends ciphertext and authentication tag to the nonce
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts a bundled ciphertext (with prepended 12-byte nonce) using AES-256-GCM.
func Decrypt(key []byte, payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(payload) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short: minimum %d bytes required", nonceSize)
	}

	nonce := payload[:nonceSize]
	ciphertext := payload[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption/authentication failed: %w", err)
	}

	return plaintext, nil
}

// EncryptHex encrypts plaintext and returns a hex string for easy terminal printing/JSON transfer.
func EncryptHex(key []byte, plaintext []byte) (string, error) {
	enc, err := Encrypt(key, plaintext)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(enc), nil
}

// DecryptHex decrypts a hex string payload.
func DecryptHex(key []byte, hexPayload string) ([]byte, error) {
	payload, err := hex.DecodeString(hexPayload)
	if err != nil {
		return nil, fmt.Errorf("invalid hex string: %w", err)
	}
	return Decrypt(key, payload)
}
