package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// AESGCMTrace contains the actual values produced or consumed by one AES-GCM
// operation. It is intended for this educational demo and includes sensitive
// values that must not be logged in production.
type AESGCMTrace struct {
	Key        []byte
	Nonce      []byte
	Plaintext  []byte
	Ciphertext []byte
	AuthTag    []byte
	Payload    []byte
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

// EncryptDetailed performs real AES-GCM encryption and returns the exact
// nonce, ciphertext, authentication tag, and bundled wire payload.
func EncryptDetailed(key []byte, plaintext []byte) ([]byte, *AESGCMTrace, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate random nonce: %w", err)
	}

	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	tagSize := gcm.Overhead()
	ciphertext := sealed[:len(sealed)-tagSize]
	authTag := sealed[len(sealed)-tagSize:]
	payload := make([]byte, 0, len(nonce)+len(sealed))
	payload = append(payload, nonce...)
	payload = append(payload, sealed...)

	trace := &AESGCMTrace{
		Key:        cloneBytes(key),
		Nonce:      cloneBytes(nonce),
		Plaintext:  cloneBytes(plaintext),
		Ciphertext: cloneBytes(ciphertext),
		AuthTag:    cloneBytes(authTag),
		Payload:    cloneBytes(payload),
	}
	return payload, trace, nil
}

// Encrypt encrypts plaintext using AES-256-GCM.
// A unique 12-byte nonce is generated and prepended to the ciphertext.
// Format: [12 bytes Nonce][Ciphertext + 16 bytes Auth Tag]
func Encrypt(key []byte, plaintext []byte) ([]byte, error) {
	payload, _, err := EncryptDetailed(key, plaintext)
	return payload, err
}

// DecryptDetailed performs real AES-GCM authentication and decryption while
// returning the exact values extracted from the received wire payload.
func DecryptDetailed(key []byte, payload []byte) ([]byte, *AESGCMTrace, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	minimumSize := nonceSize + gcm.Overhead()
	if len(payload) < minimumSize {
		return nil, nil, fmt.Errorf("ciphertext too short: minimum %d bytes required", minimumSize)
	}

	nonce := payload[:nonceSize]
	sealed := payload[nonceSize:]
	tagSize := gcm.Overhead()
	ciphertext := sealed[:len(sealed)-tagSize]
	authTag := sealed[len(sealed)-tagSize:]
	trace := &AESGCMTrace{
		Key:        cloneBytes(key),
		Nonce:      cloneBytes(nonce),
		Ciphertext: cloneBytes(ciphertext),
		AuthTag:    cloneBytes(authTag),
		Payload:    cloneBytes(payload),
	}

	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, trace, fmt.Errorf("decryption/authentication failed: %w", err)
	}
	trace.Plaintext = cloneBytes(plaintext)
	return plaintext, trace, nil
}

// Decrypt decrypts a bundled ciphertext (with prepended 12-byte nonce) using AES-256-GCM.
func Decrypt(key []byte, payload []byte) ([]byte, error) {
	plaintext, _, err := DecryptDetailed(key, payload)
	return plaintext, err
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
