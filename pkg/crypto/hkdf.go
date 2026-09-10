package crypto

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// DeriveKey derives a cryptographically strong symmetric key of specified length
// from the raw Diffie-Hellman shared secret using HKDF-SHA256.
func DeriveKey(sharedSecret []byte, salt []byte, info string, length int) ([]byte, error) {
	kdf := hkdf.New(sha256.New, sharedSecret, salt, []byte(info))
	key := make([]byte, length)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("failed to derive key using HKDF: %w", err)
	}
	return key, nil
}
