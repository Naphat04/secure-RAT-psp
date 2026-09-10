package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// GenerateKeyPair generates a new ephemeral or static X25519 key pair.
func GenerateKeyPair() (*ecdh.PrivateKey, *ecdh.PublicKey, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate X25519 key: %w", err)
	}
	return priv, priv.PublicKey(), nil
}

// ComputeSharedSecret computes the Diffie-Hellman shared secret (SSK)
// using one party's private key and the peer's public key.
func ComputeSharedSecret(priv *ecdh.PrivateKey, peerPub *ecdh.PublicKey) ([]byte, error) {
	sharedSecret, err := priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("ECDH computation failed: %w", err)
	}
	return sharedSecret, nil
}

// ParsePublicKey decodes raw bytes into an X25519 public key.
func ParsePublicKey(pubBytes []byte) (*ecdh.PublicKey, error) {
	curve := ecdh.X25519()
	pub, err := curve.NewPublicKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 public key: %w", err)
	}
	return pub, nil
}

// ParsePrivateKey decodes raw bytes into an X25519 private key.
func ParsePrivateKey(privBytes []byte) (*ecdh.PrivateKey, error) {
	curve := ecdh.X25519()
	priv, err := curve.NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 private key: %w", err)
	}
	return priv, nil
}

// Fingerprint returns the hex-encoded SHA-256 hash of data (useful for verifying identical keys).
func Fingerprint(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// ShortFingerprint returns the first 16 characters of SHA-256 for compact visual verification.
func ShortFingerprint(data []byte) string {
	fp := Fingerprint(data)
	if len(fp) > 16 {
		return fp[:16]
	}
	return fp
}
