package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// ComputeHMAC generates a hex-encoded HMAC-SHA256 signature for the given data using the secret.
func ComputeHMAC(secret []byte, data []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyHMAC validates the HMAC-SHA256 signature using constant-time comparison
// to prevent timing attacks.
func VerifyHMAC(secret []byte, data []byte, expectedHex string) bool {
	expectedBytes, err := hex.DecodeString(expectedHex)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(data)
	actualBytes := mac.Sum(nil)
	return hmac.Equal(actualBytes, expectedBytes)
}
 