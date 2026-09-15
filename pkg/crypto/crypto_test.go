package crypto_test

import (
	"bytes"
	"testing"

	"secure_c2_demo/pkg/crypto"
)

func TestECDHAndEncryptionPipeline(t *testing.T) {
	// 1. Generate Server Keypair (static)
	serPriv, serPub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server keys: %v", err)
	}

	// 2. Generate Agent Keypair (ephemeral)
	cliPriv, cliPub, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate agent keys: %v", err)
	}

	// 3. User's exact mathematical premise:
	// Server computes: ser_pri_key + cli_pub_key
	serverSSK, err := crypto.ComputeSharedSecret(serPriv, cliPub)
	if err != nil {
		t.Fatalf("Server ECDH failed: %v", err)
	}

	// Agent computes: cli_pri_key + ser_pub_key
	agentSSK, err := crypto.ComputeSharedSecret(cliPriv, serPub)
	if err != nil {
		t.Fatalf("Agent ECDH failed: %v", err)
	}

	// 4. Verify Shared Secret is 100% IDENTICAL
	if !bytes.Equal(serverSSK, agentSSK) {
		t.Fatalf("CRITICAL: Shared secrets do not match!\nServer SSK: %x\nAgent SSK:  %x", serverSSK, agentSSK)
	}
	t.Logf("✓ Mathematical ECDH Success! Shared Secret Fingerprint: %s", crypto.Fingerprint(serverSSK))

	// 5. Derive AES-256 Session Key via HKDF
	serverSessionKey, err := crypto.DeriveKey(serverSSK, nil, "test-info", 32)
	if err != nil {
		t.Fatalf("Server HKDF failed: %v", err)
	}

	agentSessionKey, err := crypto.DeriveKey(agentSSK, nil, "test-info", 32)
	if err != nil {
		t.Fatalf("Agent HKDF failed: %v", err)
	}

	if !bytes.Equal(serverSessionKey, agentSessionKey) {
		t.Fatalf("Session keys do not match!")
	}
	t.Logf("✓ HKDF Key Derivation Success! Session Key: %x", serverSessionKey)

	// 6. Test AES-256-GCM Encryption (Server -> Agent)
	plainCmd := []byte(`{"action":"SCAN_VIRUS","target":"C:\\"}`)
	ciphertext, err := crypto.Encrypt(serverSessionKey, plainCmd)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decryptedCmd, err := crypto.Decrypt(agentSessionKey, ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plainCmd, decryptedCmd) {
		t.Fatalf("Decrypted command does not match original plaintext!")
	}
	t.Logf("✓ AES-256-GCM Encrypt/Decrypt Success! Decrypted: %s", string(decryptedCmd))
}

func TestHMACAuthentication(t *testing.T) {
	secret := []byte("agent-secret-token-12345")
	wrongSecret := []byte("attacker-spoofed-secret")
	data := []byte("AGENT-001|pubkey123|1773000000")

	sig := crypto.ComputeHMAC(secret, data)

	// Legitimate agent with correct secret
	if !crypto.VerifyHMAC(secret, data, sig) {
		t.Fatalf("Valid HMAC was incorrectly rejected!")
	}

	// Rogue agent with wrong secret
	if crypto.VerifyHMAC(wrongSecret, data, sig) {
		t.Fatalf("Rogue agent with wrong secret was incorrectly accepted!")
	}

	// Tampered data
	tamperedData := []byte("AGENT-001|pubkey-TAMPERED|1773000000")
	if crypto.VerifyHMAC(secret, tamperedData, sig) {
		t.Fatalf("Tampered data was incorrectly accepted!")
	}

	t.Logf("✓ HMAC Authentication & Tamper-resistance verified!")
}

func TestAESGCMDetailedTraceAndTamperDetection(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	plaintext := []byte(`{"action":"SCAN_VIRUS","target":"C:\\"}`)

	payload, encryptTrace, err := crypto.EncryptDetailed(key, plaintext)
	if err != nil {
		t.Fatalf("Detailed encryption failed: %v", err)
	}

	if len(encryptTrace.Key) != 32 {
		t.Fatalf("AES-256 key length = %d, want 32", len(encryptTrace.Key))
	}
	if len(encryptTrace.Nonce) != 12 {
		t.Fatalf("GCM nonce length = %d, want 12", len(encryptTrace.Nonce))
	}
	if len(encryptTrace.AuthTag) != 16 {
		t.Fatalf("GCM authentication tag length = %d, want 16", len(encryptTrace.AuthTag))
	}
	if !bytes.Equal(payload, encryptTrace.Payload) {
		t.Fatal("trace payload does not match returned wire payload")
	}
	if len(payload) != 12+len(plaintext)+16 {
		t.Fatalf("wire payload length = %d, want %d", len(payload), 12+len(plaintext)+16)
	}

	decrypted, decryptTrace, err := crypto.DecryptDetailed(key, payload)
	if err != nil {
		t.Fatalf("Detailed decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted plaintext = %q, want %q", decrypted, plaintext)
	}
	if !bytes.Equal(decryptTrace.Nonce, encryptTrace.Nonce) {
		t.Fatal("decryption trace nonce differs from encryption trace nonce")
	}

	tampered := append([]byte(nil), payload...)
	tampered[len(tampered)-1] ^= 0x01
	if _, _, err := crypto.DecryptDetailed(key, tampered); err == nil {
		t.Fatal("tampered authentication tag was accepted")
	}
}
