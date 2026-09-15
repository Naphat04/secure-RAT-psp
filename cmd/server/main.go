package main

import (
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"secure_c2_demo/pkg/crypto"
	"secure_c2_demo/pkg/protocol"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for local demo
	},
}

// KeyConfig matches the structure saved by keygen
type KeyConfig struct {
	PrivateKeyHex string `json:"ser_pri_key"`
	PublicKeyHex  string `json:"ser_pub_key"`
}

// AuthorizedAgents simulates the database of registered agents (from the Enrollment stage)
var AuthorizedAgents = map[string]string{
	"AGENT-001": "secret-token-demo-12345",
	"AGENT-002": "another-valid-secret-999",
}

type ServerState struct {
	serverPriv *ecdh.PrivateKey
	serverPub  *ecdh.PublicKey
}

func main() {
	fmt.Println("================================================================")
	fmt.Println("        C2 MANAGEMENT SERVER (ECDH + HMAC + AES-GCM)            ")
	fmt.Println("================================================================")

	state, err := loadOrGenerateKeys()
	if err != nil {
		log.Fatalf("[!] Failed to initialize server keys: %v", err)
	}

	pubHex := hex.EncodeToString(state.serverPub.Bytes())
	fmt.Printf("[+] Server Public Key (ser_pub_key):\n    %s\n", pubHex)
	fmt.Printf("[+] Registered Agents in Database: %d agents\n", len(AuthorizedAgents))
	for id := range AuthorizedAgents {
		fmt.Printf("    - %s (Secret: [ENROLLED])\n", id)
	}
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("[*] Starting WebSocket listener on :8080...")

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		handleWebSocket(w, r, state)
	})

	fmt.Println("[✓] Server is ready! Waiting for Agent connections at ws://localhost:8080/ws")
	fmt.Println("================================================================")

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("[!] Server error: %v", err)
	}
}

func loadOrGenerateKeys() (*ServerState, error) {
	keyFile := "server_keys.json"
	data, err := os.ReadFile(keyFile)
	if err != nil {
		fmt.Println("[*] server_keys.json not found, generating new server keypair...")
		priv, pub, err := crypto.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
		cfg := KeyConfig{
			PrivateKeyHex: hex.EncodeToString(priv.Bytes()),
			PublicKeyHex:  hex.EncodeToString(pub.Bytes()),
		}
		savedBytes, _ := json.MarshalIndent(cfg, "", "  ")
		_ = os.WriteFile(keyFile, savedBytes, 0600)
		return &ServerState{serverPriv: priv, serverPub: pub}, nil
	}

	var cfg KeyConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("corrupt key file: %w", err)
	}

	privBytes, err := hex.DecodeString(cfg.PrivateKeyHex)
	if err != nil {
		return nil, err
	}
	pubBytes, err := hex.DecodeString(cfg.PublicKeyHex)
	if err != nil {
		return nil, err
	}

	priv, err := crypto.ParsePrivateKey(privBytes)
	if err != nil {
		return nil, err
	}
	pub, err := crypto.ParsePublicKey(pubBytes)
	if err != nil {
		return nil, err
	}

	return &ServerState{serverPriv: priv, serverPub: pub}, nil
}

func handleWebSocket(w http.ResponseWriter, r *http.Request, state *ServerState) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[!] Upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	fmt.Printf("\n[+] [CONNECT] New connection established from %s\n", remoteAddr)

	// ==========================================================
	// STEP 1: Await and parse HandshakeRequest
	// ==========================================================
	_, msgBytes, err := conn.ReadMessage()
	if err != nil {
		log.Printf("[!] Handshake read failed: %v", err)
		return
	}

	var req protocol.HandshakeRequest
	if err := json.Unmarshal(msgBytes, &req); err != nil {
		log.Printf("[!] Invalid handshake JSON: %v", err)
		return
	}

	fmt.Println("----------------------------------------------------------------")
	fmt.Println("[HANDSHAKE 1/5] Receive HandshakeRequest")
	fmt.Printf("    agent_id: %s\n", req.AgentID)
	fmt.Printf("    client_pub_key_hex: %s\n", req.ClientPubKeyHex)
	fmt.Printf("    timestamp: %d\n", req.Timestamp)
	fmt.Printf("    signature: %s\n", req.Signature)

	// Step 1.1: Replay attack check (Timestamp freshness +/- 60 seconds)
	now := time.Now().Unix()
	if math.Abs(float64(now-req.Timestamp)) > 60 {
		fmt.Printf("\n[HANDSHAKE 2/5] REJECTED: timestamp is too old (%d sec difference)\n", now-req.Timestamp)
		sendHandshakeResponse(conn, "REJECTED", "Expired timestamp / replay attack detected")
		return
	}

	// Step 1.2: Identity check in DB
	agentSecret, exists := AuthorizedAgents[req.AgentID]
	if !exists {
		fmt.Printf("\n[HANDSHAKE 2/5] REJECTED: agent_id is not enrolled (%s)\n", req.AgentID)
		sendHandshakeResponse(conn, "REJECTED", "Agent ID not enrolled")
		return
	}

	// Step 1.3: HMAC Authentication check (Prevent Rogue Agent / Key Spoofing)
	hmacData := req.AgentID + req.ClientPubKeyHex + strconv.FormatInt(req.Timestamp, 10)
	isValid := crypto.VerifyHMAC([]byte(agentSecret), []byte(hmacData), req.Signature)
	if !isValid {
		fmt.Println("\n[HANDSHAKE 2/5] REJECTED: HMAC signature mismatch")
		fmt.Println("    agent identity or public key may have been spoofed")
		sendHandshakeResponse(conn, "REJECTED", "Invalid HMAC signature. Rogue Agent blocked!")
		return
	}
	fmt.Println("[HANDSHAKE 2/5] HMAC verified: agent identity accepted")

	// ==========================================================
	// STEP 2: Compute Shared Secret (ECDH X25519)
	// ==========================================================
	clientPubBytes, err := hex.DecodeString(req.ClientPubKeyHex)
	if err != nil {
		fmt.Printf("[!] Failed to decode client public key hex: %v\n", err)
		return
	}

	clientPub, err := crypto.ParsePublicKey(clientPubBytes)
	if err != nil {
		fmt.Printf("[!] Invalid client public key curve point: %v\n", err)
		return
	}

	// Mathematical Diffie-Hellman: ser_pri_key + cli_pub_key
	ssk, err := crypto.ComputeSharedSecret(state.serverPriv, clientPub)
	if err != nil {
		fmt.Printf("[!] Failed to compute shared secret: %v\n", err)
		return
	}

	fmt.Printf("[HANDSHAKE 3/5] Compute Raw SSK with X25519 ECDH\n")
	fmt.Printf("    ECDH input: server_private_key + client_public_key\n")
	fmt.Printf("    Raw SSK                         : %x (%d bytes)\n", ssk, len(ssk))

	// Derive AES-256 Session Key via HKDF
	sessionKey, err := crypto.DeriveKey(ssk, nil, "c2-secure-session-v1", 32)
	if err != nil {
		fmt.Printf("[!] HKDF key derivation failed: %v\n", err)
		return
	}
	fmt.Printf("[HANDSHAKE 4/5] Derive Raw Session Key with HKDF-SHA256\n")
	fmt.Printf("    HKDF input (Raw SSK)            : %x\n", ssk)
	fmt.Printf("    HKDF hash                      : SHA-256\n")
	fmt.Printf("    HKDF salt                      : nil\n")
	fmt.Printf("    HKDF info                      : %q\n", "c2-secure-session-v1")
	fmt.Printf("    HKDF output length             : %d bytes\n", len(sessionKey))
	fmt.Printf("    Raw Session Key                : %x (%d bytes)\n", sessionKey, len(sessionKey))

	// Send handshake confirmation
	if err := sendHandshakeResponse(conn, "SUCCESS", "Handshake authenticated and key derived successfully"); err != nil {
		return
	}
	fmt.Println("[HANDSHAKE 5/5] Session key ready; send SUCCESS to agent")
	fmt.Println("----------------------------------------------------------------")

	// ==========================================================
	// STEP 3: Encrypted Communication Loop
	// ==========================================================
	var writeMu sync.Mutex
	var sequenceCounter uint64 = 0

	// Goroutine to receive encrypted responses from Agent
	go func() {
		for {
			_, encBytes, err := conn.ReadMessage()
			if err != nil {
				fmt.Printf("[-] Agent %s disconnected.\n", req.AgentID)
				return
			}

			var envelope protocol.EncryptedEnvelope
			if err := json.Unmarshal(encBytes, &envelope); err != nil {
				log.Printf("[!] Malformed envelope: %v", err)
				continue
			}

			isFirstResponse := envelope.Sequence == 1
			if isFirstResponse {
				fmt.Printf("\n[TRACE][SERVER RECEIVE] type=%s sequence=%d payload_hex_chars=%d\n", envelope.Type, envelope.Sequence, len(envelope.PayloadHex))
			}
			wirePayload, err := hex.DecodeString(envelope.PayloadHex)
			if err != nil {
				fmt.Printf("    hex decode failed: %v\n", err)
				continue
			}
			if isFirstResponse {
				fmt.Printf("    payload bytes decoded from wire: %d\n", len(wirePayload))
			}

			// Decrypt the actual received payload using AES-GCM.
			decryptedBytes, trace, err := crypto.DecryptDetailed(sessionKey, wirePayload)
			if err != nil {
				if envelope.Sequence == 1 {
					printDecryptTrace("SERVER RESPONSE", trace, err)
				}
				fmt.Printf("[!] 🚨 DECRYPTION FAILED for sequence %d: %v\n", envelope.Sequence, err)
				continue
			}

			var resp protocol.ResponsePayload
			if err := json.Unmarshal(decryptedBytes, &resp); err != nil {
				fmt.Printf("[!] Decrypted payload is not JSON: %s\n", string(decryptedBytes))
				continue
			}
			if resp.CommandID == "CMD-101" {
				printDecryptTrace("SERVER RESPONSE", trace, nil)
			}

			fmt.Println("\n📥 [RECV FROM AGENT]")
			if resp.CommandID == "CMD-101" {
				fmt.Printf("    [🔒 Wire Ciphertext] : %s (length: %d chars)\n", envelope.PayloadHex, len(envelope.PayloadHex))
			}
			fmt.Printf("    [🔓 Decrypted Plain] : Status=%s, CmdID=%s\n", resp.Status, resp.CommandID)
			fmt.Printf("    [📄 Output]           : %s\n", resp.Output)
		}
	}()

	// Send a series of demo C2 commands (Virus Scan, Process list, System Info)
	demoCommands := []protocol.CommandPayload{
		{
			CommandID: "CMD-101",
			Action:    "SCAN_VIRUS",
			Parameters: map[string]interface{}{
				"scan_type": "quick",
				"target":    "C:\\Users",
			},
		},
		{
			CommandID: "CMD-102",
			Action:    "GET_PROCESSES",
			Parameters: map[string]interface{}{
				"limit": 5,
			},
		},
		{
			CommandID: "CMD-103",
			Action:    "SYSTEM_INFO",
		},
	}

	for _, cmd := range demoCommands {
		time.Sleep(3 * time.Second)

		cmdJSON, _ := json.Marshal(cmd)
		encPayload, trace, err := crypto.EncryptDetailed(sessionKey, cmdJSON)
		if err != nil {
			log.Printf("[!] Failed to encrypt command: %v", err)
			continue
		}
		encHex := hex.EncodeToString(encPayload)
		isFirstVirusCommand := cmd.Action == "SCAN_VIRUS"
		if isFirstVirusCommand {
			printEncryptTrace("SERVER COMMAND", trace)
		}

		sequenceCounter++
		envelope := protocol.EncryptedEnvelope{
			Type:       "COMMAND",
			Sequence:   sequenceCounter,
			PayloadHex: encHex,
		}

		envelopeBytes, _ := json.Marshal(envelope)

		writeMu.Lock()
		err = conn.WriteMessage(websocket.TextMessage, envelopeBytes)
		writeMu.Unlock()

		if err != nil {
			log.Printf("[!] Write failed: %v", err)
			return
		}

		fmt.Println("\n📤 [SENT TO AGENT]")
		fmt.Printf("    [🔓 Action Planned]  : %s (ID: %s)\n", cmd.Action, cmd.CommandID)
		if isFirstVirusCommand {
			fmt.Printf("    [🔒 Sent on Wire]   : %s (encrypted AES-256-GCM)\n", encHex)
		}
	}

	// Keep alive
	for {
		time.Sleep(10 * time.Second)
	}
}

func sendHandshakeResponse(conn *websocket.Conn, status string, message string) error {
	resp := protocol.HandshakeResponse{
		Status:  status,
		Message: message,
	}
	bytes, _ := json.Marshal(resp)
	return conn.WriteMessage(websocket.TextMessage, bytes)
}

func printEncryptTrace(label string, trace *crypto.AESGCMTrace) {
	fmt.Printf("\n[TRACE][%s ENCRYPT] AES-256-GCM\n", label)
	fmt.Printf("  1) INPUT\n     plaintext: %q (%d bytes)\n     raw session key: %x (%d bytes)\n", trace.Plaintext, len(trace.Plaintext), trace.Key, len(trace.Key))
	fmt.Printf("  2) GCM OUTPUT\n")
	fmt.Printf("     ciphertext = AES-256-GCM(plaintext, raw session key, nonce)\n")
	fmt.Printf("     auth tag   = GCM-Tag(raw session key, nonce, ciphertext, AAD=nil)\n")
	fmt.Printf("     nonce: %x (%d bytes)\n     ciphertext: %x (%d bytes)\n     auth tag: %x (%d bytes)\n", trace.Nonce, len(trace.Nonce), trace.Ciphertext, len(trace.Ciphertext), trace.AuthTag, len(trace.AuthTag))
	fmt.Printf("  3) PAYLOAD\n     nonce || ciphertext || auth tag\n     total: %d bytes\n", len(trace.Payload))
	fmt.Printf("  4) WIRE\n     payload_hex: %s (%d chars)\n", hex.EncodeToString(trace.Payload), len(trace.Payload)*2)
	printPayloadLayout(trace)
}

func printDecryptTrace(label string, trace *crypto.AESGCMTrace, decryptErr error) {
	if trace == nil {
		return
	}
	fmt.Printf("\n[TRACE][%s DECRYPT] AES-256-GCM\n", label)
	fmt.Printf("  1) RECEIVE\n     payload_hex -> hex.DecodeString -> %d payload bytes\n", len(trace.Payload))
	fmt.Printf("  2) SPLIT\n     nonce: bytes[0:%d] = %x\n     ciphertext: bytes[%d:%d] = %x\n     auth tag: bytes[%d:%d] = %x\n", len(trace.Nonce), trace.Nonce, len(trace.Nonce), len(trace.Nonce)+len(trace.Ciphertext), trace.Ciphertext, len(trace.Nonce)+len(trace.Ciphertext), len(trace.Payload), trace.AuthTag)
	fmt.Printf("  3) VERIFY + DECRYPT\n     raw session key: %x (%d bytes)\n", trace.Key, len(trace.Key))
	if decryptErr != nil {
		fmt.Printf("     authentication: FAILED (%v)\n", decryptErr)
		return
	}
	fmt.Printf("     authentication: PASSED\n")
	fmt.Printf("  4) RESULT\n     plaintext: %q (%d bytes)\n", trace.Plaintext, len(trace.Plaintext))
	printPayloadLayout(trace)
}

func printPayloadLayout(trace *crypto.AESGCMTrace) {
	nonceStart := 0
	nonceEnd := len(trace.Nonce)
	ciphertextStart := nonceEnd
	ciphertextEnd := ciphertextStart + len(trace.Ciphertext)
	authTagStart := ciphertextEnd
	authTagEnd := authTagStart + len(trace.AuthTag)

	fmt.Printf("    [PAYLOAD LAYOUT] total=%d bytes / %d hex chars\n", len(trace.Payload), len(trace.Payload)*2)
	fmt.Printf("        nonce      bytes[%d:%d]   = %x (%d bytes / %d hex chars)\n", nonceStart, nonceEnd, trace.Nonce, len(trace.Nonce), len(trace.Nonce)*2)
	fmt.Printf("        ciphertext bytes[%d:%d] = %x (%d bytes / %d hex chars)\n", ciphertextStart, ciphertextEnd, trace.Ciphertext, len(trace.Ciphertext), len(trace.Ciphertext)*2)
	fmt.Printf("        auth tag   bytes[%d:%d] = %x (%d bytes / %d hex chars)\n", authTagStart, authTagEnd, trace.AuthTag, len(trace.AuthTag), len(trace.AuthTag)*2)
	fmt.Printf("        assembly   = nonce || ciphertext || auth tag\n")
	fmt.Printf("        hex view   = %s | %s | %s\n", hex.EncodeToString(trace.Nonce), hex.EncodeToString(trace.Ciphertext), hex.EncodeToString(trace.AuthTag))
}
