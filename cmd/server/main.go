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

	"github.com/gorilla/websocket"
	"secure_c2_demo/pkg/crypto"
	"secure_c2_demo/pkg/protocol"
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
	fmt.Println("                   🤝 HANDSHAKE VERIFICATION                   ")
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf("[1] Handshake received from AgentID: %s\n", req.AgentID)
	fmt.Printf("    Client Public Key (cli_pub_key): %s\n", req.ClientPubKeyHex)
	fmt.Printf("    Client Timestamp               : %d\n", req.Timestamp)
	fmt.Printf("    Client Signature (HMAC)        : %s\n", req.Signature)

	// Step 1.1: Replay attack check (Timestamp freshness +/- 60 seconds)
	now := time.Now().Unix()
	if math.Abs(float64(now-req.Timestamp)) > 60 {
		fmt.Printf("\n[!] 🚨 SECURITY REJECTION: Replay attack detected! Timestamp delta too large (%d sec)\n", now-req.Timestamp)
		sendHandshakeResponse(conn, "REJECTED", "Expired timestamp / replay attack detected")
		return
	}

	// Step 1.2: Identity check in DB
	agentSecret, exists := AuthorizedAgents[req.AgentID]
	if !exists {
		fmt.Printf("\n[!] 🚨 SECURITY REJECTION: Unknown Agent ID '%s'. Not registered in database!\n", req.AgentID)
		sendHandshakeResponse(conn, "REJECTED", "Agent ID not enrolled")
		return
	}

	// Step 1.3: HMAC Authentication check (Prevent Rogue Agent / Key Spoofing)
	hmacData := req.AgentID + req.ClientPubKeyHex + strconv.FormatInt(req.Timestamp, 10)
	isValid := crypto.VerifyHMAC([]byte(agentSecret), []byte(hmacData), req.Signature)
	if !isValid {
		fmt.Println("\n[!] 🚨 SECURITY ALERT: HMAC SIGNATURE MISMATCH!")
		fmt.Println("    Someone is trying to spoof Agent ID or injected a fake Public Key!")
		fmt.Println("    Connection is terminated immediately.")
		sendHandshakeResponse(conn, "REJECTED", "Invalid HMAC signature. Rogue Agent blocked!")
		return
	}
	fmt.Println("\n[✓] [2] HMAC Verification: PASSED (Authentic Agent Identity Confirmed)")

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

	sskFingerprint := crypto.Fingerprint(ssk)
	fmt.Printf("[✓] [3] ECDH Shared Secret (SSK) Computed!\n")
	fmt.Printf("    Formula: ECDH(ser_pri_key, cli_pub_key)\n")
	fmt.Printf("    🔑 SSK Fingerprint (SHA-256)   : %s\n", sskFingerprint)

	// Derive AES-256 Session Key via HKDF
	sessionKey, err := crypto.DeriveKey(ssk, nil, "c2-secure-session-v1", 32)
	if err != nil {
		fmt.Printf("[!] HKDF key derivation failed: %v\n", err)
		return
	}
	sessionKeyFingerprint := crypto.Fingerprint(sessionKey)
	fmt.Printf("[✓] [4] Derived Session Key via HKDF-SHA256!\n")
	fmt.Printf("    🛡️ Session Key Fingerprint     : %s\n", sessionKeyFingerprint)

	// Send handshake confirmation
	if err := sendHandshakeResponse(conn, "SUCCESS", "Handshake authenticated and key derived successfully"); err != nil {
		return
	}
	fmt.Println("----------------------------------------------------------------")
	fmt.Println("    🎉 SECURE ENCRYPTED SESSION ESTABLISHED WITH AGENT!        ")
	fmt.Println("----------------------------------------------------------------\n")

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

			// Decrypt ciphertext using sessionKey
			decryptedBytes, err := crypto.DecryptHex(sessionKey, envelope.PayloadHex)
			if err != nil {
				fmt.Printf("[!] 🚨 DECRYPTION FAILED for sequence %d: %v\n", envelope.Sequence, err)
				continue
			}

			var resp protocol.ResponsePayload
			if err := json.Unmarshal(decryptedBytes, &resp); err != nil {
				fmt.Printf("[!] Decrypted payload is not JSON: %s\n", string(decryptedBytes))
				continue
			}

			fmt.Println("\n📥 [RECV FROM AGENT]")
			fmt.Printf("    [🔒 Wire Ciphertext] : %s... (length: %d chars)\n", envelope.PayloadHex[:32], len(envelope.PayloadHex))
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
		encHex, err := crypto.EncryptHex(sessionKey, cmdJSON)
		if err != nil {
			log.Printf("[!] Failed to encrypt command: %v", err)
			continue
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
		fmt.Printf("    [🔒 Sent on Wire]   : %s... (encrypted AES-256-GCM)\n", encHex[:32])
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
