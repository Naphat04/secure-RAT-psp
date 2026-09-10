package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
	"secure_c2_demo/pkg/crypto"
	"secure_c2_demo/pkg/protocol"
)

// Default server public key (will be overridden by server_keys.json if present)
const DefaultServerPubKeyHex = "dc003f6adbbab9cdd9106acd4ca1095e08d1a4dda0553cdaa054a01f9c87363b"

type KeyConfig struct {
	PublicKeyHex string `json:"ser_pub_key"`
}

func main() {
	serverURL := flag.String("url", "ws://localhost:8080/ws", "C2 Server WebSocket URL")
	agentID := flag.String("id", "AGENT-001", "Agent Identifier (from enrollment)")
	secret := flag.String("secret", "secret-token-demo-12345", "Agent Secret Token (from enrollment)")
	isRogue := flag.Bool("rogue", false, "Simulate Rogue Agent (Attacker attempting to spoof agent with invalid secret)")
	flag.Parse()

	fmt.Println("================================================================")
	if *isRogue {
		fmt.Println("    🚨 SIMULATING ROGUE AGENT (ATTACKER / SPOOFING TEST)        ")
		// Tamper with the secret to show how the server blocks it
		*secret = "attacker-fake-secret-99999"
	} else {
		fmt.Println("               GO AGENT CLIENT (C2 ENDPOINT)                    ")
	}
	fmt.Println("================================================================")

	// Step 0: Obtain Server's Public Key (Hardcoded or loaded from config)
	serverPubKeyHex := loadServerPubKey()
	fmt.Printf("[+] Hardcoded Server Public Key (ser_pub_key):\n    %s\n", serverPubKeyHex)
	fmt.Printf("[+] Agent Identity: %s\n", *agentID)
	if *isRogue {
		fmt.Printf("[!] Using INVALID/SPOOFED Secret: %s\n", *secret)
	} else {
		fmt.Printf("[+] Valid Enrollment Secret Loaded\n")
	}
	fmt.Println("----------------------------------------------------------------")

	// Step 1: Connect to Server
	fmt.Printf("[*] Connecting to C2 Server at %s...\n", *serverURL)
	conn, _, err := websocket.DefaultDialer.Dial(*serverURL, nil)
	if err != nil {
		log.Fatalf("[!] Connection failed: %v", err)
	}
	defer conn.Close()
	fmt.Println("[✓] TCP & WebSocket connection established.")

	// Step 2: Generate Ephemeral Keypair (cli_pri_key, cli_pub_key)
	fmt.Println("\n[*] [1] Generating Ephemeral X25519 Keypair for this session...")
	cliPriv, cliPub, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatalf("[!] Failed to generate ephemeral keypair: %v", err)
	}
	cliPubHex := hex.EncodeToString(cliPub.Bytes())
	fmt.Printf("    Client Ephemeral Public Key (cli_pub_key):\n    %s\n", cliPubHex)

	// Step 3: Create HMAC Signature for Authentication & Integrity
	timestamp := time.Now().Unix()
	hmacData := *agentID + cliPubHex + strconv.FormatInt(timestamp, 10)
	signature := crypto.ComputeHMAC([]byte(*secret), []byte(hmacData))

	fmt.Println("[*] [2] Creating HMAC-SHA256 Signature with Agent Secret...")
	fmt.Printf("    Signed Data: AgentID + cli_pub_key + Timestamp\n")
	fmt.Printf("    Signature  : %s\n", signature)

	// Step 4: Transmit HandshakeRequest to Server
	req := protocol.HandshakeRequest{
		AgentID:         *agentID,
		ClientPubKeyHex: cliPubHex,
		Timestamp:       timestamp,
		Signature:       signature,
	}
	reqBytes, _ := json.Marshal(req)

	fmt.Println("[*] [3] Transmitting HandshakeRequest over WebSocket...")
	if err := conn.WriteMessage(websocket.TextMessage, reqBytes); err != nil {
		log.Fatalf("[!] Failed to send handshake: %v", err)
	}

	// Step 5: Read HandshakeResponse
	_, respBytes, err := conn.ReadMessage()
	if err != nil {
		log.Fatalf("[!] Failed to read handshake response: %v", err)
	}

	var resp protocol.HandshakeResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		log.Fatalf("[!] Invalid handshake response JSON: %v", err)
	}

	if resp.Status != "SUCCESS" {
		fmt.Printf("\n[!] 🚨 HANDSHAKE REJECTED BY SERVER!\n")
		fmt.Printf("    Server Reason: %s\n", resp.Message)
		if *isRogue {
			fmt.Println("\n[✓] DEMO PROOF: The Server successfully blocked the Rogue Agent!")
		}
		return
	}

	fmt.Println("[✓] Server accepted handshake!")

	// Step 6: Compute Diffie-Hellman Shared Secret (SSK)
	serverPubBytes, err := hex.DecodeString(serverPubKeyHex)
	if err != nil {
		log.Fatalf("[!] Failed to decode server public key: %v", err)
	}
	serverPub, err := crypto.ParsePublicKey(serverPubBytes)
	if err != nil {
		log.Fatalf("[!] Invalid server public key: %v", err)
	}

	// Mathematical Diffie-Hellman: cli_pri_key + ser_pub_key
	ssk, err := crypto.ComputeSharedSecret(cliPriv, serverPub)
	if err != nil {
		log.Fatalf("[!] Failed to compute shared secret: %v", err)
	}

	sskFingerprint := crypto.Fingerprint(ssk)
	fmt.Printf("\n[✓] [4] ECDH Shared Secret (SSK) Computed on Agent!\n")
	fmt.Printf("    Formula: ECDH(cli_pri_key, ser_pub_key)\n")
	fmt.Printf("    🔑 SSK Fingerprint (SHA-256)   : %s\n", sskFingerprint)

	// Step 7: Derive AES-256 Session Key via HKDF
	sessionKey, err := crypto.DeriveKey(ssk, nil, "c2-secure-session-v1", 32)
	if err != nil {
		log.Fatalf("[!] HKDF key derivation failed: %v", err)
	}
	sessionKeyFingerprint := crypto.Fingerprint(sessionKey)
	fmt.Printf("[✓] [5] Derived Session Key via HKDF-SHA256!\n")
	fmt.Printf("    🛡️ Session Key Fingerprint     : %s\n", sessionKeyFingerprint)

	fmt.Println("----------------------------------------------------------------")
	fmt.Println("    🎉 SECURE SESSION ACTIVE! LISTENING FOR ENCRYPTED COMMANDS ")
	fmt.Println("----------------------------------------------------------------")

	// Step 8: Receive and process encrypted commands
	var sequenceCounter uint64 = 0
	for {
		_, encBytes, err := conn.ReadMessage()
		if err != nil {
			fmt.Println("[-] Server disconnected.")
			return
		}

		var envelope protocol.EncryptedEnvelope
		if err := json.Unmarshal(encBytes, &envelope); err != nil {
			log.Printf("[!] Malformed envelope: %v", err)
			continue
		}

		// Decrypt command using sessionKey
		decryptedBytes, err := crypto.DecryptHex(sessionKey, envelope.PayloadHex)
		if err != nil {
			fmt.Printf("[!] Decryption error: %v\n", err)
			continue
		}

		var cmd protocol.CommandPayload
		if err := json.Unmarshal(decryptedBytes, &cmd); err != nil {
			fmt.Printf("[!] Decrypted payload is not JSON: %v\n", err)
			continue
		}

		fmt.Println("\n📥 [COMMAND RECEIVED]")
		fmt.Printf("    [🔒 Wire Ciphertext] : %s... (length: %d chars)\n", envelope.PayloadHex[:32], len(envelope.PayloadHex))
		fmt.Printf("    [🔓 Decrypted Plain] : Action=%s (ID=%s)\n", cmd.Action, cmd.CommandID)

		// Execute action (Mocking the features from PDF: Windows Defender Scan, Processes, etc.)
		respPayload := executeCommand(cmd)

		// Encrypt response
		respJSON, _ := json.Marshal(respPayload)
		encRespPayload, err := crypto.EncryptHex(sessionKey, respJSON)
		if err != nil {
			log.Printf("[!] Encryption error: %v", err)
			continue
		}

		sequenceCounter++
		respEnvelope := protocol.EncryptedEnvelope{
			Type:       "RESPONSE",
			Sequence:   sequenceCounter,
			PayloadHex: encRespPayload,
		}
		respBytes, _ := json.Marshal(respEnvelope)

		if err := conn.WriteMessage(websocket.TextMessage, respBytes); err != nil {
			log.Printf("[!] Response write failed: %v", err)
			return
		}

		fmt.Println("📤 [ENCRYPTED RESPONSE SENT]")
		fmt.Printf("    [🔓 Plain Result]    : %s\n", respPayload.Output)
		fmt.Printf("    [🔒 Sent on Wire]    : %s... (AES-256-GCM)\n", encRespPayload[:32])
	}
}

func executeCommand(cmd protocol.CommandPayload) protocol.ResponsePayload {
	switch cmd.Action {
	case "SCAN_VIRUS":
		// Mocking Windows Defender MpCmdRun.exe result from PDF (Slide 11)
		return protocol.ResponsePayload{
			CommandID: cmd.CommandID,
			Status:    "SUCCESS",
			Output:    "Windows Defender Scan Completed: Status Code 0 (ไม่พบไวรัส / Clean)",
			Details: map[string]interface{}{
				"engine":     "MpCmdRun.exe",
				"exit_code":  0,
				"scan_type":  "Quick Scan",
				"time_taken": "1.84s",
			},
		}
	case "GET_PROCESSES":
		return protocol.ResponsePayload{
			CommandID: cmd.CommandID,
			Status:    "SUCCESS",
			Output:    "Active Processes: chrome.exe (PID: 1042), code.exe (PID: 3820), agent.exe (PID: 9144)",
			Details: map[string]interface{}{
				"total_running": 142,
				"cpu_usage":     "12.4%",
				"ram_usage":     "42.1%",
			},
		}
	case "SYSTEM_INFO":
		return protocol.ResponsePayload{
			CommandID: cmd.CommandID,
			Status:    "SUCCESS",
			Output:    fmt.Sprintf("OS: %s %s | Hostname: DESKTOP-LAB-01 | Architecture: %s", runtime.GOOS, runtime.GOARCH, runtime.Version()),
		}
	default:
		return protocol.ResponsePayload{
			CommandID: cmd.CommandID,
			Status:    "UNKNOWN_COMMAND",
			Output:    fmt.Sprintf("Command '%s' is not recognized", cmd.Action),
		}
	}
}

func loadServerPubKey() string {
	data, err := os.ReadFile("server_keys.json")
	if err == nil {
		var cfg KeyConfig
		if err := json.Unmarshal(data, &cfg); err == nil && cfg.PublicKeyHex != "" {
			return cfg.PublicKeyHex
		}
	}
	return DefaultServerPubKeyHex
}
