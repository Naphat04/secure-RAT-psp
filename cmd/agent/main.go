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

	"secure_c2_demo/pkg/crypto"
	"secure_c2_demo/pkg/protocol"

	"github.com/gorilla/websocket"
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

	// Handshake 1: Generate the ephemeral keypair.
	fmt.Println("\n[HANDSHAKE 1/5] Generate ephemeral X25519 keypair")
	cliPriv, cliPub, err := crypto.GenerateKeyPair()
	if err != nil {
		log.Fatalf("[!] Failed to generate ephemeral keypair: %v", err)
	}
	cliPubHex := hex.EncodeToString(cliPub.Bytes())
	fmt.Printf("    Client Ephemeral Public Key (cli_pub_key):\n    %s\n", cliPubHex)

	// Handshake 2: Sign the handshake contents with the enrollment secret.
	timestamp := time.Now().Unix()
	hmacData := *agentID + cliPubHex + strconv.FormatInt(timestamp, 10)
	signature := crypto.ComputeHMAC([]byte(*secret), []byte(hmacData))

	fmt.Println("[HANDSHAKE 2/5] Create HMAC-SHA256 authentication signature")
	fmt.Printf("    input: AgentID + client_pub_key_hex + timestamp\n")
	fmt.Printf("    signature: %s\n", signature)

	// Handshake 3: Send the public handshake data to the server.
	req := protocol.HandshakeRequest{
		AgentID:         *agentID,
		ClientPubKeyHex: cliPubHex,
		Timestamp:       timestamp,
		Signature:       signature,
	}
	reqBytes, err := json.Marshal(req)
	if err != nil {
		log.Fatalf("[!] Failed to encode handshake request: %v", err)
	}

	fmt.Println("[HANDSHAKE 3/5] Send HandshakeRequest to server")
	fmt.Println("    sent fields (private key and enrollment secret are NOT sent):")
	fmt.Printf("    agent_id             : %s\n", req.AgentID)
	fmt.Printf("    client_pub_key_hex   : %s (%d bytes decoded)\n", req.ClientPubKeyHex, len(cliPub.Bytes()))
	fmt.Printf("    timestamp            : %d\n", req.Timestamp)
	fmt.Printf("    signature            : %s\n", req.Signature)
	fmt.Printf("    HMAC input           : AgentID + client_pub_key_hex + timestamp\n")
	fmt.Printf("    WebSocket message    : TextMessage\n")
	fmt.Printf("    JSON bytes           : %s (%d bytes)\n", reqBytes, len(reqBytes))
	if err := conn.WriteMessage(websocket.TextMessage, reqBytes); err != nil {
		log.Fatalf("[!] Failed to send handshake: %v", err)
	}
	fmt.Printf("    [✓] HandshakeRequest sent successfully (%d bytes)\n", len(reqBytes))

	// Handshake 4: Read the server's authentication result.
	_, respBytes, err := conn.ReadMessage()
	if err != nil {
		log.Fatalf("[!] Failed to read handshake response: %v", err)
	}

	var resp protocol.HandshakeResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		log.Fatalf("[!] Invalid handshake response JSON: %v", err)
	}

	if resp.Status != "SUCCESS" {
		fmt.Printf("\n[HANDSHAKE 4/5] REJECTED by server\n")
		fmt.Printf("    Server Reason: %s\n", resp.Message)
		if *isRogue {
			fmt.Println("\n[✓] DEMO PROOF: The Server successfully blocked the Rogue Agent!")
		}
		return
	}

	fmt.Println("[HANDSHAKE 4/5] Server accepted authentication")

	// Handshake 5: Derive the shared encryption key locally.
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

	fmt.Printf("\n[HANDSHAKE 5/5] Derive shared encryption key\n")
	fmt.Printf("    ECDH input: agent_private_key + server_public_key\n")
	fmt.Printf("    Raw SSK                         : %x (%d bytes)\n", ssk, len(ssk))

	// Step 7: Derive AES-256 Session Key via HKDF
	sessionKey, err := crypto.DeriveKey(ssk, nil, "c2-secure-session-v1", 32)
	if err != nil {
		log.Fatalf("[!] HKDF key derivation failed: %v", err)
	}
	fmt.Printf("    HKDF-SHA256 output: Raw Session Key\n")
	fmt.Printf("    HKDF input (Raw SSK)            : %x\n", ssk)
	fmt.Printf("    HKDF hash                      : SHA-256\n")
	fmt.Printf("    HKDF salt                      : nil\n")
	fmt.Printf("    HKDF info                      : %q\n", "c2-secure-session-v1")
	fmt.Printf("    HKDF output length             : %d bytes\n", len(sessionKey))
	fmt.Printf("    Raw Session Key                : %x (%d bytes)\n", sessionKey, len(sessionKey))

	fmt.Println("[✓] HANDSHAKE COMPLETE: secure session is ready")
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

		isFirstCommand := envelope.Sequence == 1
		if isFirstCommand {
			fmt.Printf("\n[TRACE][AGENT RECEIVE] type=%s sequence=%d payload_hex_chars=%d\n", envelope.Type, envelope.Sequence, len(envelope.PayloadHex))
		}
		wirePayload, err := hex.DecodeString(envelope.PayloadHex)
		if err != nil {
			fmt.Printf("    hex decode failed: %v\n", err)
			continue
		}
		if isFirstCommand {
			fmt.Printf("    payload bytes decoded from wire: %d\n", len(wirePayload))
		}

		// Decrypt the actual received payload using AES-GCM.
		decryptedBytes, trace, err := crypto.DecryptDetailed(sessionKey, wirePayload)
		if err != nil {
			if envelope.Sequence == 1 {
				printDecryptTrace("AGENT COMMAND", trace, err)
			}
			fmt.Printf("[!] Decryption error: %v\n", err)
			continue
		}

		var cmd protocol.CommandPayload
		if err := json.Unmarshal(decryptedBytes, &cmd); err != nil {
			fmt.Printf("[!] Decrypted payload is not JSON: %v\n", err)
			continue
		}
		isFirstVirusCommand := cmd.Action == "SCAN_VIRUS"
		if isFirstVirusCommand {
			printDecryptTrace("AGENT COMMAND", trace, nil)
		}

		fmt.Println("\n📥 [COMMAND RECEIVED]")
		if isFirstVirusCommand {
			fmt.Printf("    [🔒 Wire Ciphertext] : %s (length: %d chars)\n", envelope.PayloadHex, len(envelope.PayloadHex))
		}
		fmt.Printf("    [🔓 Decrypted Plain] : Action=%s (ID=%s)\n", cmd.Action, cmd.CommandID)

		// Execute action (Mocking the features from PDF: Windows Defender Scan, Processes, etc.)
		respPayload := executeCommand(cmd)

		// Encrypt response
		respJSON, _ := json.Marshal(respPayload)
		encRespBytes, trace, err := crypto.EncryptDetailed(sessionKey, respJSON)
		if err != nil {
			log.Printf("[!] Encryption error: %v", err)
			continue
		}
		encRespPayload := hex.EncodeToString(encRespBytes)
		if isFirstVirusCommand {
			printEncryptTrace("AGENT RESPONSE", trace)
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
		if isFirstVirusCommand {
			fmt.Printf("    [🔒 Sent on Wire]    : %s (AES-256-GCM)\n", encRespPayload)
		}
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
