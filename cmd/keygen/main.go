package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"secure_c2_demo/pkg/crypto"
)

type KeyConfig struct {
	PrivateKeyHex string `json:"ser_pri_key"`
	PublicKeyHex  string `json:"ser_pub_key"`
}

func main() {
	fmt.Println("================================================================")
	fmt.Println("      C2 SERVER KEYPAIR GENERATOR (X25519 Elliptic Curve)       ")
	fmt.Println("================================================================")

	priv, pub, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Printf("[!] Error generating keypair: %v\n", err)
		return
	}

	privHex := hex.EncodeToString(priv.Bytes())
	pubHex := hex.EncodeToString(pub.Bytes())

	config := KeyConfig{
		PrivateKeyHex: privHex,
		PublicKeyHex:  pubHex,
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		fmt.Printf("[!] Error marshalling JSON: %v\n", err)
		return
	}

	fileName := "server_keys.json"
	if err := os.WriteFile(fileName, data, 0600); err != nil {
		fmt.Printf("[!] Error saving keys to file: %v\n", err)
		return
	}

	fmt.Printf("[✓] Generated Server Keypair successfully!\n\n")
	fmt.Printf("🔒 SERVER PRIVATE KEY (ser_pri_key - Keep Secret on Server):\n    %s\n\n", privHex)
	fmt.Printf("📢 SERVER PUBLIC KEY  (ser_pub_key - Hardcode in Agent):\n    %s\n\n", pubHex)
	fmt.Printf("[+] Keys saved to: %s\n", fileName)
	fmt.Println("================================================================")
}
