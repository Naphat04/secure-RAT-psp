package protocol

// HandshakeRequest is sent by the Agent to initiate key exchange and authenticate itself.
type HandshakeRequest struct {
	AgentID         string `json:"agent_id"`
	ClientPubKeyHex string `json:"client_pub_key_hex"`
	Timestamp       int64  `json:"timestamp"`
	Signature       string `json:"signature"` // HMAC-SHA256(agent_secret, AgentID + ClientPubKeyHex + Timestamp)
}

// HandshakeResponse is returned by the Server after verifying the agent and deriving keys.
type HandshakeResponse struct {
	Status    string `json:"status"` // "SUCCESS" or "REJECTED"
	Message   string `json:"message"`
	SessionID string `json:"session_id,omitempty"`
}

// EncryptedEnvelope wraps all post-handshake traffic between Server and Agent.
type EncryptedEnvelope struct {
	Type       string `json:"type"`        // "COMMAND", "RESPONSE", "HEARTBEAT"
	Sequence   uint64 `json:"sequence"`    // Monotonically increasing sequence number
	PayloadHex string `json:"payload_hex"` // AES-256-GCM encrypted payload (Nonce + Ciphertext + Tag) in hex
}

// CommandPayload is the plaintext payload sent from Server to Agent.
type CommandPayload struct {
	CommandID   string                 `json:"command_id"`
	Action      string                 `json:"action"` // e.g., "SCAN_VIRUS", "GET_SYSTEM_INFO", "SHUTDOWN"
	Parameters  map[string]interface{} `json:"parameters,omitempty"`
}

// ResponsePayload is the plaintext response sent from Agent to Server.
type ResponsePayload struct {
	CommandID string                 `json:"command_id"`
	Status    string                 `json:"status"` // "SUCCESS", "ERROR"
	Output    string                 `json:"output"`
	Details   map[string]interface{} `json:"details,omitempty"`
}
