package network

// Define constants for all valid message types to prevent typos
const (
	// Outer Tunnel Handshake
	TypeHandshakePK  = "handshake_pk"
	TypeHandshakeCtx = "handshake_ctx"

	// Standard Server-Routed Chat
	TypeChat = "chat"

	// E2EE Key Directory Operations
	TypeE2ERegister = "e2e_register" // Client -> Server: "Here is my Kyber Public Key"
	TypeE2EKeyReq   = "e2e_key_req"  // Client -> Server: "Give me Bob's Public Key"
	TypeE2EKeyResp  = "e2e_key_resp" // Server -> Client: "Here is Bob's Public Key" (or Error)

	// E2EE Session & Messaging
	TypeE2ESessionInit = "e2e_session_init" // Client -> Client (via Server): "Here is the Kyber Ciphertext to start our session"
	TypeE2EChat        = "e2e_chat"         // Client -> Client (via Server): AES-GCM encrypted private message

	// System Messages
	TypeError = "error"
)

// Message defines the generic structure for all network communications.
type Message struct {
	Type    string `json:"type"`    // Uses one of the constants above
	Sender  string `json:"sender"`  // The user's chosen nickname
	Target  string `json:"target"`  // The receiver (Empty means everyone)
	Payload string `json:"payload"` // The actual content of the message
}
