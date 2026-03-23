package network

// Message defines the generic structure for all network communications.
// Fields must start with a capital letter to be exported for the JSON package.
type Message struct {
	Type    string `json:"type"`    // e.g., "chat", "handshake", "error"
	Payload string `json:"payload"` // The actual content of the message
}
