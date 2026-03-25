package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"pq-chat/internal/crypto"
	"pq-chat/internal/network"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("Connected to PQ-Server.")

	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

	// ==========================
	// 1. POST-QUANTUM HANDSHAKE
	// ==========================

	// Wait for the Server's Public Key
	var pkMsg network.Message
	if err := decoder.Decode(&pkMsg); err != nil || pkMsg.Type != "handshake_pk" {
		fmt.Println("Handshake failed: expected public key")
		return
	}

	// Decode Base64 and Encapsulate
	pubKey, _ := base64.StdEncoding.DecodeString(pkMsg.Payload)
	ciphertext, sharedSecret, err := crypto.Encapsulate(pubKey)
	if err != nil {
		fmt.Println("Encapsulation failed:", err)
		return
	}

	// Send Ciphertext back to Server
	ctxMsg := network.Message{
		Type:    "handshake_ctx",
		Sender:  "Client",
		Payload: base64.StdEncoding.EncodeToString(ciphertext),
	}
	if err := encoder.Encode(ctxMsg); err != nil {
		return
	}

	fmt.Printf("Handshake done. \nShared Secret starts with: %x\n", sharedSecret[:4])

	// =======================
	// 2. SETUP SECURE SESSION
	// =======================

	session, err := crypto.NewSecureSession(sharedSecret)
	if err != nil {
		fmt.Println("Failed to create secure session:", err)
		return
	}

	// ================
	// 3. START CHAT
	// ================

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter your username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("> ")

	// Launch the receiving goroutine, passing the secure session
	go receiveMessages(decoder, session)

	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			fmt.Print("> ")
			continue
		}

		// Encrypt the user input
		encryptedPayload := session.Encrypt([]byte(input))

		// Create the structured message with the Base64 encoded ciphertext
		msg := network.Message{
			Type:    "chat",
			Sender:  username,
			Payload: base64.StdEncoding.EncodeToString(encryptedPayload),
		}

		// Encode and send the message in one step
		if err := encoder.Encode(msg); err != nil {
			fmt.Printf("Failed to send message: %v\n", err)
			return
		}

		fmt.Print("> ")
	}
}

// receiveMessages runs in the background and listens for incoming server broadcasts.
// It uses the secure session to authenticate and decrypt incoming messages.
func receiveMessages(decoder *json.Decoder, session *crypto.SecureSession) {

	for {
		var msg network.Message
		if err := decoder.Decode(&msg); err != nil {
			fmt.Println("\nDisconnected from server")
			os.Exit(0)
		}

		// 1. Decode the Base64 payload back to raw encrypted bytes
		ciphertext, err := base64.StdEncoding.DecodeString(msg.Payload)
		if err != nil {
			fmt.Printf("\r[Warning] Failed to decode base64 payload from %s: %v\n> ", msg.Sender, err)
			continue // Skip this message and wait for the next one
		}

		// 2. Decrypt and authenticate the payload
		plaintext, err := session.Decrypt(ciphertext)
		if err != nil {
			// If decryption fails, it could be tampering, replay attack, or wrong key!
			fmt.Printf("\r[Warning] Decryption failed for message from %s: %v\n> ", msg.Sender, err)
			continue
		}

		// 3. Print the authentic, decrypted message
		fmt.Printf("\r[%s] %s: %s\n> ", msg.Type, msg.Sender, string(plaintext))
	}
}
