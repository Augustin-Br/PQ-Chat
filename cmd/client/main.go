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

	// ================
	// 2. START CHAT
	// ================
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter your username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("> ")

	// Launch the receiving goroutine using the EXISTING decoder
	go receiveMessages(decoder)

	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			fmt.Print("> ")
			continue
		}

		// Create the structured message
		msg := network.Message{
			Type:    "chat",
			Sender:  username,
			Payload: input,
		}

		// Encode and send the message in one step
		if err := encoder.Encode(msg); err != nil {
			fmt.Printf("Failed to send message: %v\n", err)
			return
		}

		fmt.Print("> ")
	}
}

// receiveMessages runs in the background and listens for incoming server broadcasts
func receiveMessages(decoder *json.Decoder) {

	for {
		var msg network.Message
		if err := decoder.Decode(&msg); err != nil {
			fmt.Println("\nDisconnected from server")
			os.Exit(0)
		}

		// Print the received message
		fmt.Printf("\r[%s] %s: %s\n> ", msg.Type, msg.Sender, msg.Payload)
	}
}
