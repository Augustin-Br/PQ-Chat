package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"pq-chat/internal/crypto"
	"sync"

	"pq-chat/internal/network"
)

type Client struct {
	Session  *crypto.SecureSession
	Username string
}

var clients = make(map[net.Conn]*Client)

var mutex = &sync.Mutex{}

func main() {
	// 1. Listen for incoming connections
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Printf("Startup error: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Println("PQ-Server listening on :8080...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("Accept error: %v\n", err)
			continue
		}

		// 2. Handle each connection in a dedicated goroutine
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	fmt.Printf("New connection from: %s\n", conn.RemoteAddr())

	encoder := json.NewEncoder(conn)
	decoder := json.NewDecoder(conn)

	// ============================
	// 1. POST-QUANTUM HANDSHAKE
	// ============================

	// Generate Kyber Keypair
	pubKey, privKey, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Println("Crypto error:", err)
		return
	}

	// Send Public Key to Client
	pkMsg := network.Message{
		Type:    "handshake_pk",
		Sender:  "Server",
		Payload: base64.StdEncoding.EncodeToString(pubKey),
	}
	if err := encoder.Encode(pkMsg); err != nil {
		return
	}
	fmt.Println("Sent Kyber Public Key to client")

	// Wait for Client to send back the Ciphertext
	var ctxMsg network.Message
	if err := decoder.Decode(&ctxMsg); err != nil || ctxMsg.Type != "handshake_ctx" {
		fmt.Println("Handshake failed: expected ciphertext")
		return
	}

	// Decapsulate the Secret
	ciphertext, _ := base64.StdEncoding.DecodeString(ctxMsg.Payload)
	sharedSecret, err := crypto.Decapsulate(privKey, ciphertext)
	if err != nil {
		fmt.Println("Decapsulation failed:", err)
		return
	}

	fmt.Printf("Handshake done\n Shared Secret starts with: %x\n", sharedSecret[:4])

	// ========
	// 2. CHAT
	// ========

	session, err := crypto.NewSecureSession(sharedSecret)
	if err != nil {
		fmt.Println("Failed to create session:", err)
		return
	}

	// Create the Client object. Username is empty initially.
	clientData := &Client{
		Session:  session,
		Username: "",
	}

	mutex.Lock()
	clients[conn] = clientData
	mutex.Unlock()

	defer func() {
		mutex.Lock()
		delete(clients, conn)
		mutex.Unlock()
	}()

	// Normal chat loop
	for {
		var msg network.Message
		if err := decoder.Decode(&msg); err != nil {
			fmt.Printf("Client %s disconnected.\n", conn.RemoteAddr())
			return
		}

		// 1. Decode the incoming Base64 payload
		ciphertext, err := base64.StdEncoding.DecodeString(msg.Payload)
		if err != nil {
			fmt.Printf("Warning: failed to decode base64 from %s: %v\n", conn.RemoteAddr(), err)
			continue
		}

		// 2. Decrypt the message using THIS client's secure session
		plaintext, err := session.Decrypt(ciphertext)
		if err != nil {
			fmt.Printf("Warning: decryption failed for %s: %v\n", conn.RemoteAddr(), err)
			continue
		}

		// 3. Replace the payload with the actual plaintext
		msg.Payload = string(plaintext)

		// =================
		// 4. ANTI-SPOOFING
		// =================
		if clientData.Username == "" {
			clientData.Username = msg.Sender
			fmt.Printf("Registered new user: %s (%s)\n", clientData.Username, conn.RemoteAddr())
		} else {
			msg.Sender = clientData.Username
		}

		fmt.Printf("[%s] Decrypted from %s (%s): %s\n", msg.Type, msg.Sender, conn.RemoteAddr(), msg.Payload)

		// 5. Broadcast the PLAINTEXT message
		broadcast(conn, msg)
	}
}

func broadcast(sender net.Conn, message network.Message) {
	mutex.Lock()
	defer mutex.Unlock()

	// clientData is of type *Client
	for clientConn, clientData := range clients {
		if clientConn != sender {
			msgToSend := message

			// We access the Encrypt method through the Session field of the Client struct
			encryptedPayload := clientData.Session.Encrypt([]byte(message.Payload))

			msgToSend.Payload = base64.StdEncoding.EncodeToString(encryptedPayload)

			encoder := json.NewEncoder(clientConn)
			if err := encoder.Encode(msgToSend); err != nil {
				fmt.Printf("Error sending message to %s: %v\n", clientConn.RemoteAddr(), err)
			}
		}
	}
}
