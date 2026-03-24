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

var clients = make(map[net.Conn]bool)

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

	// ============================
	// 2. CHAT ROOM REGISTRATION
	// ============================
	mutex.Lock()
	clients[conn] = true
	mutex.Unlock()

	defer func() {
		mutex.Lock()
		delete(clients, conn)
		mutex.Unlock()
	}()

	// Normal chat loop (same as before)
	for {
		var msg network.Message
		if err := decoder.Decode(&msg); err != nil {
			fmt.Printf("Client %s disconnected.\n", conn.RemoteAddr())
			return
		}
		fmt.Printf("[%s] Received from %s (%s): %s\n", msg.Type, msg.Sender, conn.RemoteAddr(), msg.Payload)
		broadcast(conn, msg)
	}
}

func broadcast(sender net.Conn, message network.Message) {
	mutex.Lock()
	defer mutex.Unlock()

	for client := range clients {
		if client != sender {
			encoder := json.NewEncoder(client)
			encoder.Encode(message)
		}
	}
}
