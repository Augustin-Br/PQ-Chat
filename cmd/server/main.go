package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	"pq-chat/internal/network"
)

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

	// 3. Create a JSON decoder for the incoming network stream
	decoder := json.NewDecoder(conn)

	for {
		var msg network.Message

		// 4. Decode the incoming JSON into the msg struct
		if err := decoder.Decode(&msg); err != nil {
			fmt.Printf("Client %s disconnected.\n", conn.RemoteAddr())
			return
		}

		// 5. Access the structured data
		fmt.Printf("[%s] Received from %s: %s\n", msg.Type, conn.RemoteAddr(), msg.Payload)
	}
}
