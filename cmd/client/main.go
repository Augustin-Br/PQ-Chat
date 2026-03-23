package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"pq-chat/internal/network"
)

func main() {
	// 1. Connect to the server
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println("Error connecting to server:", err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Println("Connected to PQ-Server")

	reader := bufio.NewReader(os.Stdin)

	// 2. Create a JSON encoder that writes directly to the network connection
	encoder := json.NewEncoder(conn)

	for {
		fmt.Print("Message > ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		// 3. Create the structured message
		msg := network.Message{
			Type:    "chat",
			Payload: input,
		}

		// 4. Encode and send the message in one step
		if err := encoder.Encode(msg); err != nil {
			fmt.Printf("Failed to send message: %v\n", err)
			return
		}
	}
}
