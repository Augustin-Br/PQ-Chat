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
	// 3. START CHAT & E2E REGISTRATION
	// ================

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter your username: ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Println("Generating your Post-Quantum E2EE Keys...")

	e2ePubKey, e2ePrivKey, err := crypto.GenerateKeyPair()
	if err != nil {
		fmt.Println("Failed to generate E2E keys:", err)
		return
	}

	regMsg := network.Message{
		Type:    network.TypeE2ERegister,
		Sender:  username,
		Payload: base64.StdEncoding.EncodeToString(e2ePubKey),
	}

	encryptedRegPayload := session.Encrypt([]byte(regMsg.Payload))

	regMsg.Payload = base64.StdEncoding.EncodeToString(encryptedRegPayload)

	if err := encoder.Encode(regMsg); err != nil {
		fmt.Printf("Failed to register E2E keys: %v\n", err)
		return
	}

	fmt.Println("✅ E2EE Keys registered with the Server!")

	fmt.Print("> ")

	e2eSessions := make(map[string]*crypto.SecureSession)
	keyRespChan := make(chan []byte)

	go receiveMessages(decoder, session, e2ePrivKey, e2eSessions, keyRespChan)

	for {
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		if input == "" {
			fmt.Print("> ")
			continue
		}

		if strings.HasPrefix(input, "/msg ") {
			// ============================
			// PRIVATE CHAT FLOW (E2EE)
			// ============================
			parts := strings.SplitN(input[5:], " ", 2)
			if len(parts) < 2 {
				fmt.Println("Usage: /msg <username> <message>")
				fmt.Print("> ")
				continue
			}
			targetUser := parts[0]
			privateText := parts[1]

			targetSession, exists := e2eSessions[targetUser]
			if !exists {
				fmt.Printf("Requesting %s's Public Key from Server...\n", targetUser)

				req := network.Message{
					Type:   network.TypeE2EKeyReq,
					Sender: username,
					Target: targetUser,
				}

				encReq := session.Encrypt([]byte("req"))
				req.Payload = base64.StdEncoding.EncodeToString(encReq)
				encoder.Encode(req)

				pubKey := <-keyRespChan
				if len(pubKey) == 0 {
					fmt.Println("Could not get key for user.")
					continue
				}

				cipherText, sharedSecret, err := crypto.Encapsulate(pubKey)
				if err != nil {
					fmt.Println("E2E Setup failed:", err)
					continue
				}
				targetSession, _ = crypto.NewSecureSession(sharedSecret)
				e2eSessions[targetUser] = targetSession

				initMsg := network.Message{
					Type:    network.TypeE2ESessionInit,
					Sender:  username,
					Target:  targetUser,
					Payload: base64.StdEncoding.EncodeToString(cipherText),
				}
				encInit := session.Encrypt([]byte(initMsg.Payload))
				initMsg.Payload = base64.StdEncoding.EncodeToString(encInit)
				encoder.Encode(initMsg)
			}

			encMsg := targetSession.Encrypt([]byte(privateText))
			chatMsg := network.Message{
				Type:    network.TypeE2EChat,
				Sender:  username,
				Target:  targetUser,
				Payload: base64.StdEncoding.EncodeToString(encMsg),
			}
			encChatMsg := session.Encrypt([]byte(chatMsg.Payload))
			chatMsg.Payload = base64.StdEncoding.EncodeToString(encChatMsg)
			encoder.Encode(chatMsg)

		} else {
			// ============================
			// GLOBAL CHAT FLOW (Standard)
			// ============================
			encryptedPayload := session.Encrypt([]byte(input))
			msg := network.Message{
				Type:    network.TypeChat,
				Sender:  username,
				Payload: base64.StdEncoding.EncodeToString(encryptedPayload),
			}
			encoder.Encode(msg)
		}
		fmt.Print("> ")
	}
}

func receiveMessages(decoder *json.Decoder, session *crypto.SecureSession, e2ePrivKey []byte, e2eSessions map[string]*crypto.SecureSession, keyRespChan chan []byte) {
	for {
		var msg network.Message
		if err := decoder.Decode(&msg); err != nil {
			fmt.Println("\nDisconnected from server")
			os.Exit(0)
		}

		ciphertext, err := base64.StdEncoding.DecodeString(msg.Payload)
		if err != nil {
			continue
		}

		plaintext, err := session.Decrypt(ciphertext)
		if err != nil {
			continue
		}

		msg.Payload = string(plaintext)

		switch msg.Type {
		case network.TypeChat:
			fmt.Printf("\r[Global] %s: %s\n> ", msg.Sender, msg.Payload)

		case network.TypeE2EKeyResp:
			pubKey, _ := base64.StdEncoding.DecodeString(msg.Payload)
			keyRespChan <- pubKey

		case network.TypeE2ESessionInit:
			kyberCiphertext, err := base64.StdEncoding.DecodeString(msg.Payload)
			if err != nil {
				continue
			}

			sharedSecret, err := crypto.Decapsulate(e2ePrivKey, kyberCiphertext)
			if err != nil {
				fmt.Printf("\r[Error] Failed to decapsulate session from %s\n> ", msg.Sender)
				continue
			}

			e2eSession, err := crypto.NewSecureSession(sharedSecret)
			if err != nil {
				continue
			}

			e2eSessions[msg.Sender] = e2eSession
			fmt.Printf("\r[System] Secure E2E session established with %s!\n> ", msg.Sender)

		case network.TypeE2EChat:
			e2eSession, exists := e2eSessions[msg.Sender]
			if !exists {
				fmt.Printf("\r[Warning] Received E2E chat from %s but no session exists!\n> ", msg.Sender)
				continue
			}

			encryptedPayload, err := base64.StdEncoding.DecodeString(msg.Payload)
			if err != nil {
				continue
			}

			decryptedText, err := e2eSession.Decrypt(encryptedPayload)
			if err != nil {
				fmt.Printf("\r[Warning] Failed to decrypt E2E message from %s\n> ", msg.Sender)
				continue
			}

			fmt.Printf("\r[Private from %s]: %s\n> ", msg.Sender, string(decryptedText))

		default:
		}
	}
}
