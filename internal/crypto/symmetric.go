package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"sync"
)

// SecureSession maintains the cryptographic state of a connection after the Handshake
type SecureSession struct {
	aead        cipher.AEAD
	sendCounter uint64
	recvCounter uint64
	mu          sync.Mutex
}

func NewSecureSession(sharedSecret []byte) (*SecureSession, error) {
	if len(sharedSecret) != 32 {
		return nil, fmt.Errorf("key must be exactly 32 bytes, got: %d", len(sharedSecret))
	}

	// 1. Create the AES block cipher
	block, err := aes.NewCipher(sharedSecret)
	if err != nil {
		return nil, err
	}

	// 2. Wrap the block in GCM mode (handles authentication and nonces)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &SecureSession{
		aead:        aesgcm,
		sendCounter: 0,
		recvCounter: 0,
	}, nil
}

// Encrypt secures the plaintext using AES-GCM and an incrementing nonce.
func (s *SecureSession) Encrypt(plaintext []byte) []byte {
	s.mu.Lock()
	currentCounter := s.sendCounter
	s.sendCounter++
	s.mu.Unlock()

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], currentCounter)

	return s.aead.Seal(nil, nonce, plaintext, nil)
}

// Decrypt authenticates and decrypts the ciphertext
// It only increments the receive counter if the decryption is successful
func (s *SecureSession) Decrypt(ciphertext []byte) ([]byte, error) {
	s.mu.Lock()
	currentCounter := s.recvCounter
	s.mu.Unlock()

	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], currentCounter)

	plaintext, err := s.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption/authentication failed: %w", err)
	}

	s.mu.Lock()
	s.recvCounter++
	s.mu.Unlock()

	return plaintext, nil
}
