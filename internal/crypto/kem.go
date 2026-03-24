package crypto

import (
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
)

// GenerateKeyPair creates a public/private key pair for the Server
func GenerateKeyPair() ([]byte, []byte, error) {
	scheme := kyber1024.Scheme()

	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate kyber keypair: %w", err)
	}

	packedPubKey, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to pack public key: %w", err)
	}

	packedPrivKey, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to pack private key: %w", err)
	}

	return packedPubKey, packedPrivKey, nil
}

// Encapsulate is used by the Client
func Encapsulate(packedPubKey []byte) (ciphertext []byte, sharedSecret []byte, err error) {
	scheme := kyber1024.Scheme()

	pk, err := scheme.UnmarshalBinaryPublicKey(packedPubKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public key format: %w", err)
	}

	ciphertext, sharedSecret, err = scheme.Encapsulate(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("encapsulation failed: %w", err)
	}

	return ciphertext, sharedSecret, nil
}

// Decapsulate is used by the Server
func Decapsulate(packedPrivKey []byte, ciphertext []byte) (sharedSecret []byte, err error) {
	scheme := kyber1024.Scheme()

	sk, err := scheme.UnmarshalBinaryPrivateKey(packedPrivKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key format: %w", err)
	}

	sharedSecret, err = scheme.Decapsulate(sk, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decapsulation failed: %w", err)
	}

	return sharedSecret, nil
}
