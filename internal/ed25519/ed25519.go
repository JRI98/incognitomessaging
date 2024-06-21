package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	PrivateKeySize = ed25519.PrivateKeySize
	PublicKeySize  = ed25519.PublicKeySize
	SignatureSize  = ed25519.SignatureSize
)

type (
	PublicKey  = ed25519.PublicKey
	PrivateKey = ed25519.PrivateKey
)

func Generate() (PublicKey, PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ed25519 key pair: %w", err)
	}

	return publicKey, privateKey, nil
}

func Sign(privateKey PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

func Verify(publicKey PublicKey, message []byte, signature []byte) bool {
	return ed25519.Verify(publicKey, message, signature)
}

func PublicKeyFromBytes(bytes []byte) (PublicKey, error) {
	if len(bytes) != PublicKeySize {
		return nil, errors.New("invalid public key size")
	}
	return PublicKey(bytes), nil
}

func PrivateKeyFromBytes(bytes []byte) (PrivateKey, error) {
	if len(bytes) != PrivateKeySize {
		return nil, errors.New("invalid private key size")
	}
	return PrivateKey(bytes), nil
}
