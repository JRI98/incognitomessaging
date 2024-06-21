package x25519

import (
	"crypto/ecdh"
	"crypto/rand"
)

const (
	PublicKeySize  = 32
	PrivateKeySize = 32
)

type (
	PublicKey  = ecdh.PublicKey
	PrivateKey = ecdh.PrivateKey
)

func Generate() (*PublicKey, *PrivateKey) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil
	}

	return privateKey.PublicKey(), privateKey
}

func ECDH(privateKey *PrivateKey, publicKey *PublicKey) ([]byte, error) {
	return privateKey.ECDH(publicKey)
}

func PublicKeyFromBytes(bytes []byte) (*PublicKey, error) {
	return ecdh.X25519().NewPublicKey(bytes)
}

func PrivateKeyFromBytes(bytes []byte) (*PrivateKey, error) {
	return ecdh.X25519().NewPrivateKey(bytes)
}
