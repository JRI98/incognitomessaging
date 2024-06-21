package xchacha20poly1305

import (
	"github.com/JRI98/yeomessaging/internal/cryptorandom"
	"golang.org/x/crypto/chacha20poly1305"
)

func Encrypt(data []byte, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	nonce, err := cryptorandom.RandomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}

	encrypted := aead.Seal(nil, nonce, data, nil)
	encryptedWithNonce := append(nonce, encrypted...)

	return encryptedWithNonce, nil
}

func Decrypt(data []byte, key []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	decrypted, err := aead.Open(nil, data[:aead.NonceSize()], data[aead.NonceSize():], nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}
