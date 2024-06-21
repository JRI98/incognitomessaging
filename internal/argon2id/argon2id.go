package argon2id

import (
	"crypto/subtle"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	SaltLen = 16
	time    = 1
	memory  = 64 * 1024
	threads = 1
	keyLen  = 32
)

func HashKDF32(password []byte, salt []byte) ([]byte, error) {
	if len(salt) != SaltLen {
		return nil, fmt.Errorf("invalid salt length: %d", len(salt))
	}

	hash := argon2.IDKey(password, salt, time, memory, threads, keyLen)

	return hash, nil
}

func VerifyKDF32(password []byte, hash []byte, salt []byte) (bool, error) {
	if len(salt) != SaltLen {
		return false, fmt.Errorf("invalid salt length: %d", len(salt))
	}

	passwordHash := argon2.IDKey(password, salt, time, memory, threads, keyLen)

	return subtle.ConstantTimeCompare(passwordHash, hash) == 1, nil
}
