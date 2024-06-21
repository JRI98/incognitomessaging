package cryptorandom

import "crypto/rand"

func RandomBytes(n int) ([]byte, error) {
	data := make([]byte, n)
	_, err := rand.Read(data)
	if err != nil {
		return nil, err
	}

	return data, nil
}
