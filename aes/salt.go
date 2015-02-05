package aes

import (
	"crypto/aes"
	"crypto/rand"
	"errors"
	"io"
)

const saltSize = 16

// Securely generate a 8 byte salt
func GenerateSalt() ([]byte, error) {
	var salt []byte = make([]byte, saltSize)

	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	return salt, nil
}

// helper functions to separate salt and message
func ExtractSalt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < saltSize+aes.BlockSize { //replace these with actual values
		return nil, errors.New("Ciphertext too short")
	}

	return ciphertext[:saltSize], nil
}

// Prepend salt to the message
func PrependSalt(salt, ciphertext []byte) []byte {
	var msg []byte = make([]byte, len(salt)+len(ciphertext))

	for i := 0; i < len(salt)+len(ciphertext); i++ {
		if i >= len(salt) {
			msg[i] = ciphertext[i-len(salt)]
		} else {
			msg[i] = salt[i]
		}
	}

	return msg
}
