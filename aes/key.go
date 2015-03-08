package aes

import (
	"crypto/aes"
	"errors"

	"code.google.com/p/go.crypto/scrypt"
)

type Key struct {
	key  []byte
	salt []byte
}

// make an AES key. Pass nil as salt if you want to generate a new one
// otherwise pass the salt from the message and you will get the key
// will use scrypt to make it semi secure
func MakeKey(passphrase string, salt []byte) (*Key, error) {
	var b []byte = []byte(passphrase)
	var err error

	if salt == nil {
		salt, err = GenerateSalt()
		if err != nil {
			return nil, err
		}
	} else {
		if len(salt) != SALT_SIZE {
			return nil, errors.New("Salt is not the correct size")
		}
	}

	key, err := scrypt.Key(b, salt, 65536, aes.BlockSize, 1, 32)
	if err != nil {
		return nil, err
	}

	return NewKey(key, salt), nil
}

// Generate a new AES256 key from a key and salt
func NewKey(key, salt []byte) *Key {
	return &Key{key, salt}
}
