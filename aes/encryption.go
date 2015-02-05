package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
)

type AES256Encrypter struct {
	Key        *AES256Key
	passphrase string
}

func (a *AES256Encrypter) Encrypt(pd []byte) ([]byte, error) {
	var ciphertext []byte

	block, err := aes.NewCipher(a.Key.key)
	if err != nil {
		return nil, err
	}

	ciphertext = make([]byte, aes.BlockSize+len(pd))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], pd)
	ciphertext = PrependSalt(a.Key.salt, ciphertext)

	return ciphertext, nil
}

func NewAES256Encrypter(passphrase string, salt string) (*AES256Encrypter, error) {
	var k *AES256Key
	var ae *AES256Encrypter
	var err error

	k, err = MakeAES256Key(passphrase, salt)
	if err != nil {
		return nil, err
	}

	ae = &AES256Encrypter{
		Key:        k,
		passphrase: passphrase,
	}

	return ae, err
}
