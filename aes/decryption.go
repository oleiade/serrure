package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type AES256Decrypter struct {
	passphrase string
}

func (a *AES256Decrypter) Decrypt(ed []byte) ([]byte, error) {
	var aesKey *AES256Key
	var ciphertext []byte
	var err error

	ciphertext, aesKey, err = parseMsg(a.passphrase, ed)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(aesKey.key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("Ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// get ciphertext from message
func extractMsg(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < saltSize+aes.BlockSize {
		return nil, errors.New("Ciphertext too short")
	}

	return ciphertext[saltSize:], nil
}

func parseMsg(passphrase string, msg []byte) ([]byte, *AES256Key, error) {
	salt, err := ExtractSalt(msg)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err := extractMsg(msg)
	if err != nil {
		return nil, nil, err
	}

	aeskey, err := MakeAES256Key(passphrase, salt)
	if err != nil {
		return nil, nil, err
	}

	return ciphertext, aeskey, nil
}

func NewAES256Decrypter(p string) *AES256Decrypter {
	return &AES256Decrypter{
		passphrase: p,
	}
}
