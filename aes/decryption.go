package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"log"
)

// More generalized form of AES below, with GCM as the default
// mode of operation. Only has AESNOMAC support for legacy
// You should NOT use AESNOMAC as messages are not authenticated
// and therefore are insecure

// Added an algo variable to support different algos
// and perhaps differnt modes of operation
type SymmetricDecrypter struct {
	// Passphrase to be used to decrypt the AES256 ciphered blocks
	Passphrase string
	algo       cryptoAlgo
}

func (sd *SymmetricDecrypter) SetAlgo(algo cryptoAlgo) {
	sd.algo = algo
}

func NewSymmetricDecrypter(p string) *SymmetricDecrypter {
	return &SymmetricDecrypter{
		Passphrase: p,
		algo:       AESGCM,
	}
}

func (a *SymmetricDecrypter) Decrypt(ed []byte) ([]byte, error) {
	var key *Key
	var ciphertext []byte
	var err error
	ciphertext, key, err = parseMsgGeneric(a.Passphrase, ed)

	// This is a special case for legacy support
	// IT SHOULD NOT BE USED AT ALL. PLEASE DO NOT CONSIDER THIS SECURE
	// Switch to GCM mode of operation, so messages can be authenticated
	if a.algo == AESNOMAC {
		log.Println("You are using non-authenticated encryption. This is insecure, and you should not be doing this. Please use an algo in GCM mode")
		var key *Key
		var ciphertext []byte
		var err error

		ciphertext, key, err = parseMsgGeneric(a.Passphrase, ed)
		if err != nil {
			return nil, err
		}

		block, err := aes.NewCipher(key.key)
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

	if err != nil {
		return nil, err
	}

	block, err := ChooseAlgo(key, a.algo)
	if err != nil {
		return nil, err
	}
	ad, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := ciphertext[:ad.NonceSize()]
	ct := ciphertext[ad.NonceSize():]
	pt, err := ad.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// extractMsg extracts ciphertext from message
func extractMsg(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < SALT_SIZE+aes.BlockSize {
		return nil, errors.New("Ciphertext too short")
	}

	return ciphertext[SALT_SIZE:], nil
}

func parseMsgGeneric(Passphrase string, msg []byte) ([]byte, *Key, error) {
	salt, err := ExtractSalt(msg)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err := extractMsg(msg)
	if err != nil {
		return nil, nil, err
	}

	key, err := MakeKey(Passphrase, salt)
	if err != nil {
		return nil, nil, err
	}

	return ciphertext, key, nil
}
