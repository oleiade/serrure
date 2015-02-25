package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
)

// General Purpose Key
type SymmetricEncrypter struct {
	Key  *Key
	algo cryptoAlgo
}

// General Purpose Symmetric Encryption
// Uses GCM mode of operation with message authentication
// Will provide fallback support for AESNOMAC (AES256 in CFB mode
// without message authentication)
func (a *SymmetricEncrypter) Encrypt(pd []byte) ([]byte, error) {
	// This is a special case for legacy support
	// IT SHOULD NOT BE USED AT ALL. PLEASE DO NOT CONSIDER THIS SECURE
	// Switch to GCM mode of operation, so messages can be authenticated
	if a.algo == AESNOMAC {
		log.Println("You are using non-authenticated encryption. This is insecure, and you should not be doing this. Please use an algo in GCM mode")
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

	block, err := ChooseAlgo(a.Key, a.algo)
	if err != nil {
		return nil, err
	}
	ad, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, ad.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := ad.Seal(nil, nonce, pd, nil)
	ciphertext = PrependSalt(a.Key.salt, PrependSalt(nonce, ciphertext))
	return ciphertext, nil
}

func NewSymmetricEncrypter(Passphrase string, salt []byte) (*SymmetricEncrypter, error) {
	var k *Key
	var ae *SymmetricEncrypter
	var err error

	k, err = MakeKey(Passphrase, salt)
	if err != nil {
		return nil, err
	}

	ae = &SymmetricEncrypter{
		Key:  k,
		algo: AESGCM,
	}

	return ae, err
}
