package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"log"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/twofish"
)

// General Purpose Key
type SymmetricEncrypter struct {
	Key  *Key
	algo cryptoAlgo
}

// This chooses the algo given a SymmetricDecrypter and
// returns a cipher.Block object given key (passphrase)
// TODO:This can be changed to drop the key argument
// but i will leave it for now to remain consistent with the
// SymmetricDecrypter version of this same function
func (a *SymmetricEncrypter) ChooseAlgo(key *Key) (cipher.Block, error) {
	switch a.algo {
	case AESNOMAC:
		return aes.NewCipher(key.key)
	case AESGCM:
		return aes.NewCipher(key.key)
	case BLOWFISHGCM:
		return blowfish.NewCipher(key.key)
	case TWOFISHGCM:
		return twofish.NewCipher(key.key)
	default:
		return nil, errors.New("Did not understand the algo you chose")
	}
}

// General Purpose Symmetric Encryption
// Uses GCM mode of operation with message authentication
// Will provide fallback support for AESNOMAC (AES256 in CFB mode
// without message authentication)
func (a *SymmetricEncrypter) Encrypt(pd []byte) ([]byte, error) {
	// Support for AESNOMAC
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

	block, err := a.ChooseAlgo(a.Key) //aes.NewCipher(a.Key.key)
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
