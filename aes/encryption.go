package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"log"
)

const (
	GCM_MODE int = iota // GCM Mode of operation with message authentication
	CFB_MODE            // CFB Mode of operation with *** NO MESSAGE AUTHENTICATIO ***
)

// AES256Encrypter implements the Encrypter interface.
// Provided a AES256Key object it exposes a Encrypt method to
// encrypt provided plain bytes using AES256 algorithm.
type AES256Encrypter struct {
	Key  *Key
	Mode int
}

// This method sets the mode of operation of the
// AES256 Encrypter.
func (a *AES256Encrypter) SetMode(mode int) {
	a.Mode = mode
}

// Encrypt reads up plain data bytes contained in pd, encrypts
// them using AES256 encryption algorithm, and returns the
// resulting bytes as well as any potential errors.
func (a *AES256Encrypter) Encrypt(pd []byte) ([]byte, error) {
	var ciphertext []byte
	block, err := aes.NewCipher(a.Key.key)
	if err != nil {
		return nil, err
	}

	switch a.Mode {
	case CFB_MODE:
		{
			log.Println("You are using non-authenticated encryption. This is insecure, and you should consider switching to a mode with message authentication, such as GCM.")
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
	case GCM_MODE:
		{
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
	default:
		{
			return nil, errors.New("No known mode of operation defined")
		}
	}
	return nil, errors.New("No known mode of operation defined")
}

// NewAES256Encrypter builds a new AES256Encrypter object
// from provided passphrase and salt.
// The returned object can then be used against byte slices
// to encrypt them with the AES256 encryption algorithm using
// the Encrypt method.
//
// See Encrypter interface.
func NewAES256Encrypter(Passphrase string, salt []byte) (*AES256Encrypter, error) {
	var k *Key
	var ae *AES256Encrypter
	var err error

	k, err = MakeKey(Passphrase, salt)
	if err != nil {
		return nil, err
	}

	ae = &AES256Encrypter{
		Key:  k,
		Mode: GCM_MODE,
	}
	return ae, err
}
