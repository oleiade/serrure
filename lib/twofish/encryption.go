package twofish

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	"golang.org/x/crypto/twofish"
)

// TwofishEncrypter implements the Encrypter interface.
// Provided a Key object it exposes a Encrypt method to
// encrypt provided plain bytes using Twofish algorithm.
type TwofishEncrypter struct {
	Key *Key
}

// Encrypt reads up plain data bytes contained in pd, encrypts
// them using AES256 encryption algorithm, and returns the
// resulting bytes as well as any potential errors.
func (a *TwofishEncrypter) Encrypt(pd []byte) ([]byte, error) {
	var ciphertext []byte
	block, err := twofish.NewCipher(a.Key.key)
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

	ciphertext = ad.Seal(nil, nonce, pd, nil)
	ciphertext = PrependSalt(a.Key.salt, PrependSalt(nonce, ciphertext))
	return ciphertext, nil
}

// NewTwofishEncrypter builds a new TwofishEncrypter object
// from provided passphrase and salt.
// The returned object can then be used against byte slices
// to encrypt them with the Twofish encryption algorithm using
// the Encrypt method.
//
// See Encrypter interface.
func NewTwofishEncrypter(Passphrase string, salt []byte) (*TwofishEncrypter, error) {
	var k *Key
	var ae *TwofishEncrypter
	var err error

	k, err = MakeKey(Passphrase, salt)
	if err != nil {
		return nil, err
	}

	ae = &TwofishEncrypter{
		Key: k,
	}
	return ae, err
}
