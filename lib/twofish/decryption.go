package twofish

import (
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/twofish"
)

// TwofishDecrypter implements the Decrypter interface.
// Provided a Passphrase it exposes a Decrypt method to
// read the content of AES256 encrypted bytes.
type TwofishDecrypter struct {
	// Passphrase to be used to decrypt the AES256 ciphered blocks
	Passphrase string
}

// Decrypt reads up the AES256 encrypted data bytes from ed,
// decrypts them and returns the resulting plain data bytes as well
// as any potential errors.
func (a *TwofishDecrypter) Decrypt(ed []byte) ([]byte, error) {
	var Key *Key
	var ciphertext []byte
	var err error

	ciphertext, Key, err = parseMsg(a.Passphrase, ed)
	if err != nil {
		return nil, err
	}

	block, err := twofish.NewCipher(Key.key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < twofish.BlockSize {
		return nil, errors.New("Ciphertext too short")
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
	if len(ciphertext) < SALT_SIZE+twofish.BlockSize {
		return nil, errors.New("Ciphertext too short")
	}

	return ciphertext[SALT_SIZE:], nil
}

func parseMsg(Passphrase string, msg []byte) ([]byte, *Key, error) {
	salt, err := ExtractSalt(msg)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err := extractMsg(msg)
	if err != nil {
		return nil, nil, err
	}

	aeskey, err := MakeKey(Passphrase, salt)
	if err != nil {
		return nil, nil, err
	}

	return ciphertext, aeskey, nil
}

// NewAES256Decrypter builds a new AES256Decrypter object
// from Passphrase. The returned object can then be used
// against AES256 encrypted bytes using this Passphrase
// using the Decrypt method.
//
// See Decrypter interface.
func NewTwofishDecrypter(p string) *TwofishDecrypter {
	return &TwofishDecrypter{
		Passphrase: p,
	}
}
