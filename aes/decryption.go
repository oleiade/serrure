package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"log"
)

// AES256Decrypter implements the Decrypter interface.
// Provided a Passphrase it exposes a Decrypt method to
// read the content of AES256 encrypted bytes.
type AES256Decrypter struct {
	// Passphrase to be used to decrypt the AES256 ciphered blocks
	Passphrase string
	Mode       int
}

// This method sets the mode of operation of the
// AES256 Decrypter.
func (a *AES256Decrypter) SetMode(mode int) {
	a.Mode = mode
}

// Decrypt reads up the AES256 encrypted data bytes from ed,
// decrypts them and returns the resulting plain data bytes as well
// as any potential errors.
func (a *AES256Decrypter) Decrypt(ed []byte) ([]byte, error) {
	var aesKey *Key
	var ciphertext []byte
	var err error

	ciphertext, aesKey, err = parseMsg(a.Passphrase, ed)
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
	switch a.Mode {
	case CFB_MODE:
		{
			log.Println("You are using non-authenticated encryption. This is insecure, and you should consider switching to a mode with message authentication, such as GCM.")
			iv := ciphertext[:aes.BlockSize]
			ciphertext = ciphertext[aes.BlockSize:]
			stream := cipher.NewCFBDecrypter(block, iv)
			stream.XORKeyStream(ciphertext, ciphertext)

			return ciphertext, nil
		}
	case GCM_MODE:
		{
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
	default:
		{
			return nil, errors.New("No known mode of operation defined")
		}
	}
	return nil, errors.New("No known mode of operation defined")
}

// extractMsg extracts ciphertext from message
func extractMsg(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < SALT_SIZE+aes.BlockSize {
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
func NewAES256Decrypter(p string) *AES256Decrypter {
	return &AES256Decrypter{
		Passphrase: p,
		Mode:       GCM_MODE,
	}
}
