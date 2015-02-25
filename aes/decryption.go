package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"log"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/twofish"
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

func NewSymmetricDecrypter(p string) *SymmetricDecrypter {
	return &SymmetricDecrypter{
		Passphrase: p,
		algo:       AESGCM,
	}
}

// This chooses the algo given a SymmetricDecrypter and
// returns a cipher.Block object given key (passphrase)
// YOU MUST PASS THE KEY INTO THIS ONE (unlike the SymmetricEncrypter
// version) as you need the nonce and salt to actually create the key
// and that is message dependent
func (a *SymmetricDecrypter) ChooseAlgo(key *Key) (cipher.Block, error) {
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

func (a *SymmetricDecrypter) Decrypt(ed []byte) ([]byte, error) {
	var key *Key
	var ciphertext []byte
	var err error
	ciphertext, key, err = parseMsgGeneric(a.Passphrase, ed)
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

	block, err := a.ChooseAlgo(key)
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
