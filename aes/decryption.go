package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/twofish"
)

// More generalized form of AES below, with GCM as the default
// mode of operation. Only has AESNOMAC support for legacy
// You should NOT use AESNOMAC as messages are not authenticated
// and therefore are insecure

type SymmetricDecrypter struct {
	// Passphrase to be used to decrypt the AES256 ciphered blocks
	Passphrase string
	algo       cryptoAlgo
}

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

// AES256Decrypter implements the Decrypter interface.
// Provided a Passphrase it exposes a Decrypt method to
// read the content of AES256 encrypted bytes.
type AES256Decrypter struct {
	// Passphrase to be used to decrypt the AES256 ciphered blocks
	Passphrase string
}

// Decrypt reads up the AES256 encrypted data bytes from ed,
// decrypts them and returns the resulting plain data bytes as well
// as any potential errors.
func (a *AES256Decrypter) Decrypt(ed []byte) ([]byte, error) {
	var aesKey *AES256Key
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

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// extractMsg extracts ciphertext from message
func extractMsg(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < SALT_SIZE+aes.BlockSize {
		return nil, errors.New("Ciphertext too short")
	}

	return ciphertext[SALT_SIZE:], nil
}

func parseMsg(Passphrase string, msg []byte) ([]byte, *AES256Key, error) {
	salt, err := ExtractSalt(msg)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, err := extractMsg(msg)
	if err != nil {
		return nil, nil, err
	}

	aeskey, err := MakeAES256Key(Passphrase, salt)
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
	}
}
