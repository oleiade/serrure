package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/twofish"
)

// Constants for choosing the encryption algoritm
// All of these algorithms in serrure use 256-bit keys,
// despite algorithm support for different key sizes

const (
	NONEALGO    int = iota //BASE Algo - nothing to maintain consistency with trousseau
	AESNOMAC               // AES256 in CFB mode, no authentication
	AESGCM                 // AES256 in GCM mode
	TWOFISHGCM             // Twofish 256-bit in GCM mode
	BLOWFISHGCM            // Blowfish 256-bit in GCM mode will not work - needs 128-bit block size, BLOWFISH is 64 bit
)

// Thinking the choose algo function should be here, so I'll write it
func ChooseAlgo(key *Key, algo int) (cipher.Block, error) {
	switch algo {
	case AESNOMAC: //fallback should never run
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
