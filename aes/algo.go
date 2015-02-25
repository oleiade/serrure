package aes

// Constants for choosing the encryption algoritm
// All of these algorithms in serrure use 256-bit keys,
// despite algorithm support for different key sizes

type cryptoAlgo int

const (
	AESNOMAC    cryptoAlgo = iota // AES256 in CFB mode, no authentication
	AESGCM                        // AES256 in GCM mode
	TWOFISHGCM                    // Twofish 256-bit in GCM mode
	BLOWFISHGCM                   // Blowfish 256-bit in GCM mode
)
