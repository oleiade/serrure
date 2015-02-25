package aes

type cryptoAlgo int

const (
	AESNOMAC cryptoAlgo = iota
	AESGCM
	TWOFISHGCM
	BLOWFISHGCM
)
