package main

type Encrypter interface {
	Encrypt([]byte) ([]byte, error)
}

type Decrypter interface {
	Decrypt([]byte) ([]byte, error)
}

type SymmetricEncrypter interface {
	Encrypter
}

type SymmetricDecrypter interface {
	Decrypter
}

type AsymmetricEncrypter interface {
	Encrypter
}

type AsymmetricDecrypter interface {
	Decrypter
}
