package main

// Encrypter is the interface that wraps the basic Encrypt method
//
// Encrypt reads up plain data bytes contained in pd, encrypts
// them and returns the resulting bytes as well as any potential errors.
//
// Implementations of Encrypter are let free to implement their own
// Symmetric/Asymmetric algorithm needs management (public/private keys,
// passphrase, etc...).
// For a real-world implementation example, please refer to
// serrure.openpgp.OpenPGPEncrypter or serrure.aes.AES256Encrypter.
type Encrypter interface {
	Encrypt(pd []byte) (ed []byte, err error)
}

// Decrypter is the interface that wraps the basice Decrypt method
//
// Decrypts reads up the encrypted data bytes from ed,
// decrypts them and returns the resulting plain data bytes as well
// as any potential errors.
//
// Implementations of Decrypter are let free to implement their own
// Symmetric/Asymmetric algorithm needs management (public/private keys,
// passphrase, etc...)
// For a real-world implementation example, please refer to
// serrure.openpgp OpenPGPDecrypter or serrure.aes.AES256Decrypter.
type Decrypter interface {
	Decrypt(ed []byte) (pd []byte, err error)
}
