package openpgp

import (
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"fmt"
	"io"
)

type OpenPGPEncrypter struct {
	Keys *openpgp.EntityList
}

func (oe *OpenPGPEncrypter) Encrypt(pd []byte) ([]byte, error) {
	var buffer *bytes.Buffer = &bytes.Buffer{}
	var armoredWriter io.WriteCloser
	var cipheredWriter io.WriteCloser
	var err error

	// Create an openpgp armored cipher writer pointing on our
	// buffer
	armoredWriter, err = armor.Encode(buffer, "PGP MESSAGE", nil)
	if err != nil {
		return nil, NewOpenPGPError(
			ERR_ENCRYPTION_ENCODING,
			fmt.Sprintf("Can't make armor: %v", err),
		)
	}

	// Create an encrypted writer using the provided encryption keys
	cipheredWriter, err = openpgp.Encrypt(armoredWriter, *oe.Keys, nil, nil, nil)
	if err != nil {
		return nil, NewOpenPGPError(
			ERR_ENCRYPTION_ENCRYPT,
			fmt.Sprintf("Error encrypting: %v", err),
		)
	}

	// Write (encrypts on the fly) the provided bytes to
	// cipheredWriter
	_, err = cipheredWriter.Write(pd)
	if err != nil {
		return nil, NewOpenPGPError(
			ERR_ENCRYPTION_ENCRYPT,
			fmt.Sprintf("Error copying encrypted content: %v", err),
		)
	}

	cipheredWriter.Close()
	armoredWriter.Close()

	return buffer.Bytes(), nil
}

func NewOpenPGPEncrypter(pubRingPath string, recipients []string) (*OpenPGPEncrypter, error) {
	var ek *openpgp.EntityList
	var oe *OpenPGPEncrypter
	var err error

	ek, err = ReadPubRing(pubRingPath, recipients)
	if err != nil {
		return nil, err
	}

	oe = &OpenPGPEncrypter{
		Keys: ek,
	}

	return oe, err
}
