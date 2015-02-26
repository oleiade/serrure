package symmetric

import (
	"bytes"
	"testing"
)

const testPassphrase = "test passphrase"

var plainText = []byte("This is a secret message")

func TestKeys(t *testing.T) {
	k, err := MakeKey(testPassphrase, nil)
	if err != nil {
		t.Errorf("err:", err)
	}
	if len(k.key) != 32 {
		t.Errorf("Keysize is not 256 bits")
	}
}

func TestEncrypterDecrypter(t *testing.T) {
	se, err := NewSymmetricEncrypter(testPassphrase, nil)
	if err != nil {
		t.Errorf("err:", err)
	}
	ct, err := se.Encrypt(plainText)
	sd := NewSymmetricDecrypter(testPassphrase)
	pt, err := sd.Decrypt(ct)
	if err != nil {
		t.Errorf("err:", err)
	}
	if bytes.Compare(pt, plainText) != 0 {
		t.Errorf("Encryption does not decrypt to the proper message")
	}

	// Message is tampered with, it MUST not authenticate
	ct[2] = 0
	pt, err = sd.Decrypt(ct)
	if err.Error() != "cipher: message authentication failed" {
		t.Errorf("Message should not authenticate, it did")
	}

}
