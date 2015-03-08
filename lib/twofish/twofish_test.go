package twofish

import (
	"bytes"
	"testing"
)

var secret = []byte("This is a secret message")
var testKey = "My passphrase 1234"

func TestGCM(t *testing.T) {
	en, err := NewTwofishEncrypter(testKey, nil)
	if err != nil {
		t.Errorf("Error:", err)
	}
	ct, err := en.Encrypt(secret)
	if err != nil {
		t.Errorf("Error:", err)
	}
	dc := NewTwofishDecrypter(testKey)
	if err != nil {
		t.Errorf("Error:", err)
	}
	pt, err := dc.Decrypt(ct)
	if err != nil {
		t.Errorf("Error:", err)
	}
	if bytes.Compare(pt, secret) != 0 {
		t.Errorf("Encryption/Decryption did not work properly")
	}
	ct[len(ct)-1]++
	pt, err = dc.Decrypt(ct)
	if err == nil {
		t.Errorf("Message should not authenticate, it did")
	}
}
