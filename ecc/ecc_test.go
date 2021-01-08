package ecc

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func TestCrypt(t *testing.T) {
	var err error
	testKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("%v", err)
	}
	message := []byte("One ping only, please.")
	out, err := Encrypt(&testKey.PublicKey, message)

	if err != nil {
		t.Fatalf("%v", err)
	}

	out, err = Decrypt(testKey, out)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if !bytes.Equal(out, message) {
		t.Fatal("Decryption return different plaintext than original message.")
	}
}
