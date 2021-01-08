package ecc

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	inter "github.com/meshplus/crypto-standard"
)

// MakeRandom is a helper that makes a new buffer full of random data.
func makeRandom(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	return bytes, err
}

// Encrypt secures and authenticates its input using the public key
func Encrypt(pub *ecdsa.PublicKey, in []byte) (out []byte, err error) {
	ephemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	x, _ := pub.Curve.ScalarMult(pub.X, pub.Y, ephemeral.D.Bytes())
	if x == nil {
		return nil, errors.New("failed to generate encryption key")
	}
	shared := sha256.Sum256(x.Bytes())
	iv, err := makeRandom(16)
	if err != nil {
		return
	}
	//paddedIn := inter.PKCS5Padding(in, 16)
	//ct, err := encryptCBC(paddedIn, iv, shared[:16])
	aesKey := inter.AESKey(shared[0:])
	interAes := new(inter.AES)
	ct, err := interAes.Encrypt(aesKey, in, rand.Reader)

	if err != nil {
		return
	}

	ephPub := elliptic.Marshal(pub.Curve, ephemeral.PublicKey.X, ephemeral.PublicKey.Y)
	out = make([]byte, 1+len(ephPub)+16)
	out[0] = byte(len(ephPub))
	copy(out[1:], ephPub)
	copy(out[1+len(ephPub):], iv)
	out = append(out, ct...)

	h := hmac.New(sha1.New, shared[16:])
	_, err = h.Write(iv)
	if err != nil {
		return nil, err
	}
	_, err = h.Write(ct)
	if err != nil {
		return nil, err
	}
	out = h.Sum(out)
	return
}

// Decrypt authenticates and recovers the original message from
// its input using the private key and the ephemeral key included in
// the message.
func Decrypt(priv *ecdsa.PrivateKey, in []byte) (out []byte, err error) {
	ephLen := int(in[0])
	ephPub := in[1 : 1+ephLen]
	ct := in[1+ephLen:]
	if len(ct) < (sha1.Size + aes.BlockSize) {
		return nil, errors.New("invalid cipher text")
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), ephPub)

	// CHANGE from redoctober
	// panic: runtime error: invalid memory address or nil pointer dereference
	if x == nil || y == nil {
		return nil, errors.New("ecc: failed to unmarshal ephemeral key")
	}
	// END CHANGE

	ok := elliptic.P256().IsOnCurve(x, y) // Rejects the identity point too.
	if !ok {
		return nil, errors.New("invalid public key")
	}

	x, _ = priv.Curve.ScalarMult(x, y, priv.D.Bytes())
	if x == nil {
		return nil, errors.New("failed to generate encryption key")
	}
	shared := sha256.Sum256(x.Bytes())

	tagStart := len(ct) - sha1.Size
	h := hmac.New(sha1.New, shared[16:])
	_, err = h.Write(ct[:tagStart])
	if err != nil {
		return nil, err
	}
	mac := h.Sum(nil)
	if !hmac.Equal(mac, ct[tagStart:]) {
		return nil, errors.New("invalid MAC")
	}

	//paddedOut, err := decryptCBC(ct[aes.BlockSize:tagStart], ct[:aes.BlockSize], shared[:16])

	aesKey := inter.AESKey(shared[0:])
	interAes := new(inter.AES)
	out, err = interAes.Decrypt(aesKey, ct[aes.BlockSize:tagStart])

	if err != nil {
		return
	}

	//out, err = inter.PKCS5UnPadding(paddedOut)
	return
}
