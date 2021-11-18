package asym

import (
	std "crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"github.com/meshplus/crypto-standard/asym/secp256k1"
	"io"
	"math/big"
	"strconv"
)

//ECDSASignature ECDSASignature struct
type ECDSASignature struct {
	R, S *big.Int
}

//ECDSAPrivateKey ECDSA private key.
// never new(ECDSAPrivateKey), use NewECDSAPrivateKey()
type ECDSAPrivateKey struct {
	ECDSAPublicKey
	D *big.Int
}

func generateKeyParam(c elliptic.Curve) (X, Y, D *big.Int) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, _ = io.ReadFull(rand.Reader, b)
	D = GetBig().SetBytes(b)
	n := GetBig().Sub(params.N, one)
	D.Mod(D, n)
	D.Add(D, one)
	X, Y = c.ScalarBaseMult(D.Bytes())
	PutBig(n)
	return
}

//GenerateKey generate a pair of key,input is algorithm type
func GenerateKey(opt int) (*ECDSAPrivateKey, error) {
	var curve elliptic.Curve
	switch opt {
	case AlgoP256K1, AlgoP256K1Recover:
		curve = secp256k1.S256()
	case AlgoP256R1:
		curve = elliptic.P256()
	case AlgoP384R1:
		curve = elliptic.P384()
	case AlgoP521R1:
		curve = elliptic.P521()
	default:
		return nil, errors.New(errIllegalInputParameter + strconv.Itoa(opt))
	}
	X, Y, D := generateKeyParam(curve)
	return &ECDSAPrivateKey{
		ECDSAPublicKey: ECDSAPublicKey{
			Curve:   curve,
			X:       X,
			Y:       Y,
			recover: opt == AlgoP256K1Recover,
		},
		D: D,
	}, nil
}

//Bytes return key bytes. Inverse method of FromBytes(k []byte, opt AlgorithmOption)
func (key *ECDSAPrivateKey) Bytes() ([]byte, error) {
	if key.D == nil || key.Curve == nil {
		return nil, errors.New("ECDSAPrivateKey.k is nil, please invoke FromBytes()")
	}
	ret := make([]byte, (key.Params().BitSize+7)>>3)
	d := key.D.Bytes()
	copy(ret[len(ret)-len(d):], d)
	return ret, nil
}

//FromBytes parse a private Key from bytes, Inverse method of Bytes()
func (key *ECDSAPrivateKey) FromBytes(k []byte, opt int) error {
	if key.D == nil {
		key.D = GetBig()
	}
	key.D.SetBytes(k)
	switch opt {
	case AlgoP256K1Recover:
		key.recover = true
		fallthrough
	case AlgoP256K1:
		key.Curve = secp256k1.S256()
	case AlgoP256R1:
		key.Curve = elliptic.P256()
	case AlgoP384R1:
		key.Curve = elliptic.P384()
	case AlgoP521R1:
		key.Curve = elliptic.P521()
	}
	key.CalculatePublicKey()
	return nil
}

//SetPublicKey Set the public key contained in the private key
// when get a ECDSAPrivateKey by FromBytes(...), the public key contained is empty,
// you should invoke SetPublicKey(...) or CalculatePublicKey().
// If you have the Public Key,SetPublicKey(...) is better and faster, since CalculatePublicKey() while calculate public key once again.
func (key *ECDSAPrivateKey) SetPublicKey(k *ECDSAPublicKey) *ECDSAPrivateKey {
	if k.recover {
		//public key that should in recovery mode
		return nil
	}
	key.ECDSAPublicKey.Curve = k.Curve
	key.ECDSAPublicKey.X = k.X
	key.ECDSAPublicKey.X = k.Y
	key.recover = k.recover
	key.address = make([]byte, len(k.address))
	copy(key.address, k.address)
	return key
}

//CalculatePublicKey Calculate the public key contained in the private key
// when get a ECDSAPrivateKey by FromBytes(...), the public key contained is empty,
// you should invoke SetPublicKey(...) or CalculatePublicKey().
// If you have the Public Key,SetPublicKey(...) is better and faster, since CalculatePublicKey() while calculate public key once again.
func (key *ECDSAPrivateKey) CalculatePublicKey() *ECDSAPrivateKey {
	key.X, key.Y = key.Curve.ScalarBaseMult(key.D.Bytes())
	if key.recover && len(key.address) == 0 {
		_, _ = key.ECDSAPublicKey.Bytes()
	}
	return key
}

//Public GetBig ECDSAPublicKey from a ECDSAPrivateKey, if ECDSAPublicKey is empty, this method will invoke CalculatePublicKey().
func (key *ECDSAPrivateKey) Public() std.PublicKey {
	return &key.ECDSAPublicKey
}

//Sign get signature of specific digest by ECDSAPrivateKey self,so the first parameter will be ignored
// signature is 65 bytes: r + s + v
// if s is odd, v == 01
// if s is even, v == 00
// look Ethereum yellow paper
func (key *ECDSAPrivateKey) Sign(k, digest []byte, reader io.Reader) (signature []byte, err error) {
	//secp256k1使用的签名算法是C实现的
	if key.Curve == secp256k1.S256() && key.recover {
		b := key.D.Bytes()
		if len(b) != 32 {
			tmp := make([]byte, 32)
			copy(tmp[32-len(b):], b)
			b = tmp
		}
		return secp256k1.Sign(digest, b, reader)
	}

	r, s, err := ecdsa.Sign(reader, &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: key.Curve,
			X:     key.X,
			Y:     key.Y,
		},
		D: key.D,
	}, digest)
	if err != nil {
		return nil, err
	}
	signatureBytes := new(ECDSASignature)
	signatureBytes.R, signatureBytes.S = r, s
	return asn1.Marshal(*signatureBytes)
}
