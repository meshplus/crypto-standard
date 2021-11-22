package asym

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/meshplus/crypto"
	"github.com/meshplus/crypto-standard/asym/secp256k1"
	"github.com/meshplus/crypto-standard/hash"
	"math/big"
)

//Algorithm identity
const (
	AlgorithmNone     = 0x00
	AlgoP256K1        = 0x0200
	AlgoP256R1        = 0x0300
	AlgoP384R1        = 0x0400
	AlgoP521R1        = 0x0500
	AlgoP256K1Recover = 0x0600
	AlgoRSA2048       = 0x1000
	AlgoRSA3072       = 0x1100
	AlgoRSA4096       = 0x1200
)

//ECDSAPublicKey ECDSA public key.
// never new(ECDSAPublicKey), use NewECDSAPublicKey()
type ECDSAPublicKey struct {
	elliptic.Curve
	X, Y    *big.Int
	recover bool
	address []byte
}

//FromBytes Parse a public key from 65 bytes and specific algorithm.The reverse method of Bytes()
func (key *ECDSAPublicKey) FromBytes(k []byte, opt int) error {
	//in recover mode, the verification does not need to actually pass in a public key
	//k is a address
	if opt == AlgoP256K1Recover || opt == AlgoP256K1 {
		if len(k) == 20 {
			key.Curve = secp256k1.S256()
			key.recover = true
			key.address = k
			return nil
		} else if len(k) == 65 {
			//txgen配备k1证书时，因历史原因签署的需要为recover的签名
			opt = AlgoP256K1 //虽然指定了recover，但是传入一个20字节的address，还是看作非recover，这样兼容性较好
		}
	}

	key.recover = false
	key.address = nil

	if key.X == nil {
		key.X = GetBig()
	}
	if key.Y == nil {
		key.Y = GetBig()
	}
	switch opt {
	case AlgoP256K1:
		if len(k) != 65 {
			return fmt.Errorf("k length is %v, maybe should use AlgoP256K1Recover", len(k))
		}
		key.Curve = secp256k1.S256()
		key.X.SetBytes(k[1:33])
		key.Y.SetBytes(k[33:])
	case AlgoP256R1:
		if len(k) != 65 {
			return nil
		}
		key.Curve = elliptic.P256()
		key.X.SetBytes(k[1:33])
		key.Y.SetBytes(k[33:])
	case AlgoP384R1:
		if len(k) != 1+(elliptic.P384().Params().BitSize+7)>>2&0x7ffffffffffffffe {
			return nil
		}
		key.Curve = elliptic.P384()
		key.X.SetBytes(k[1:49])
		key.Y.SetBytes(k[49:])
	case AlgoP521R1:
		if len(k) != 1+(elliptic.P521().Params().BitSize+7)>>2&0x7ffffffffffffffe {
			return nil
		}
		key.Curve = elliptic.P521()
		key.X.SetBytes(k[1:67])
		key.Y.SetBytes(k[67:])
	}
	return nil
}

//Bytes return key bytes
func (key *ECDSAPublicKey) Bytes() ([]byte, error) {
	if key.Y == nil || key.X == nil && len(key.address) == 0 {
		return nil, errors.New("X or Y is nil")
	}
	tmp := get65BytesPub(key.X, key.Y, key.Params().BitSize)
	if key.recover {
		hForAddress := hash.NewHasher(crypto.KECCAK_256)
		address, _ := hForAddress.Hash(tmp[1:]) //remove 04
		key.address = address[12:]
		return key.address, nil
	}
	return tmp, nil
}

func get65BytesPub(X, Y *big.Int, bitsLen int) []byte {
	x := X.Bytes()
	y := Y.Bytes()
	byteLen := (bitsLen + 7) >> 3
	tmp := make([]byte, byteLen*2+1)
	tmp[0] = 0x04
	copy(tmp[byteLen+1-len(x):], x)
	copy(tmp[byteLen*2+1-len(y):], y)
	return tmp
}

// Verify verify the signature by ECDSAPublicKey self, so the first parameter will be ignored.
func (key *ECDSAPublicKey) Verify(_ []byte, signature, digest []byte) (valid bool, err error) {
	var signatureBytes ECDSASignature
	//倾向于是recovery的，也就是用户会把该是recovery=true的错误传入false
	var recovery = key.Curve == secp256k1.S256() && (key.recover || len(signature) == 65)
	var haveXY = key.X != nil && key.Y != nil
	_, err = asn1.Unmarshal(signature, &signatureBytes)
	var asn1Form = err == nil

	if !asn1Form && len(signature) != 65 {
		return false, fmt.Errorf("worng signature format: %v", hex.EncodeToString(signature))
	}
	if !recovery && !haveXY {
		return false, fmt.Errorf("key is empty")
	}

	switch {
	case recovery && asn1Form: //transfer to 65byte
		if !haveXY {
			return false, fmt.Errorf("k1: key is recover mod, but signature is asn1From")
		}
		fallthrough
	case !recovery && asn1Form:
		if !normalVerify(key.Curve, key.X, key.Y, signatureBytes.R, signatureBytes.S, digest) {
			return false, errors.New(errInvalidSignature)
		}
	case recovery && !asn1Form: //65byte
		var keyOrAddress []byte
		if haveXY {
			keyOrAddress = get65BytesPub(key.X, key.Y, key.Params().BitSize)
		} else {
			keyOrAddress = key.address
		}
		if !recoverVerify(signature, keyOrAddress, digest) {
			return false, errors.New(errInvalidSignature)
		}
	case !recovery && !asn1Form: //65byte
		if key.Curve == secp256k1.S256() && haveXY {
			if !recoverVerify(signature, get65BytesPub(key.X, key.Y, key.Params().BitSize), digest) {
				return false, errors.New(errInvalidSignature)
			}
		}
		return false, fmt.Errorf("k1: key is not recovery mod, but signature is 65bytes")
	}
	return true, nil
}

func normalVerify(c elliptic.Curve, x, y, r, s *big.Int, digest []byte) bool {
	return ecdsa.Verify(&ecdsa.PublicKey{
		Curve: c,
		X:     x,
		Y:     y,
	}, digest, r, s)
}

func recoverVerify(signature, keyOrAddr, digest []byte) bool {
	target, rerr := secp256k1.RecoverPubkey(digest, signature)
	if rerr != nil {
		return false
	}

	if len(keyOrAddr) == 20 {
		hForAddress := hash.NewHasher(crypto.KECCAK_256)
		target, _ = hForAddress.Hash(target[1:]) //remove 04
		target = target[12:]
	}
	return bytes.Equal(target, keyOrAddr)
}

//AlgorithmType return the algorithm type
func (key *ECDSAPublicKey) AlgorithmType() int {
	if key.recover {
		return AlgoP256K1Recover
	}
	switch key.Curve {
	case secp256k1.S256():
		return AlgoP256K1
	case elliptic.P256():
		return AlgoP256R1
	case elliptic.P384():
		return AlgoP384R1
	case elliptic.P521():
		return AlgoP521R1
	default:
		return AlgorithmNone
	}
}
