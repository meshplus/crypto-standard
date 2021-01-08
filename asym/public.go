package asym

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"github.com/meshplus/crypto-standard/asym/secp256k1"
	"github.com/meshplus/crypto-standard/hash"
	"math/big"
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
func (key *ECDSAPublicKey) FromBytes(k []byte, opt AlgorithmOption) *ECDSAPublicKey {
	//in recover mode, the verification does not need to actually pass in a public key
	//k is a address
	if opt == AlgoP256K1Recover {
		key.Curve = secp256k1.S256()
		key.recover = true
		key.address = k
		return key
	}
	key.recover = false
	key.address = nil

	if len(k) != 65 {
		return nil
	}
	if key.X == nil {
		key.X = GetBig()
	}
	if key.Y == nil {
		key.Y = GetBig()
	}
	key.X.SetBytes(k[1:33])
	key.Y.SetBytes(k[33:])
	switch opt {
	case AlgoP256K1:
		key.Curve = secp256k1.S256()
	case AlgoP256R1:
		key.Curve = elliptic.P256()
	}
	return key
}

//Bytes return key bytes
func (key *ECDSAPublicKey) Bytes() ([]byte, error) {
	if key.recover {
		return nil, errors.New("the ECDSAPublicKey.Bytes() should not be called in recover mode")
	}
	if key.Y == nil || key.X == nil {
		return nil, errors.New("X or Y is nil")
	}
	x := key.X.Bytes()
	y := key.Y.Bytes()
	tmp := make([]byte, 65)
	tmp[0] = 0x04
	copy(tmp[33-len(x):], x)
	copy(tmp[65-len(y):], y)
	return tmp, nil
}

// Verify verify the signature by ECDSAPublicKey self, so the first parameter will be ignored.
func (key *ECDSAPublicKey) Verify(_ []byte, signature, digest []byte) (valid bool, err error) {
	//1. 256k1
	if key.Curve == secp256k1.S256() {
		if len(signature) != 65 {
			sigS := new(ECDSASignature)
			_, uerr := asn1.Unmarshal(signature, sigS)
			if uerr != nil {
				return false, uerr
			}
			if !ecdsa.Verify(&ecdsa.PublicKey{
				Curve: key.Curve,
				X:     key.X,
				Y:     key.Y,
			}, digest, sigS.R, sigS.S) {
				return false, errors.New(errInvalidSignature)
			}
			return true, nil
		}
		digest = paddingOrCut(digest)
		recoverKey, rerr := secp256k1.RecoverPubkey(digest, signature)
		if rerr != nil {
			return false, rerr
		}
		//1.1 recover mode
		if key.recover {
			if len(key.address) != 20 {
				return false, errors.New("in recover mode, disest should be a address in 20bytes")
			}
			h, _ := hash.NewHasher(hash.KECCAK_256).Hash(recoverKey[1:]) //remove 04
			if bytes.Compare(h[12:], key.address) != 0 {
				return false, errors.New(errInvalidSignature)
			}
			return true, nil
		}
		//1.2 normal mode
		pub, berr := key.Bytes()
		if berr != nil {
			return false, berr
		}

		if bytes.Compare(recoverKey, pub) != 0 {
			return false, errors.New(errInvalidSignature)
		}
		return true, nil
	}
	//2. 256r1 224r1 384r1 521r1
	signatureBytes := new(ECDSASignature)
	_, err = asn1.Unmarshal(signature, signatureBytes)
	if err != nil {
		return false, errors.New(errInvalidSignature)
	}

	if !ecdsa.Verify(&ecdsa.PublicKey{
		Curve: key.Curve,
		X:     key.X,
		Y:     key.Y,
	}, digest, signatureBytes.R, signatureBytes.S) {
		return false, errors.New(errInvalidSignature)
	}
	return true, nil
}

//AlgorithmType return the algorithm type
func (key *ECDSAPublicKey) AlgorithmType() AlgorithmOption {
	if key.recover {
		return AlgoP256K1Recover
	}
	switch key.Curve {
	case secp256k1.S256():
		return AlgoP256K1
	case elliptic.P256():
		return AlgoP256R1
	case elliptic.P224():
		return AlgoP224R1
	case elliptic.P384():
		return AlgoP384R1
	case elliptic.P521():
		return AlgoP521R1
	default:
		return AlgorithmOption("illegal algorithm type")
	}
}
