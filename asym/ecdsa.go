package asym

import (
	"errors"
	"io"
)

//ECDSA ECDSA instance is a tool to sign and verify.
// You can sign and verify via ECDSAPrivateKey and ECDSAPublicKey, ECDSA instance is just a package of ECDSAPrivateKey's Sign and ECDSAPublicKey's Verify.
// If you need revoke Sign or Verify at a sepcific Key many times, we recommend using ECDSAPrivateKey and ECDSAPublicKey, which avoid decode and alloc repeatedly.
// All in all, ECDSA is convenient; ECDSAPrivateKey and ECDSAPublicKey are faster.
type ECDSA struct {
	Opt AlgorithmOption
}

//NewECDSA get a ECDSA instance, input parameter is algorithm type
func NewECDSA(opt AlgorithmOption) *ECDSA {
	return &ECDSA{Opt: opt}
}

//Sign get signature to digest, k is the private key
func (sv *ECDSA) Sign(k []byte, digest []byte, reader io.Reader) (signature []byte, err error) {
	return new(ECDSAPrivateKey).FromBytes(k, sv.Opt).Sign(reader, digest, nil)
}

//Verify verify signature ,k is the public key
func (sv *ECDSA) Verify(k []byte, signature, digest []byte) (valid bool, err error) {
	key := new(ECDSAPublicKey).FromBytes(k, sv.Opt)
	if key == nil {
		return false, errors.New("k is not a valide public key")
	}
	return key.Verify(nil, signature, digest)
}
