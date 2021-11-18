package ed25519

import (
	"crypto"
	"errors"
	_ "github.com/meshplus/crypto"
)

// length
const (
	EddsaPKLen   = 32
	EddsaVKLen   = 64
	EddsaSignLen = 64
)

//EDDSAPrivateKey : 64[]byte
type EDDSAPrivateKey [EddsaVKLen]byte

//Bytes return key bytes. Inverse method of FromBytes(k []byte, opt AlgorithmOption)
func (key *EDDSAPrivateKey) Bytes() ([]byte, error) {
	r := make([]byte, EddsaVKLen)
	copy(r, key[:])
	return r, nil
}

//FromBytes parse a private Key from bytes, Inverse method of Bytes()
func (key *EDDSAPrivateKey) FromBytes(k []byte, opt int) error {
	if len(k) != EddsaVKLen {
		return errors.New("length error")
	}
	copy(key[:], k)
	return nil
}

//Public Get EDDSAPublicKey from a EDDSAPrivateKey, if EDDSAPublicKey is empty, this method will invoke CalculatePublicKey().
func (key *EDDSAPrivateKey) Public() crypto.PublicKey {
	r := new(EDDSAPublicKey)
	copy(r[:], key[EddsaPKLen:])
	return r
}

//EDDSAPublicKey :32[]byte
type EDDSAPublicKey [EddsaPKLen]byte

//FromBytes Parse a public key from 65 bytes and specific algorithm.The reverse method of Bytes()
func (key *EDDSAPublicKey) FromBytes(k []byte, opt int) error {
	if len(k) != EddsaPKLen {
		return errors.New("length error")
	}
	copy(key[:], k)
	return nil
}

//Bytes return key bytes
func (key *EDDSAPublicKey) Bytes() ([]byte, error) {
	r := make([]byte, EddsaPKLen)
	copy(r, key[:])
	return r, nil
}

