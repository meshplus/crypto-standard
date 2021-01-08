package ed25519

import (
	"crypto"
	"fmt"
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
func (key *EDDSAPrivateKey) FromBytes(k []byte, opt interface{}) []byte {
	if len(k) != EddsaVKLen {
		return nil
	}
	copy(key[:], k)
	return k
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
func (key *EDDSAPublicKey) FromBytes(k []byte) *EDDSAPublicKey {
	if len(k) != EddsaPKLen {
		return nil
	}
	copy(key[:], k)
	return key
}

//Bytes return key bytes
func (key *EDDSAPublicKey) Bytes() ([]byte, error) {
	r := make([]byte, EddsaPKLen)
	copy(r, key[:])
	return r, nil
}

//BatchVerify BatchVerify
func (key *EDDSAPublicKey) BatchVerify(publicKey, signature, msg [][]byte) (valid bool, err error) {
	if len(msg) == 1 {
		msgTmp := make([][]byte, len(signature))
		for i := range msgTmp {
			msgTmp[i] = msg[0]
		}
		msg = msgTmp
	}

	if len(signature) != len(msg) || len(signature) != len(publicKey) || len(msg) == 0 {
		return false, fmt.Errorf("len(signature)、 len(msg) " +
			"and len(publicKey) not equal")
	}

	for i := range signature {
		if len(signature[i]) != EddsaSignLen || len(publicKey[i]) != EddsaPKLen {
			return false, fmt.Errorf("each signature length mast be 64," +
				"each publickey length mast be 32 ")
		}
	}
	l := len(signature)
	b := true
	for l > 2 {
		batchSize := 64
		if l < 64 {
			batchSize = l
		}
		if !BatchVerify(publicKey[:batchSize], signature[:batchSize], msg[:batchSize]) {
			b = false
			break
		}
		publicKey, signature, msg = publicKey[:batchSize], signature[:batchSize], msg[:batchSize]
		l -= batchSize
	}
	if l == 1 {
		b = ed25519Verify(msg[0], publicKey[0], signature[0])
	} else if l == 2 {
		b = ed25519Verify(msg[0], publicKey[0], signature[0]) &&
			ed25519Verify(msg[1], publicKey[1], signature[1])
	}
	if !b {
		return false, fmt.Errorf("verify err, have bad signature in batch")
	}
	return true, nil
}
