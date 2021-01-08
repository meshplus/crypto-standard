//Hyperchain License
//Copyright (C) 2016 The Hyperchain Authors.

package secp256k1

import "C"
import (
	"github.com/meshplus/crypto-standard/asym/secp256k1/internal"
	"io"
	"math/big"
)

// holds ptr to secp256k1_context_struct (see secp256k1/include/secp256k1.h)
var (
	N *big.Int
)

func init() {
	N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
}

//Sign return signature
func Sign(msg []byte, seckey []byte, rand io.Reader) ([]byte, error) {
	return internal.Sign(msg, seckey, rand)
}

// RecoverPubkey returns the the public key of the signer.
// msg must be the 32-byte hash of the message to be signed.
// sig must be a 65-byte compact ECDSA signature containing the
// recovery id as the last element.
func RecoverPubkey(msg []byte, sig []byte) ([]byte, error) {
	return internal.RecoverPubkey(msg, sig)
}
