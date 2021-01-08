//+build amd64

package ed25519

import (
	"crypto"
	"fmt"
	"github.com/meshplus/crypto-standard/ed25519/internal"
	"io"
)

//BatchHeapGo in amd64
type BatchHeapGo = internal.BatchHeapGo

//heapIndex in batch.Heap
type heapIndex = uint64

//ExtendedGroupElement is a point of edwards curve
type ExtendedGroupElement = internal.ExtendedGroupElement

//Bignum256 in amd64
type Bignum256 = internal.Bignum256

//scReduce generate bignum256 from bytes
var scReduce = internal.ScReduce

//neg -(bignum256)
var neg = internal.FeNeg

//geScalarMultBase scalar * basepoint
var geScalarMultBase = internal.GeScalarMultBase

//scMulAdd out = a *b + c
var scMulAdd = internal.ScMulAdd

//scAdd out = a + b
var scAdd = internal.ScAdd

//geDoubleScalarMultVartime combine scalar * point add  add
var geDoubleScalarMultVartime = internal.GeDoubleScalarMultVartime

//batchVerifyInit init
var batchVerifyInit = internal.BatchVerifyInit

//batchVerifyEnd end
var batchVerifyEnd = internal.BatchVerifyEnd

//batchTestHeap just for test
var batchTestHeap = internal.BatchTestHeap

//ed25519Verify verify ed25519 signature
var ed25519Verify = internal.Ed25519Verify

//polynomial2LE bignum256 to []byte
var polynomial2LE = internal.Polynomial2LE

//lE2Polynomial []byte to bignum256
var lE2Polynomial = internal.LE2Polynomial

//GenerateKey get a EDDSA private key
func GenerateKey(reader io.Reader) (*EDDSAPrivateKey, *EDDSAPublicKey) {
	sk := internal.GenerateEd25519Key(reader)
	pk := new(EDDSAPublicKey)
	copy(pk[:], sk[EddsaVKLen-EddsaPKLen:])
	return (*EDDSAPrivateKey)(sk), pk
}

//Sign get signature of specific digest by EDDSAPrivateKey self,so the first parameter will be ignored
func (key *EDDSAPrivateKey) Sign(_ io.Reader, msg []byte, _ crypto.SignerOpts) ([]byte, error) {
	r := internal.Ed25519Sign(msg, key[:], key[EddsaPKLen:])
	if r == nil {
		return nil, fmt.Errorf("ed25519 sign err")
	}
	return r, nil
}

//Verify verify the signature by EDDSAPublicKey self, so the first parameter will be ignored.
func (key *EDDSAPublicKey) Verify(_ []byte, signature, msg []byte) (valid bool, err error) {
	if len(signature) != EddsaSignLen {
		return false, fmt.Errorf("signature length mast be 64")
	}
	return internal.Ed25519Verify(msg, key[:], signature), nil
}
