package asym

import (
	"math/big"
	"sync"
)

var one = big.NewInt(1)
var zero = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

var bigPool = sync.Pool{New: func() interface{} {
	return new(big.Int)
}}

var bytes32Pool = sync.Pool{New: func() interface{} {
	return make([]byte, 32)
}}

//Get32BYtes get 32 bytes
func Get32BYtes() []byte {
	return bytes32Pool.Get().([]byte)
}

//Put32Bytes put 32 bytes
func Put32Bytes(in []byte) {
	copy(zero[:], in)
	bytes32Pool.Put(in)
}

//GetBig git big
func GetBig() *big.Int {
	return bigPool.Get().(*big.Int)
}

//PutBig put big
func PutBig(in *big.Int) {
	in.Xor(in, in)
	bigPool.Put(in)
}

//Copy copy big
func Copy(in *big.Int) *big.Int {
	r := big.NewInt(0)
	return r.Add(in, r)
}
