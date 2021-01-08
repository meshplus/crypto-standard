package internal_test

import (
	"encoding/hex"
	"fmt"
	"github.com/meshplus/crypto-standard/ed25519/internal"
	"math/big"
)

//ComputedL
func ExampleEd25519Verify() {
	//l = 2^252 + 27742317777372353535851937790883648493.
	a, _ := new(big.Int).SetString("1000000000000000000000000000000000000000000000000000000000000000", 16)
	b, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	a.Add(a, b)
	fmt.Println(hex.EncodeToString(a.Bytes()))

	le := new(internal.Bignum256)
	in := new([32]byte)
	copy(in[:], a.Bytes()[:])
	internal.LE2Polynomial(le, in)

	fmt.Printf("0x%x 0x%x 0x%x 0x%x 0x%x\n", le[0], le[1], le[2], le[3], le[4])
	//output:
	//1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
	//0x10 0x0 0xa2def9de140000 0x1a631258d69cf7 0xedd3f55c
}
