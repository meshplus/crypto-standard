package ed25519_test

import (
	"crypto/rand"
	"fmt"
	"github.com/meshplus/crypto-standard/ed25519"
	"testing"
)

var numOfMember = 10
var message = []byte("Hello World")

var datePrivKey = [64]byte{
	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
	0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
	0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a}
var datePub = [32]byte{
	0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
	0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
	0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
	0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a}

func Example() {
	//w & l
	pubKeyTmp, priKeyTmp := ed25519.EDDSAPublicKey(datePub), ed25519.EDDSAPrivateKey(datePrivKey)
	pubKey1, priKey1, pubKey2, priKey2 := &pubKeyTmp, &priKeyTmp, &pubKeyTmp, &priKeyTmp

	pubKeys := []*ed25519.EDDSAPublicKey{pubKey1, pubKey2}
	w1, w2 := ed25519.NewEd25519Witness(priKey1), ed25519.NewEd25519Witness(priKey2)
	l := ed25519.NewEd25519Leader(pubKeys)
	//commit
	V1, V2 := w1.Commit(rand.Reader), w2.Commit(rand.Reader)

	//challenge
	c := l.Challenge([]ed25519.Commitment{V1, V2})

	//response
	r1, r2 := w1.Response(message, c, l.GetAggPublicKey()), w2.Response(message, c, l.GetAggPublicKey())

	// Sign a test message.
	fmt.Printf("verify part 1: %v\n", l.VerifyPartSign(message, c, 0, V1, r1))
	fmt.Printf("verify part 2: %v\n", l.VerifyPartSign(message, c, 1, V2, r2))
	sign := l.AggSign(c, []ed25519.SignaturePart{r1, r2})

	// Now verify the resulting collective signature.
	// This can be done by anyone any time, not just the leader.
	valid := w1.AggVerify(2, message, sign, l.GetAggPublicKey())
	fmt.Printf("signature valid: %v", valid)

	// Output:
	// verify part 1: true
	// verify part 2: true
	// signature valid: true
}

//ExampleWitness_AggVerify_threshold is Threshold
func ExampleWitness_AggVerify_threshold() {
	// 参与投票的人应该都有自己的公私钥，公钥公开
	pubKeys := make([]*ed25519.EDDSAPublicKey, numOfMember)
	priKeys := make([]*ed25519.EDDSAPrivateKey, numOfMember)
	for i := 0; i < numOfMember; i++ {
		priKeys[i], pubKeys[i] = ed25519.GenerateKey(rand.Reader)
	}

	//w & l
	witnesses := make([]ed25519.Witness, numOfMember)
	for i := range witnesses {
		witnesses[i] = ed25519.NewEd25519Witness(priKeys[i])
	}
	l := ed25519.NewEd25519Leader(pubKeys)
	if l == nil {
		fmt.Println("init leader err")
		return
	}

	//commit
	Vs := make([]ed25519.Commitment, numOfMember)
	for i := 0; i < numOfMember; i++ {
		Vs[i] = witnesses[i].Commit(rand.Reader)
	}
	Vs[9] = nil //模拟没有收到9号的commit

	//challenge
	c := l.Challenge(Vs) //如果没有收到某成员的commit，随机生成一个

	//response
	rs := make([]ed25519.SignaturePart, numOfMember)
	for i := 0; i < numOfMember; i++ {
		rs[i] = witnesses[i].Response(message, c, l.GetAggPublicKey())
	}

	//agg sign
	for i := range rs {
		rs[2][0] = 0                                        //模拟2号的签名验签失败
		r1 := l.VerifyPartSign(message, c, i, Vs[i], rs[i]) //2号验签失败，自动disable
		r2 := i == 2 || i == 9
		if r1 == r2 {
			fmt.Printf("error part signature:%v\n", i)
			return
		}
	}
	signature := l.AggSign(c, rs) //signature don't include 2

	//验签，按照超过投票超过8票的要求验证
	valid := witnesses[0].AggVerify(8, message, signature, l.GetAggPublicKey()) //cX + V ?= rG
	fmt.Printf("signature valid: %v\n", valid)

	//验签，按照超过投票超过9票的要求验证
	valid = witnesses[0].AggVerify(9, message, signature, l.GetAggPublicKey()) //cX + V ?= rG
	fmt.Printf("signature valid: %v", valid)

	// Output:
	// signature valid: true
	// signature valid: false
}

func BenchmarkExample(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pubKeyTmp, priKeyTmp := ed25519.EDDSAPublicKey(datePub), ed25519.EDDSAPrivateKey(datePrivKey)
		pubKey1, priKey1, pubKey2, priKey2 := &pubKeyTmp, &priKeyTmp, &pubKeyTmp, &priKeyTmp
		pubKeys := []*ed25519.EDDSAPublicKey{pubKey1, pubKey2}
		w1, w2 := ed25519.NewEd25519Witness(priKey1), ed25519.NewEd25519Witness(priKey2)
		l := ed25519.NewEd25519Leader(pubKeys)
		V1, V2 := w1.Commit(rand.Reader), w2.Commit(rand.Reader)
		c := l.Challenge([]ed25519.Commitment{V1, V2})
		r1, r2 := w1.Response(message, c, l.GetAggPublicKey()), w2.Response(message, c, l.GetAggPublicKey())
		sign := l.AggSign(c, []ed25519.SignaturePart{r1, r2})
		w1.AggVerify(2, message, sign, l.GetAggPublicKey())
	}
}
