package ed25519

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/rand"
	"testing"
)

var Ps [10]ExtendedGroupElement

var input = []string{
	"6a62a6205507fcafe9ee43d6f8332a37144085f9ae454611263232ec771107c6",
	"f1bed61e1ecbce3f5c4f562a66d6d679749d3e1cd4ef9e36a909ff8e8b39858e",
	"01633d1be2a99e5a04b1e47c44f90336e15cb5dac62ced2f68f52b1e0911f454",
	"c9f7ec3ef931bd89f78e63b734e9d0bf3468a58e6fda16ca991645337d569e57",
	"f36b246bb8b88c397775ac1ad34606295cae333150ce2fc568e99a620f9d2b73",
	"d28d272dbfb761925541c14117cc3454b5f610df732518a1cab644c9277fe538",
	"6d0f36e2e942450340bbfcb96849fbe0fa97ad8e0b99bbee19e1a4caa6906e50",
	"4991cdf5856f465ca76735a2c341274bdb4b0a2b867dc25ed02f5c699cbcf872",
	"ad743c5f9f9d9e12bf31f3120580cc45cbec5edf5aba6457ed9433af279baccf",
	"c38f873d8b07fc976dd7d6611397d635b5879c90b271e649f14d2328435bc51e",
}

var sum = []string{
	"36a1e8bcaba7d31818d953e5e3e4ac67e46537d7fafbb7a48205dac9e6a85933",
	"5c7b9402d615532cf60cb6aa2c2f1914b18aab56d739fa52d7df10a068cf6f77",
	"0af69aedf904813ad481e8770fb3d75c31814c3dec254b8d7d019656aad09979",
	"ba3a429d16a75037e59c0af7f7d456f12dd7782331783ebe44505ecbedfd208c",
	"4cfff383bf92fe6dcb070753b9a242eb36f9344b6e4abd3bd6e0539efd6fbe3d",
}

func init() {
	for i := range input {
		encode := [32]byte{}
		temp, _ := hex.DecodeString(input[i])
		copy(encode[:], temp)
		if !Ps[i].FromBytes(&encode) {
			panic("error 1")
		}
	}
}

func toString(e ExtendedGroupElement) string {
	encode := [32]byte{}
	e.ToBytes(&encode)
	return hex.EncodeToString(encode[:])
}

func TestEncode(t *testing.T) {
	inputInner := append(input, sum...)
	for i := range inputInner {
		ge := new(ExtendedGroupElement)
		bs := [32]byte{}
		temp, _ := hex.DecodeString(inputInner[i])
		copy(bs[:], temp)
		ge.FromBytes(&bs)
		bs = [32]byte{0}
		ge.ToBytes(&bs)
		if bytes.Compare(bs[:], temp) != 0 {
			fmt.Println("-----------", i)
			fmt.Printf("%v\n", hex.EncodeToString(temp[:]))
			fmt.Printf("%v\n", hex.EncodeToString(bs[:]))
			fmt.Printf("want: %08b\n", temp[31])
			fmt.Printf("got : %08b\n", bs[31])
			t.Fail()
		}
	}
}

func TestAdd_Sub(t *testing.T) {

	var Sum [5]ExtendedGroupElement
	//----add----
	for i := 0; i < 5; i++ {
		Sum[i].Add(&Ps[2*i], &Ps[2*i+1])
		if toString(Sum[i]) != sum[i] {
			fmt.Println("add-----------", i)
			fmt.Printf("%v\n", toString(Sum[i]))
			fmt.Printf("%v\n", sum[i])
			t.Fail()
		}
	}
	//----sub----
	for i := 0; i < 5; i++ {
		sub := ExtendedGroupElement{}
		sub.Sub(&Sum[i], &Ps[2*i])
		if toString(sub) != toString(Ps[2*i+1]) {
			fmt.Println("sub-----------", i)
			fmt.Printf("%v\n", toString(sub))
			fmt.Printf("%v\n", toString(Ps[2*i+1]))
			t.Fail()
		}
	}
}

func TestEncodeOnly(t *testing.T) { //ok
	code := "6a62a6205507fcafe9ee43d6f8332a37144085f9ae454611263232ec771107c6"
	ge := new(ExtendedGroupElement)
	bs := [32]byte{}
	temp, _ := hex.DecodeString(code)
	copy(bs[:], temp)
	ge.FromBytes(&bs)

	bs = [32]byte{0}
	ge.ToBytes(&bs)
	assert.Equal(t, hex.EncodeToString(bs[:]), code)
}

func TestReduce(t *testing.T) {
	input := "d6658452c234151a85fa4be812543ea3bd45f7a1880fd881882f9e0cdf31aac6ffc11c8d37da6b81941f27e088ec82c2bcc56806312f7d1778b8e9f88daab5b1"
	hash, _ := hex.DecodeString(input)
	hram := Bignum256{}
	scReduce(&hram, hash)
	assert.Equal(t, big2String(&hram), "e4109b82e5d9fd898be765047b33eab2d55a0a0dba342775f223fa2573e7df0c")
}

func big2String(n *Bignum256) string {
	tmp := new([32]byte)
	polynomial2LE(tmp[:], n)
	return hex.EncodeToString(tmp[:])
}

func TestGeSub(t *testing.T) {
	dByte, _ := hex.DecodeString("a3785913ca4deb75abd841414d0a700098e879777940c78c73fe6f2bee6c0352")
	d2Byte, _ := hex.DecodeString("59f1b226949bd6eb56b183829a14e00030d1f3eef2808e19e7fcdf56dcd90624")
	want, _ := hex.DecodeString("126a5b9f1ac4267df92b49b6de654b4dbbbbedf3809136951371298dacbcb5d7")
	var dArray, d2Array [32]byte
	copy(dArray[:], dByte)
	copy(d2Array[:], d2Byte)
	var d, d2 ExtendedGroupElement
	d.FromBytes(&dArray)
	d2.FromBytes(&d2Array)

	d2.Sub(&d2, &d)
	var r [32]byte
	d2.ToBytes(&r)
	assert.Equal(t, r[:], want)
}

func BenchmarkEDDSA_Add(b *testing.B) {
	var Sum ExtendedGroupElement
	for i := 0; i < b.N; i++ {
		Sum.Add(&Ps[0], &Ps[1])
	}
}

func BenchmarkEDDSA_ScalMul(B *testing.B) {
	var Sum ExtendedGroupElement
	a := new(Bignum256)
	b := new(Bignum256)
	r := make([]byte, 128)
	_, _ = rand.Read(r)
	scReduce(a, r)

	for i := 0; i < B.N; i++ {
		geDoubleScalarMultVartime(&Sum, &Ps[1], a, b)
	}
}

func BenchmarkEDDSA_ScalMulBase(B *testing.B) {
	var Sum ExtendedGroupElement
	a := new(Bignum256)
	r := make([]byte, 128)
	_, _ = rand.Read(r)
	scReduce(a, r)

	for i := 0; i < B.N; i++ {
		geScalarMultBase(&Sum, a)
	}
}
