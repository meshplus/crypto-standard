package ed25519

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

type constReader struct{ val byte }

func (cr constReader) Read(buf []byte) (int, error) {
	for i := range buf {
		buf[i] = cr.val
	}
	return len(buf), nil
}

var pubKeys []*EDDSAPublicKey
var priKeys []*EDDSAPrivateKey

var rightMessage = []byte("test message")
var wrongMessage = []byte("wrong message")

func genKeys(n int) {
	for len(priKeys) < n {
		i := len(priKeys)
		pri, pub := GenerateKey(constReader{byte(i)})
		pubKeys = append(pubKeys, pub)
		priKeys = append(priKeys, pri)
	}
}

func testCosign(tb testing.TB, message []byte, priKey []*EDDSAPrivateKey,
	l Leader) []byte {

	n := len(priKey)

	aggX := l.GetAggPublicKey()

	// Create the individual commits and corresponding secrets
	// (these would be done by the individual participants in practice)
	commits := make([]Commitment, n)
	witnesses := make([]Witness, n)
	for i := range commits {
		witnesses[i] = NewEd25519Witness(priKey[i])
		commits[i] = witnesses[i].Commit(rand.Reader)
	}

	// Leader: combine the individual commits into an aggregate commit
	c := l.Challenge(commits)

	// Create the individual signature parts
	rs := make([]SignaturePart, n)
	for i := range rs {
		rs[i] = witnesses[i].Response(message, c, aggX)

		// verify each part individually
		if !l.VerifyPartSign(message, c, i, commits[i], rs[i]) {
			tb.Errorf("signature part %d rejected ", i)
		}
	}

	// Leader: combine the signature parts into a collective signature
	return l.AggSign(c, rs)
}

func countTotal(leader Leader) int {
	l := leader.(*ed25519Leader)
	return len(l.keys)
}

func countEnable(leader Leader) int {
	l := leader.(*ed25519Leader)
	j := uint(0)
	for i := range l.mask {
		temp := l.mask[i]
		for k := 0; k < 8; k++ {
			j += uint(temp&0x01 ^ 0x01)
			temp = temp >> 1
		}
	}
	return int(j)
}

func TestSignVerify(t *testing.T) {

	// Create a number of distinct keypairs
	n := 5
	genKeys(n)
	l := NewEd25519Leader(pubKeys[:n]) // all enabled by default
	if countTotal(l) != n {
		t.Errorf("cosigners reports incorrect number of public keys")
	}
	if countEnable(l) != n {
		t.Errorf("cosigners reports incorrect number of enabled keys")
	}

	// collectively sign a test message
	sig := testCosign(t, rightMessage, priKeys[:n], l)
	fool := NewEd25519Witness(priKeys[0])
	if !fool.AggVerify(uint(n), rightMessage, sig, l.GetAggPublicKey()) {
		t.Errorf("valid signature rejected")
	}

	if fool.AggVerify(uint(n), wrongMessage, sig, l.GetAggPublicKey()) {
		t.Errorf("signature of different message accepted")
	}

	// now collectively sign with only a partial cosigners set
	l.SetDisable(3)
	if countEnable(l) != n-1 {
		t.Errorf("cosigners reports incorrect number of enabled keys")
	}
	sig = testCosign(t, rightMessage, priKeys[:n], l)
	assert.False(t, fool.AggVerify(uint(n), rightMessage, sig, l.GetAggPublicKey()), "signature with too few cosigners accepted")

	// now reduce the verification threshold
	assert.True(t, fool.AggVerify(uint(n-1), rightMessage, sig, l.GetAggPublicKey()), "valid threshold not accepted")

	// now remove another cosigner and make sure it breaks again
	l.SetDisable(4)
	if countEnable(l) != n-2 {
		t.Errorf("cosigners reports incorrect number of enabled keys")
	}
	sig = testCosign(t, rightMessage, priKeys[:n], l)
	assert.False(t, fool.AggVerify(uint(n-1), rightMessage, sig, l.GetAggPublicKey()), "signature with too few cosigners accepted")
}

func TestScReduce(t *testing.T) {
	in, _ := hex.DecodeString("035df10d284df3f08222f04dbca7a4c20ef15bdc988a22c7207411377c33f2ac035df10d284df3f08222f04dbca7a4c20ef15bdc988a22c7207411377c33f2ac")

	out := Bignum256{}
	scReduce(&out, in)
	assert.Equal(t, big2String(&out), "93975573f1f2862c8360fa0713c4cd9cf4456413d7f7ebe0e9dd1040bec0750f")
}

func TestDoubleScalar(t *testing.T) {
	datePoint := [32]byte{
		0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
		0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
		0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
		0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x9a}
	a := new(Bignum256)
	tmp1, _ := hex.DecodeString("7c8a6dc480e2daae391c50d335dc76a92d13892ab7c1cdfdfb2e2f40bfd8e302")
	tmp2 := new([32]byte)
	copy(tmp2[:], tmp1[:])
	lE2Polynomial(a, tmp2)

	b := new(Bignum256)
	tmp3, _ := hex.DecodeString("f767f113e6b89c61c0b3d89fcecd9426bf525f8397576be34eeadd6f012d2400")
	tmp4 := new([32]byte)
	copy(tmp4[:], tmp3[:])
	lE2Polynomial(b, tmp4)

	var R ExtendedGroupElement
	var P ExtendedGroupElement
	P.FromBytes(&datePoint)

	//fmt.Println("verify hram:", big2String(a))
	X := new([32]byte)
	P.ToBytes(X)
	//fmt.Println("-X", hex.EncodeToString(X[:]))
	//fmt.Println("sigS", big2String(b))
	geDoubleScalarMultVartime(&R, &P, a, b)
	out := new([32]byte)
	R.ToBytes(out)
	assert.Equal(t, hex.EncodeToString(out[:]), "0b88325025cbb7a3177d082e4a17194edeaaeaf15adee531b2cf6cb9f0ab7353")
}

func TestLETransfer(t *testing.T) {
	for i := 0; i < 1000; i++ {
		temp := new([32]byte)
		_, _ = rand.Read(temp[:])
		num := new(Bignum256)
		lE2Polynomial(num, temp)
		target := new([32]byte)
		polynomial2LE(target[:], num)
		assert.Equal(t, target, temp)
	}
}

func TestMask(t *testing.T) {
	genKeys(16)
	test := make([]byte, 2)
	for index := 0; index < 1024; index++ {
		_, _ = rand.Read(test)
		v := binary.BigEndian.Uint16(test)
		leader := NewEd25519Leader(pubKeys)
		for i := 0; i < 16; i++ {
			if v>>uint16(i)&0x01 == 1 {
				leader.SetDisable(i)
			}
		}
		l := leader.(*ed25519Leader)
		for i := 0; i < 16; i++ {
			if (v>>uint16(i)&0x01 == 1) && l.maskBit(i) != Disabled {
				t.Errorf("v: %016b, %v", v, l.maskBit(i))
			}
		}
	}
}
