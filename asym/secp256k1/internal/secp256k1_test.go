package internal

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func BenchmarkCurveScalarMult(b *testing.B) {
	r := make([]byte, 32)
	_, _ = rand.Read(r)
	x, _ := new(big.Int).SetString("b89cd926c8b1fa219587eb65a68b3c963dd941fc3a426b50d12be30fbb756a58", 16)
	y, _ := new(big.Int).SetString("e89d75acbaac61ee27f475eb7437dd997a973791e5fb1aa1a03b3b26e6181e12", 16)
	for i := 0; i < b.N; i++ {
		CurveScalarMult(x, y, r)
	}
}

func BenchmarkBaseMul(b *testing.B) {
	r := make([]byte, 32)
	_, _ = rand.Read(r)
	for i := 0; i < b.N; i++ {
		BaseMul(r)
	}
}
func TestCsprng(t *testing.T) {
	a, err := csprng(32, rand.Reader)
	assert.Nil(t, err)
	b, err := csprng(32, rand.Reader)
	assert.Nil(t, err)
	if bytes.Equal(a, b) {
		t.Errorf("got same nonce a = %s, b= %s", hex.EncodeToString(a), hex.EncodeToString(b))
	}
}
