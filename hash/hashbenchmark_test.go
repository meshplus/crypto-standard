package hash

import (
	"bytes"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func BenchmarkSHA1(b *testing.B) {
	hasher := NewHasher(SHA1)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		hash, err := hasher.Hash([]byte(msg))
		b.StopTimer()
		assert.Nil(b, err)
		if hex.EncodeToString(hash) != sha1Expect {
			b.Error("err")
		}
	}
}

func BenchmarkSHA2_256(b *testing.B) {
	hasher := NewHasher(SHA2_256)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		hash, err := hasher.Hash([]byte(msg))
		b.StopTimer()
		assert.Nil(b, err)
		if hex.EncodeToString(hash) != sha2_256Expect {
			b.Error("err")
		}
	}
}

func BenchmarkSHA2_512(b *testing.B) {
	hasher := NewHasher(SHA2_512)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		hash, err := hasher.Hash([]byte(msg))
		b.StopTimer()
		assert.Nil(b, err)
		if hex.EncodeToString(hash) != sha2_512Expect {
			b.Error("err")
		}
	}
}

func BenchmarkKeccak224(b *testing.B) {
	hasher := NewHasher(KECCAK_224)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		hash, err := hasher.Hash([]byte(msg))
		b.StopTimer()
		assert.Nil(b, err)
		assert.Equal(b, hex.EncodeToString(hash), keccak224Expect)
	}
}

func BenchmarkKeccak5224_WithBuffer(b *testing.B) {
	hasher := NewHasher(KECCAK_224)
	reuseBuff := make([]byte, 0, 28)
	var err error
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		reuseBuff = reuseBuff[:0]
		reuseBuff, err = hasher.HashBuffer([]byte(msg), reuseBuff)
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if hex.EncodeToString(reuseBuff) != keccak224Expect {
			b.Error("err")
		}
	}
}

func BenchmarkKeccak256(b *testing.B) {
	hasher := NewHasher(KECCAK_256)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		hash, err := hasher.Hash([]byte(msg))
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if hex.EncodeToString(hash) != keccak256Expect {
			b.Error("err")
		}
	}
}

func BenchmarkKeccak256_WithBuffer(b *testing.B) {
	hasher := NewHasher(KECCAK_256)
	reuseBuff := make([]byte, 0, 32)
	var err error
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		reuseBuff = reuseBuff[:0]
		reuseBuff, err = hasher.HashBuffer([]byte(msg), reuseBuff)
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if hex.EncodeToString(reuseBuff) != keccak256Expect {
			b.Error("err")
		}
	}
}

func BenchmarkKeccak384(b *testing.B) {
	hasher := NewHasher(KECCAK_384)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		hash, err := hasher.Hash([]byte(msg))
		b.StopTimer()
		assert.Nil(b, err)
		if hex.EncodeToString(hash) != keccak384Expect {
			b.Error("err")
		}
	}
}

func BenchmarkKeccak384_WithBuffer(b *testing.B) {
	hasher := NewHasher(KECCAK_384)
	reuseBuff := make([]byte, 0, 48)
	var err error
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		reuseBuff = reuseBuff[:0]
		reuseBuff, err = hasher.HashBuffer([]byte(msg), reuseBuff)
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if hex.EncodeToString(reuseBuff) != keccak384Expect {
			b.Error("err")
		}
	}
}

func BenchmarkKeccak512(b *testing.B) {
	hasher := NewHasher(KECCAK_512)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		hash, err := hasher.Hash([]byte(msg))
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if hex.EncodeToString(hash) != keccak512Expect {
			b.Error("err")
		}
	}
}

func BenchmarkKeccak512_WithBuffer(b *testing.B) {
	hasher := NewHasher(KECCAK_512)
	reuseBuff := make([]byte, 0, 64)
	var err error
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		reuseBuff = reuseBuff[:0]
		reuseBuff, err = hasher.HashBuffer([]byte(msg), reuseBuff)
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if hex.EncodeToString(reuseBuff) != keccak512Expect {
			b.Error("err")
		}
	}
}

func BenchmarkSHA3_224(b *testing.B) {
	hasher := NewHasher(SHA3_224)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		hash, err := hasher.Hash([]byte(msg))
		b.StopTimer()
		assert.Nil(b, err)
		if hex.EncodeToString(hash) != sha3_224Expect {
			b.Error("err")
		}
	}
}

func BenchmarkSHA3_224_WithBuffer(b *testing.B) {
	hasher := NewHasher(SHA3_224)
	reuseBuff := make([]byte, 0, 28)
	var err error
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		reuseBuff = reuseBuff[:0]
		reuseBuff, err = hasher.HashBuffer([]byte(msg), reuseBuff)
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if hex.EncodeToString(reuseBuff) != sha3_224Expect {
			b.Error("err")
		}
	}
}

func BenchmarkSHA3_256(b *testing.B) {
	hasher := NewHasher(SHA3_256)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		hash, err := hasher.Hash([]byte(msg))
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if hex.EncodeToString(hash) != sha3_256Expect {
			b.Error("err")
		}
	}
}

func BenchmarkSHA3_256_WithBuffer(b *testing.B) {
	hasher := NewHasher(SHA3_256)
	reuseBuff := make([]byte, 0, 32)
	var err error
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		reuseBuff = reuseBuff[:0]
		reuseBuff, err = hasher.HashBuffer([]byte(msg), reuseBuff)
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if hex.EncodeToString(reuseBuff) != sha3_256Expect {
			b.Error("err")
		}
	}
}

func BenchmarkSHA3_384(b *testing.B) {
	hasher := NewHasher(SHA3_384)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		hash, err := hasher.Hash([]byte(msg))
		b.StopTimer()
		assert.Nil(b, err)
		if hex.EncodeToString(hash) != sha3_384Expect {
			b.Error("err")
		}
	}
}

func BenchmarkSHA3_384_WithBuffer(b *testing.B) {
	hasher := NewHasher(SHA3_384)
	reuseBuff := make([]byte, 0, 48)
	var err error
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		reuseBuff = reuseBuff[:0]
		reuseBuff, err = hasher.HashBuffer([]byte(msg), reuseBuff)
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if hex.EncodeToString(reuseBuff) != sha3_384Expect {
			b.Error("err")
		}
	}
}

func BenchmarkSHA3_512(b *testing.B) {
	hasher := NewHasher(SHA3_512)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		hash, err := hasher.Hash([]byte(msg))
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if hex.EncodeToString(hash) != sha3_512Expect {
			b.Error("err")
		}
	}
}

func BenchmarkSHA3_512_WithBuffer(b *testing.B) {
	hasher := NewHasher(SHA3_512)
	reuseBuff := make([]byte, 0, 64)
	var err error
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		reuseBuff = reuseBuff[:0]
		reuseBuff, err = hasher.HashBuffer([]byte(msg), reuseBuff)
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if hex.EncodeToString(reuseBuff) != sha3_512Expect {
			b.Error("err")
		}
	}
}

func BenchmarkKeccak256Batch(b *testing.B) {
	hasher := NewHasher(SHA3_512)
	slice := bytes.Split([]byte(msg), []byte{'e'})
	for i := range slice {
		if i == len(slice)-1 {
			continue
		}
		slice[i] = append(slice[i], 'e')
	}
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		hash, err := hasher.BatchHash(slice)
		b.StopTimer()
		if err != nil {
			b.Error(err)
		}
		if hex.EncodeToString(hash) != sha3_512Expect {
			b.Error("err")
		}
	}
}
