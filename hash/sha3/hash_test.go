package sha3

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

const msg = `Qulian Technology is an international leading blockchain team with all core team members graduated from Zhejiang University, Tsinghua University and other first-class universities at home and abroad, and Academician Chen Chun of the Chinese Academy of Engineering acted as chairman of the board. The company has a team of nearly 200 people, 90% of whom are technicians, more than 10 have doctoral degrees and 140 have master's degrees. The core competitiveness of the company is Hyperchain bottom technology platform. This platform ranks first in the technical evaluation of several large and medium-sized financial institutions. It is also the first batch of bottom platforms to pass the Blockchain Standard Test of the China Electronics Standardization Institute (CESI) and China Academy of Information and Communications Technology (CAICT) of Ministry of Industry and Information Technology (MIIT). It has applied for 28 patents in blockchain related fields.`

const (
	//nolint
	sha1Expect = `8fe056433a6b4bd1bc92f97c53e8afe559ce271c`
	//nolint
	sha2_256Expect = `f264c3d7afbbc5ac58abcd2d0f1d433f223b168ba30a755ec8c8b0040097d603`
	//nolint
	sha2_512Expect  = `b171bf6461560531fa924e162f98114acf39c8837d573e6692101aedda056e86285736b6523565ef2e4e85a2d92fd84f4a8b4f4084665c8d5d80f3c2510f86fe`
	keccak224Expect = `ebd8dc9c5cdcfaaaf20196660039e04e2827c700a2862b2a698fb9c3`
	keccak256Expect = `69127f35538a7e09c01123d0554a35641691b66d0ef0556d2abd6c99b074473f`
	keccak384Expect = `31d5734b848480961b17a71f3a91c96b62c733584fe23f0a8919ab88cea4bfbd50822e515409973789e0e46d4eee3bb2`
	keccak512Expect = `b8ca5ff5564c7e8645a966b9ef39ca782733c828fdc4c7ec31bd363076809c2f8200480becd86158b80260833b4ab35bebdb11b389c7ff50bdeb3b7c29b36954`
	sha3_224Expect  = `dad478f0edd59dabb434b2846d8f0974c2def3e62835a263d17c2800`
	sha3_256Expect  = `e9f40250a1b7f98e5f8680d010e3d4f418dabc27ed11c51fe263d0792d31b578`
	sha3_384Expect  = `4312cf057f8c923d51826f269f685a55c4a41599a5de05da83d3a617de595c7bf66fc07e0f524fd19726e813be657b6b`
	sha3_512Expect  = `5cd0efa722dc1d624e62ce49ad17ab7d8dcea2cefd947bea8ef278fad01a1b97a722737275a79fe6b89164cc8433128c8124d37cac7842627cb08442dd28bd93`
)

func TestKeccak224(t *testing.T) {
	hasher := NewKeccak224()
	_, _ = hasher.Write([]byte(msg))
	hash := hasher.Sum(nil)
	hashHex := hex.EncodeToString(hash)
	assert.Equal(t, keccak224Expect, hashHex)
}

func TestKeccak256(t *testing.T) {
	hasher := NewKeccak256()
	_, _ = hasher.Write([]byte(msg))
	hash := hasher.Sum(nil)
	hashHex := hex.EncodeToString(hash)
	assert.Equal(t, keccak256Expect, hashHex)
}

func TestKeccak384(t *testing.T) {
	hasher := NewKeccak384()
	_, _ = hasher.Write([]byte(msg))
	hash := hasher.Sum(nil)
	hashHex := hex.EncodeToString(hash)
	assert.Equal(t, keccak384Expect, hashHex)
}

func TestKeccak512(t *testing.T) {
	hasher := NewKeccak512()
	_, _ = hasher.Write([]byte(msg))
	hash := hasher.Sum(nil)
	hashHex := hex.EncodeToString(hash)
	assert.Equal(t, keccak512Expect, hashHex)
}

func TestSHA3_224(t *testing.T) {
	hasher := New224()
	_, _ = hasher.Write([]byte(msg))
	hash := hasher.Sum(nil)
	hashHex := hex.EncodeToString(hash)
	assert.Equal(t, sha3_224Expect, hashHex)
}

func TestSHA3_256(t *testing.T) {
	hasher := New256()
	_, _ = hasher.Write([]byte(msg))
	hash := hasher.Sum(nil)
	hashHex := hex.EncodeToString(hash)
	assert.Equal(t, sha3_256Expect, hashHex)
}

func TestSHA3_384(t *testing.T) {
	hasher := New384()
	_, _ = hasher.Write([]byte(msg))
	hash := hasher.Sum(nil)
	hashHex := hex.EncodeToString(hash)
	assert.Equal(t, sha3_384Expect, hashHex)
}

func TestSHA3_512(t *testing.T) {
	hasher := New512()
	_, _ = hasher.Write([]byte(msg))
	hash := hasher.Sum(nil)
	hashHex := hex.EncodeToString(hash)
	assert.Equal(t, sha3_512Expect, hashHex)
}
