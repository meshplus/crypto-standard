package hash

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	sha3Hash "github.com/meshplus/crypto-standard/hash/sha3"
	"hash"
)

//Hasher thw return value of function NewHasher
type Hasher struct {
	inner hash.Hash
	dirty bool
}

//NewHasher instruct a Hasher, the incoming parameter is the algorithm type.
func NewHasher(hashType HashType) *Hasher {
	switch hashType {
	case SHA1:
		return &Hasher{inner: sha1.New()}
	case SHA2_256:
		return &Hasher{inner: sha256.New()}
	case SHA2_512:
		return &Hasher{inner: sha512.New()}
	case SHA3_224:
		return &Hasher{inner: sha3Hash.New224()}
	case SHA3_256:
		return &Hasher{inner: sha3Hash.New256()}
	case SHA3_384:
		return &Hasher{inner: sha3Hash.New384()}
	case SHA3:
		return &Hasher{inner: sha3Hash.New512()}
	case KECCAK_224:
		return &Hasher{inner: sha3Hash.NewKeccak224()}
	case KECCAK_384:
		return &Hasher{inner: sha3Hash.NewKeccak384()}
	case KECCAK_512:
		return &Hasher{inner: sha3Hash.NewKeccak512()}
	case KECCAK_256:
		return &Hasher{inner: sha3Hash.NewKeccak256()}
	default:
		return nil
	}
}

//Hash compute hash
func (h *Hasher) Hash(msg []byte) (hash []byte, err error) {
	h.cleanIfDirty()
	h.dirty = true
	if _, err := h.inner.Write(msg); err != nil {
		return nil, err
	}
	return h.inner.Sum(nil), nil
}

// HashBuffer is identical to Hash except that it stages through the
// provided buffer (if one is required) rather than allocating a
// temporary one. If buf is nil or has un-expected size, one fix-sized
// bytes will be allocated.
func (h *Hasher) HashBuffer(msg []byte, buf []byte) (hash []byte, err error) {
	h.cleanIfDirty()
	h.dirty = true
	if _, err := h.inner.Write(msg); err != nil {
		return nil, err
	}
	return h.inner.Sum(buf), nil
}

//BatchHash hash with two-dimensional array
func (h *Hasher) BatchHash(msg [][]byte) (hash []byte, err error) {
	h.cleanIfDirty()
	h.dirty = true
	for i := range msg {
		_, err := h.inner.Write(msg[i])
		if err != nil {
			return nil, err
		}
	}
	return h.inner.Sum(nil), nil
}

func (h *Hasher) cleanIfDirty() {
	if h.dirty {
		h.inner.Reset()
	}
}
