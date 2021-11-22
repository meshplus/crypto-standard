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
	ht, size := hashType&0xf0, hashType&0x0f
	switch ht {
	case SHA1:
		return &Hasher{inner: sha1.New()}
	case SHA2:
		switch size {
		case Size224:
			return &Hasher{inner: sha256.New224()}
		case Size256:
			return &Hasher{inner: sha256.New()}
		case Size384:
			return &Hasher{inner: sha512.New384()}
		case Size512:
			return &Hasher{inner: sha512.New()}
		default:
			return nil
		}
	case SHA3:
		switch size {
		case Size224:
			return &Hasher{inner: sha3Hash.New224()}
		case Size256:
			return &Hasher{inner: sha3Hash.New256()}
		case Size384:
			return &Hasher{inner: sha3Hash.New384()}
		case Size512:
			return &Hasher{inner: sha3Hash.New512()}
		default:
			return nil
		}
	case KECCAK:
		switch size {
		case Size224:
			return &Hasher{inner: sha3Hash.NewKeccak224()}
		case Size256:
			return &Hasher{inner: sha3Hash.NewKeccak256()}
		case Size384:
			return &Hasher{inner: sha3Hash.NewKeccak384()}
		case Size512:
			return &Hasher{inner: sha3Hash.NewKeccak512()}
		default:
			return nil
		}
	default:
		return nil
	}
}

//Write write data
func (h *Hasher) Write(p []byte) (n int, err error) {
	return h.inner.Write(p)
}

//Sum get sum
func (h *Hasher) Sum(b []byte) []byte {
	return h.inner.Sum(b)
}

//Reset  reset state
func (h *Hasher) Reset() {
	h.inner.Reset()
}

//Size hash size
func (h *Hasher) Size() int {
	return h.inner.Size()
}

//BlockSize hash block size
func (h *Hasher) BlockSize() int {
	return h.inner.BlockSize()
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
