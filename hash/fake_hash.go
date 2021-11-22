package hash

import (
	"bytes"
)

//FakeHasher thw return value of function FakeHasher
type FakeHasher struct {
	e     *bytes.Buffer
	dirty bool
}

//GetFakeHasher get hasher
func GetFakeHasher() *FakeHasher {
	return &FakeHasher{
		e:     bytes.NewBuffer(nil),
		dirty: false,
	}
}

//Write write data
func (f *FakeHasher) Write(p []byte) (n int, err error) {
	return f.e.Write(p)
}

//Sum hash sum
func (f *FakeHasher) Sum(b []byte) []byte {
	return f.e.Bytes()
}

//Reset reset state
func (f *FakeHasher) Reset() {
	f.e.Reset()
}

//Size size
func (f *FakeHasher) Size() int {
	return f.e.Len()
}

//BlockSize hash block size
func (f *FakeHasher) BlockSize() int {
	return f.e.Len()
}

//Hash compute hash
func (f *FakeHasher) Hash(msg []byte) (hash []byte, err error) {
	f.Reset()
	_, _ = f.Write(msg)
	return f.Sum(nil), nil
}

//BatchHash hash with two-dimensional array
func (f *FakeHasher) BatchHash(msg [][]byte) (hash []byte, err error) {
	f.Reset()
	for i := range msg {
		_, _ = f.Write(msg[i])
	}
	return f.Sum(nil), nil
}
