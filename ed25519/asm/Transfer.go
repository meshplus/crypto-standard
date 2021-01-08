package asm

import "unsafe"

//Get2DArray get 2d array
func Get2DArray(out []uint64, in [][]byte) {
	for i := range in {
		out[i] = *(*uint64)(unsafe.Pointer(&in[i]))
	}
}
