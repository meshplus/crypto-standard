package internal

/*
#include "ed25519-donna.h"
#include "ed25519.h"
#include <stdint.h>

*/
import "C"
import (
	"github.com/meshplus/crypto-standard/ed25519/asm"
	"unsafe"
)

const heapBatchSize = C.heap_batch_size

//Ge25519 for c type Ge25519
type Ge25519 struct {
	//nolint: structcheck
	x, y, z, t Bignum256
}

//BatchHeapGo for c type BatchHeapGo
type BatchHeapGo struct {
	Size    uint64
	Heap    [heapBatchSize]uint64
	Scalars [heapBatchSize]Bignum256
	Points  [heapBatchSize]Ge25519
	//R       [heapBatchSize * 16]byte /* 128 bit random values */
}

//BatchVerifyInit BatchVerify Init
func BatchVerifyInit(ctx *BatchHeapGo, publicKey, signature, msg [][]byte) bool {
	l := len(msg)
	l2 := l << 1
	lens := make([]int32, l)
	for i := range msg {
		lens[i] = int32(len(msg[i]))
	}

	array2D := make([]uint64, l+l2)
	pArray, sArray, mArray := array2D[:l], array2D[l:l2], array2D[l2:]
	asm.Get2DArray(pArray, publicKey)
	asm.Get2DArray(sArray, signature)
	asm.Get2DArray(mArray, msg)
	return C.ed25519_sign_open_batch_pre((*C.batch_heap)(unsafe.Pointer(ctx)),
		(**C.uchar)(unsafe.Pointer(&mArray[0])), (*C.uint32_t)(unsafe.Pointer(&lens[0])),
		(**C.uchar)(unsafe.Pointer(&pArray[0])),
		(**C.uchar)(unsafe.Pointer(&sArray[0])),
		C.size_t(len(msg))) == 0
}

//BatchVerifyEnd BatchVerifyEnd
func BatchVerifyEnd(ctx *BatchHeapGo, length int) bool {
	return C.ed25519_sign_open_batch_end((*C.batch_heap)(unsafe.Pointer(ctx)), C.size_t(length)) == 0
}

//BatchTestHeap BatchTestHeap
func BatchTestHeap(ctx *BatchHeapGo, length int) bool {
	return C.ed25519_test_heap((*C.batch_heap)(unsafe.Pointer(ctx)), C.size_t(length)) == 0
}
