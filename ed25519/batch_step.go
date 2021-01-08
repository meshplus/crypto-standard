package ed25519

import (
	"sync"
)

var batchHeapGoPool = &sync.Pool{
	New: func() interface{} {
		return &BatchHeapGo{}
	},
}

//GetHeap get Heap
func GetHeap() *BatchHeapGo {
	heap := batchHeapGoPool.Get().(*BatchHeapGo)
	return heap
}

//CloseHeap close Heap
func CloseHeap(in *BatchHeapGo) {
	batchHeapGoPool.Put(in)
}

//BatchVerifyInit BatchVerify Init
func BatchVerifyInit(ctx *BatchHeapGo, publicKey, signature, msg [][]byte) bool {
	return batchVerifyInit(ctx, publicKey, signature, msg)
}

//BatchVerifyEnd BatchVerify End
func BatchVerifyEnd(ctx *BatchHeapGo, length int) bool {
	return batchVerifyEnd(ctx, length)
}

//BatchVerify  return batch verify init and batch verify end
func BatchVerify(publicKey, signature, msg [][]byte) bool {
	ctx := GetHeap()
	defer CloseHeap(ctx)
	return batchVerifyInit(ctx, publicKey, signature, msg) && batchVerifyEnd((*BatchHeapGo)(ctx), len(msg))
}

//BatchTestHeap BatchTestHeap End
func BatchTestHeap(ctx *BatchHeapGo, length int) {
	batchTestHeap(ctx, length)
}
