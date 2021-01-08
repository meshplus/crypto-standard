package ed25519

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHeap(t *testing.T) {
	heap := GetHeap()
	heap.Size = 9
	for i := range heap.Heap {
		heap.Heap[i] = heapIndex(i)
	}
	BatchTestHeap(heap, 3)
	for i := range heap.Heap {
		assert.True(t, heap.Heap[i] == 233)
	}
	CloseHeap(heap)
}

func TestHeap_2(t *testing.T) {
	heap := GetHeap()
	CloseHeap(heap)
	heap.Size = 9
	for i := range heap.Heap {
		heap.Heap[i] = heapIndex(i)
	}
	BatchTestHeap(heap, 3)
	for i := range heap.Heap {
		assert.True(t, heap.Heap[i] == 233)
	}
	GetHeap()
	for i := range heap.Heap {
		assert.True(t, heap.Heap[i] == 233)
	}
	CloseHeap(heap)
}

func BenchmarkStep1(b *testing.B) {
	/*	go test -c -o BenchmarkStep1.test
		./BenchmarkStep1.test -test.bench BenchmarkStep1 -test.run XXX -test.cpuprofile=BenchmarkStep1.cpu
		go tool pprof BenchmarkStep1.test BenchmarkStep1.cpu
		rm ./BenchmarkStep1.cpu rm ./BenchmarkStep1.test
	*/
	var vk, pk, msg, s [][]byte
	var size = 20
	vk, pk, msg, s = make([][]byte, size), make([][]byte, size), make([][]byte, size), make([][]byte, size)
	for i := 0; i < size; i++ {
		vktmp, pktmp := GenerateKey(rand.Reader)
		vk[i], pk[i] = vktmp[:], pktmp[:]
		buf := make([]byte, 64)
		_, _ = rand.Read(buf)
		msg[i] = buf
		s[i], _ = vktmp.Sign(nil, msg[i], nil)
	}

	heaps := make([]*BatchHeapGo, b.N)
	for i := 0; i < b.N; i++ {
		heaps[i] = GetHeap()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !BatchVerifyInit(heaps[i], pk, s, msg) {
			panic(false)
		}
	}
}

func BenchmarkStep2(b *testing.B) {
	var vk, pk, msg, s [][]byte
	var size = 20
	vk, pk, msg, s = make([][]byte, size), make([][]byte, size), make([][]byte, size), make([][]byte, size)
	for i := 0; i < size; i++ {
		vktmp, pktmp := GenerateKey(rand.Reader)
		vk[i], pk[i] = vktmp[:], pktmp[:]
		buf := make([]byte, 64)
		_, _ = rand.Read(buf)
		msg[i] = buf
		s[i], _ = vktmp.Sign(nil, msg[i], nil)
	}

	heaps := make([]*BatchHeapGo, b.N)
	for i := 0; i < b.N; i++ {
		heaps[i] = GetHeap()
		BatchVerifyInit(heaps[i], pk, s, msg)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := BatchVerifyEnd(heaps[i], len(msg))
		if !result {
			panic(b)
		}
	}
}
func TestBatchVerifyStep(t *testing.T) {
	var vk, pk, msg, s [][]byte
	var size = 20
	vk, pk, msg, s = make([][]byte, size), make([][]byte, size), make([][]byte, size), make([][]byte, size)

	for bat := 0; bat < 10000; bat++ {
		for i := 0; i < size; i++ {
			vktmp, pktmp := GenerateKey(rand.Reader)
			vk[i], pk[i] = vktmp[:], pktmp[:]
			buf := make([]byte, 64)
			_, _ = rand.Read(buf)
			msg[i] = buf
			s[i], _ = vktmp.Sign(nil, msg[i], nil)
		}

		heap := GetHeap()
		assert.True(t, BatchVerifyInit(heap, pk, s, msg))
		assert.True(t, BatchVerifyEnd(heap, size))
		CloseHeap(heap)
	}

	for bat := 0; bat < 10000; bat++ {
		for i := 0; i < size; i++ {
			vktmp, pktmp := GenerateKey(rand.Reader)
			vk[i], pk[i] = vktmp[:], pktmp[:]
			buf := make([]byte, 64)
			_, _ = rand.Read(buf)
			msg[i] = buf
			s[i], _ = vktmp.Sign(nil, msg[i], nil)
		}
		s[3][20], s[13][20] = 0, 0
		msg[3][2], msg[13][23] = 222, 133
		heap := GetHeap()
		r := BatchVerifyInit(heap, pk, s, msg) && BatchVerifyEnd(heap, size)
		assert.False(t, r)
		CloseHeap(heap)
	}
}

func TestBatchVerify(t *testing.T) {
	var vk, pk, msg, s [][]byte
	var size = 20
	vk, pk, msg, s = make([][]byte, size), make([][]byte, size), make([][]byte, size), make([][]byte, size)

	for bat := 0; bat < 10000; bat++ {
		for i := 0; i < size; i++ {
			vktmp, pktmp := GenerateKey(rand.Reader)
			vk[i], pk[i] = vktmp[:], pktmp[:]
			buf := make([]byte, 64)
			_, _ = rand.Read(buf)
			msg[i] = buf
			s[i], _ = vktmp.Sign(nil, msg[i], nil)
		}
		b, err := new(EDDSAPublicKey).BatchVerify(pk, s, msg)
		assert.Nil(t, err)
		assert.True(t, b)
	}
}
