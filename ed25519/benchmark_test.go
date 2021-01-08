package ed25519

import (
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

// Generate n individual signatures with standard Ed25519 signing,
// for comparison.
func genInd(tb testing.TB, n int) [][]byte {
	genKeys(n)
	sigs := make([][]byte, n)
	for i := range sigs {
		sigs[i], _ = priKeys[i].Sign(rand.Reader, rightMessage, nil)
	}
	return sigs
}

func benchSign(b *testing.B, nsigners int) {
	genKeys(nsigners)                              // make sure we have enough keypairs
	leader := NewEd25519Leader(pubKeys[:nsigners]) // all enabled by default
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testCosign(b, rightMessage, priKeys[:nsigners], leader)
	}
}

func benchSignInd(b *testing.B, nsigners int) {
	genKeys(nsigners)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		genInd(b, nsigners)
	}
}

func benchVerifyCached(b *testing.B, nsigners int) {
	genKeys(nsigners)                              // make sure we have enough keypairs
	leader := NewEd25519Leader(pubKeys[:nsigners]) // all enabled
	sig := testCosign(b, rightMessage, priKeys[:nsigners], leader)
	b.ResetTimer()
	fool := NewEd25519Witness(priKeys[0])
	for i := 0; i < b.N; i++ {
		if !fool.AggVerify(uint(nsigners), rightMessage, sig, leader.GetAggPublicKey()) {
			b.Errorf("%d-signer signature rejected", nsigners)
		}
	}
}

func benchVerifyWorst(b *testing.B, nsigners int) {
	genKeys(nsigners)                              // make sure we have enough keypairs
	leader := NewEd25519Leader(pubKeys[:nsigners]) // all enabled
	sig := testCosign(b, rightMessage, priKeys[:nsigners], leader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		leader := NewEd25519Leader(pubKeys[:nsigners])
		witness := NewEd25519Witness(nil)
		if !witness.AggVerify(uint(nsigners), rightMessage, sig, leader.GetAggPublicKey()) {
			b.Errorf("%d-signer signature rejected", nsigners)
		}
	}
}

func benchVerifyInd(b *testing.B, nsigners int) {
	sigs := genInd(b, nsigners)
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		for j := range sigs {
			if bo, _ := pubKeys[j].Verify(nil, sigs[j], rightMessage); !bo {
				b.Errorf("signer %d's signature rejected", j)
			}
		}
	}
}

// Signing benchmarks

func BenchmarkSign1Collective(b *testing.B) {
	benchSign(b, 1)
}

func BenchmarkSign1Individual(b *testing.B) {
	benchSignInd(b, 1)
}

func BenchmarkSign10Collective(b *testing.B) {
	benchSign(b, 10)
}

func BenchmarkSign10Individual(b *testing.B) {
	benchSignInd(b, 10)
}

func BenchmarkSign100Collective(b *testing.B) {
	benchSign(b, 100)
}

func BenchmarkSign100Individual(b *testing.B) {
	benchSignInd(b, 100)
}

func BenchmarkSign1000Collective(b *testing.B) {
	benchSign(b, 1000)
}

func BenchmarkSign1000Individual(b *testing.B) {
	benchSignInd(b, 1000)
}

// Verification benchmarks

func BenchmarkVerify1CollectiveCache(b *testing.B) {
	benchVerifyCached(b, 1)
}

func BenchmarkVerify1CollectiveWorst(b *testing.B) {
	benchVerifyWorst(b, 1)
}

func BenchmarkVerify1Individual(b *testing.B) {
	benchVerifyInd(b, 1)
}

func BenchmarkVerify10CollectiveCache(b *testing.B) {
	benchVerifyCached(b, 10)
}

func BenchmarkVerify10CollectiveWorst(b *testing.B) {
	benchVerifyWorst(b, 10)
}

func BenchmarkVerify10Individual(b *testing.B) {
	benchVerifyInd(b, 10)
}

func BenchmarkVerify100CollectiveCache(b *testing.B) {
	benchVerifyCached(b, 100)
}

func BenchmarkVerify100CollectiveWorst(b *testing.B) {
	benchVerifyWorst(b, 100)
}

func BenchmarkVerify100Individual(b *testing.B) {
	benchVerifyInd(b, 100)
}

func BenchmarkVerify1000CollectiveCache(b *testing.B) {
	benchVerifyCached(b, 1000)
}

func BenchmarkVerify1000CollectiveWorst(b *testing.B) {
	benchVerifyWorst(b, 1000)
}

func BenchmarkVerify1000Individual(b *testing.B) {
	benchVerifyInd(b, 1000)
}

func BenchmarkBatchVerify(b *testing.B) {
	var vk, pk, msg, s [][]byte
	var size = 20
	vk, pk, msg, s = make([][]byte, size), make([][]byte, size), make([][]byte, size), make([][]byte, size)

	for bat := 0; bat < b.N; bat++ {
		for i := 0; i < size; i++ {
			vktmp, pktmp := GenerateKey(rand.Reader)
			vk[i], pk[i] = vktmp[:], pktmp[:]
			buf := make([]byte, 64)
			_, _ = rand.Read(buf)
			msg[i] = buf
			s[i], _ = vktmp.Sign(nil, msg[i], nil)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, _ := new(EDDSAPublicKey).BatchVerify(pk, s, msg)
		assert.True(b, result)
	} //696147 -> 599354
}
