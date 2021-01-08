package internal

//小端表示：
// H       L
// _ _ _ _ _
// 7 7 7 7 4    7+7+7+7+4 = 32

//Polynomial2LE Polynomial2LE
func Polynomial2LE(out []byte, in *Bignum256) {
	U64to8LE(out[:8], (in[0])|(in[1]<<56))
	U64to8LE(out[8:16], (in[1]>>8)|(in[2]<<48))
	U64to8LE(out[16:24], (in[2]>>16)|(in[3]<<40))
	U64to8LE(out[24:32], (in[3]>>24)|(in[4]<<32))
}

//U64to8LE U64 to 8LE
func U64to8LE(p []byte, v uint64) {
	p[0] = (byte)(v)
	p[1] = (byte)(v >> 8)
	p[2] = (byte)(v >> 16)
	p[3] = (byte)(v >> 24)
	p[4] = (byte)(v >> 32)
	p[5] = (byte)(v >> 40)
	p[6] = (byte)(v >> 48)
	p[7] = (byte)(v >> 56)
}

//U8to64LE U8to64LE
func U8to64LE(p []byte) uint64 {
	return ((uint64)(p[0])) |
		((uint64)(p[1]) << 8) |
		((uint64)(p[2]) << 16) |
		((uint64)(p[3]) << 24) |
		((uint64)(p[4]) << 32) |
		((uint64)(p[5]) << 40) |
		((uint64)(p[6]) << 48) |
		((uint64)(p[7]) << 56)
}

//LE2Polynomial LE2Polynomial
func LE2Polynomial(out *Bignum256, in *[32]byte) {
	var x [4]uint64

	x[0] = U8to64LE(in[0:8])
	x[1] = U8to64LE(in[8:16])
	x[2] = U8to64LE(in[16:24])
	x[3] = U8to64LE(in[24:32])

	out[0] = (x[0]) & 0xffffffffffffff
	out[1] = ((x[0] >> 56) | (x[1] << 8)) & 0xffffffffffffff
	out[2] = ((x[1] >> 48) | (x[2] << 16)) & 0xffffffffffffff
	out[3] = ((x[2] >> 40) | (x[3] << 24)) & 0xffffffffffffff
	out[4] = (x[3] >> 32) & 0x000000ffffffff
}

//look at ExampleComputedL
var l = [5]uint64{0x10, 0x0, 0xa2def9de140000, 0x1a631258d69cf7, 0xedd3f55c}

//nolint: deadcode
func biggerThanL(in *Bignum256) bool {
	if (in[0]-l[0])>>63 == 0x00 {
		return true
	}
	if (in[1]-l[1])>>63 == 0x00 {
		return true
	}
	if (in[2]-l[2])>>63 == 0x00 {
		return true
	}
	if (in[3]-l[3])>>63 == 0x00 {
		return true
	}
	if (in[4]-l[4])>>63 == 0x00 {
		return true
	}
	return false
}

//Bignum256 in amd64
type Bignum256 [5]uint64
