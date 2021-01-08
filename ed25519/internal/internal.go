//+build amd64

package internal

/*
#cgo CFLAGS: -I.  -O4 -w

#cgo amd64 CFLAGS: -m64

#include "ed25519-donna.h"
#include "ed25519.h"
#include <string.h>
#include <stdio.h>

#define OUT
//unsigned char * getMsgFromGroup(unsigned char * addr, OUT unsigned char **msg, OUT unsigned long *len, int batch_num){
//	int i = 0;
//	//int j = 0;
//	unsigned char *ptr = addr;
//	for(i = 0;i<batch_num;i++){
//		//printf("%02x,%02x,%02x,%02x\n",ptr[0],ptr[1],ptr[2],ptr[3]);
//		len[i] = *((int *)(ptr));
//		msg[i] = ptr + 4;
//		ptr += 4 + len[i];
//		//printf("%d\n",len[i]);
//		//for(j = 0;j< len[i];j++){
//		//  printf("%c",msg[i][j]);
//		//}
//		//printf("\n");
//	}
//}
//
//void getPKAndSign(unsigned char *pkGroup,unsigned char *signGroup,
//	OUT unsigned char **pk ,OUT unsigned char **sign, int batch_num){
//	int i,j;
//	for (i=0;i<batch_num;i++){
//		*(pk + i) = pkGroup + 32 * i;
//		*(sign + i) = signGroup + 64 * i;
//		//if(i == 23){
//		//printf("%d\n",i);
//		//for(j = 0;j< 32;j++){
//		//   printf("%02x",*(*(pk + i)+j));
//		//}
//		//printf("\n");
//		//}
//	}
//}
//
//int batch_verify(unsigned char * msgGroup, unsigned char * pkGroup,unsigned char * signGroup, int batch_num){
//	unsigned char **msg = malloc(batch_num * sizeof(unsigned char *));
//	unsigned char *lens = malloc(batch_num * sizeof(long));
//	unsigned char **pk = malloc(batch_num * sizeof(unsigned char*));
//	unsigned char **sign = malloc(batch_num * sizeof(unsigned char*));
//	//unsigned char *msg[64];
//	//unsigned long lens[64];
//	//unsigned char *pk[64];
//	//unsigned char *sign[64];
//	getMsgFromGroup(msgGroup, msg, lens, batch_num);
//	getPKAndSign(pkGroup, signGroup, pk, sign, batch_num);
//	int allValid = ed25519_sign_open_batch( msg, lens, pk, sign, batch_num);
//	free(msg);
//	free(lens);
//	free(pk);
//	free(sign);
//	return allValid;
//}
//
//int batch_verify_same_msg(unsigned char * msg, size_t len ,unsigned char * pkGroup,unsigned char * signGroup, int batch_num){
//	unsigned char **pk = malloc(batch_num * sizeof(unsigned char*));
//	unsigned char **sign = malloc(batch_num * sizeof(unsigned char*));
//
//	getPKAndSign(pkGroup, signGroup, pk, sign, batch_num);
//	int allValid = ed25519_sign_open_batch_same_msg( msg, len, pk, sign, batch_num);
//	free(pk);
//	free(sign);
//	return allValid;
//}

DONNA_INLINE static void
curve25519_reduce(bignum25519 out, const bignum25519 a) {
	uint64_t c;
	out[0] = a[0]     ; c = (out[0] >> 51); out[0] &= reduce_mask_51;
	out[1] = a[1]  + c; c = (out[1] >> 51); out[1] &= reduce_mask_51;
	out[2] = a[2]  + c; c = (out[2] >> 51); out[2] &= reduce_mask_51;
	out[3] = a[3]  + c; c = (out[3] >> 51); out[3] &= reduce_mask_51;
	out[4] = a[4]  + c; c = (out[4] >> 51); out[4] &= reduce_mask_51;
	out[0] += c * 19;
}

static void
ge25519_neg(ge25519 *r, const ge25519 *p) {
	curve25519_copy(r->x,p->x);
	curve25519_copy(r->z,p->z);
    curve25519_neg(r->y, p->y);
    curve25519_neg(r->t, p->t);
}

*/
import "C"
import (
	"io"
	"unsafe"
)

//var scOne = [5]uint64{1, 0, 0, 0, 0}

//GenerateEd25519Key GenerateEd25519Key
func GenerateEd25519Key(reader io.Reader) (vk *[64]byte) {
	vk = new([64]byte)
	_, _ = reader.Read(vk[:])
	C.ed25519_publickey(
		(*C.uchar)(unsafe.Pointer(&vk[0])),
		(*C.uchar)(unsafe.Pointer(&vk[32])))
	return vk
}

// Ed25519Sign Ed25519Sign
func Ed25519Sign(digest, vk, pk []byte) []byte {
	sign := make([]byte, 64)
	msg := (*C.uchar)(C.NULL)
	if len(digest) > 0 {
		msg = (*C.uchar)(unsafe.Pointer(&digest[0]))
	}
	C.ed25519_sign(
		msg,
		C.ulong(len(digest)),
		(*C.uchar)(unsafe.Pointer(&vk[0])),
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&sign[0])))
	return sign
}

// Ed25519Verify Ed25519Verify
func Ed25519Verify(digest, pk, signature []byte) bool {
	msg := (*C.uchar)(C.NULL)
	if len(digest) > 0 {
		msg = (*C.uchar)(unsafe.Pointer(&digest[0]))
	}
	r := C.ed25519_sign_open(
		msg,
		C.ulong(len(digest)),
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&signature[0])))
	return int32(r) == 0
}

// Ed25519BatchVerifySameMsg Ed25519BatchVerifySameMsg
//func Ed25519BatchVerifySameMsg(msg, pkGroup, signGroup []byte, batchNum int) bool {
//	c := C.batch_verify_same_msg(
//		(*C.uchar)(unsafe.Pointer(&msg[0])),
//		(C.size_t)(len(msg)),
//		(*C.uchar)(unsafe.Pointer(&pkGroup[0])),
//		(*C.uchar)(unsafe.Pointer(&signGroup[0])),
//		(C.int)(batchNum))
//	return int(c) == 0
//}

/*======================================================================================================================
 */

//ExtendedGroupElement 4 * 5 * 8 bytes
// 和internal包中的表示兼容
type ExtendedGroupElement struct {
	X, Y, Z, T Bignum256
}

//Add Add
func (ge *ExtendedGroupElement) Add(a, b *ExtendedGroupElement) {
	C.ge25519_add((*C.ge25519)(unsafe.Pointer(ge)),
		(*C.ge25519)(unsafe.Pointer(a)),
		(*C.ge25519)(unsafe.Pointer(b)))
}

var d2 = Bignum256{0x00069b9426b2f159, 0x00035050762add7a, 0x0003cf44c0038052, 0x0006738cc7407977, 0x0002406d9dc56dff}

//Sub Sub
func (ge *ExtendedGroupElement) Sub(a, b *ExtendedGroupElement) {
	var ryPlusX, ryMinusX, rZ, rT2d Bignum256
	var r ExtendedGroupElement
	var t0 Bignum256
	//1
	//var cache, r ExtendedGroupElement
	//var t0 [5]uint64
	//C.ge25519_full_to_pniels(
	//	(*C.ge25519_pniels)(unsafe.Pointer(&cache)),
	//	(*C.ge25519)(unsafe.Pointer(b)))
	CurveAdd(&ryPlusX, &b.Y, &b.X)

	CurveSub(&ryMinusX, &b.Y, &b.X)
	rZ = b.Z
	CurveMul(&rT2d, &b.T, &d2)
	//
	//fmt.Println("ryPlusX",big2String(&ryPlusX))
	//fmt.Println("ryMinusX",big2String(&ryMinusX))
	//fmt.Println("rZ",big2String(&rZ))
	//fmt.Println("rT2d",big2String(&rT2d))
	////2

	CurveAdd(&r.X, &a.Y, &a.X)

	CurveSub(&r.Y, &a.Y, &a.X)

	CurveMul(&r.Z, &r.X, &ryMinusX) //ScMul(&r.Z, &r.X, &q.yPlusX)

	CurveMul(&r.Y, &r.Y, &ryPlusX) //ScMul(&r.Y, &r.Y, &q.yMinusX)

	CurveMul(&r.T, &rT2d, &a.T)
	CurveMul(&r.X, &a.Z, &rZ)

	CurveAdd(&t0, &r.X, &r.X)
	CurveSub(&r.X, &r.Z, &r.Y)
	CurveAdd(&r.Y, &r.Z, &r.Y)
	CurveSub(&r.Z, &t0, &r.T) //ScAdd(&r.Z, &t0, &r.T)
	CurveAdd(&r.T, &t0, &r.T) //ScSub(&r.T, &t0, &r.T)
	//3

	CurveMul(&ge.X, &r.X, &r.T)

	CurveMul(&ge.Y, &r.Y, &r.Z)

	CurveMul(&ge.Z, &r.Z, &r.T)

	CurveMul(&ge.T, &r.X, &r.Y)

}

//FromBytes FromBytes
func (ge *ExtendedGroupElement) FromBytes(s *[32]byte) bool {
	C.ge25519_unpack_vartime((*C.ge25519)(unsafe.Pointer(ge)), (*C.uchar)(unsafe.Pointer(&s[0])), 0)
	return true
}

//ToBytes ToBytes
func (ge *ExtendedGroupElement) ToBytes(s *[32]byte) {
	C.ge25519_pack((*C.uchar)(unsafe.Pointer(&s[0])), (*C.ge25519)(unsafe.Pointer(ge)))
}

//Zero to zero
func (ge *ExtendedGroupElement) Zero() {
	ge.X[0] = 0
	ge.X[1] = 0
	ge.X[2] = 0
	ge.X[3] = 0
	ge.X[4] = 0

	ge.T[0] = 0
	ge.T[1] = 0
	ge.T[2] = 0
	ge.T[3] = 0
	ge.T[4] = 0

	ge.Y[0] = 1
	ge.Y[1] = 0
	ge.Y[2] = 0
	ge.Y[3] = 0
	ge.Y[4] = 0

	ge.Z[0] = 1
	ge.Z[1] = 0
	ge.Z[2] = 0
	ge.Z[3] = 0
	ge.Z[4] = 0
}

//big num

// Input:
//   s[0]+256*s[1]+...+256^63*s[63] = s
//
// Output:
//   s[0]+256*s[1]+...+256^31*s[31] = s mod l
//   where l = 2^252 + 27742317777372353535851937790883648493.

// ScReduce function
func ScReduce(out *Bignum256, s []byte) {
	//C.expand256_modm((*C.uint64_t)(unsafe.Pointer(out)),
	//	(*C.uchar)(unsafe.Pointer(&s[0])),
	//	C.size_t(len(s)))
	//return
	var work [64]byte
	var x [16]uint64
	var q1 [5]uint64

	copy(work[:], s)
	x[0] = U8to64LE(work[:8])
	x[1] = U8to64LE(work[8:16])
	x[2] = U8to64LE(work[16:24])
	x[3] = U8to64LE(work[24:32])
	x[4] = U8to64LE(work[32:40])
	x[5] = U8to64LE(work[40:48])
	x[6] = U8to64LE(work[48:56])
	x[7] = U8to64LE(work[56:64])

	/* r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1) */ //只有后面256 + 8 位
	out[0] = (x[0]) & 0xffffffffffffff
	out[1] = ((x[0] >> 56) | (x[1] << 8)) & 0xffffffffffffff
	out[2] = ((x[1] >> 48) | (x[2] << 16)) & 0xffffffffffffff
	out[3] = ((x[2] >> 40) | (x[3] << 24)) & 0xffffffffffffff
	out[4] = ((x[3] >> 32) | (x[4] << 32)) & 0x0000ffffffffff

	/* under 252 bits, no need to reduce */
	if len(s) < 32 {
		return
	}

	/* q1 = x >> 248 = 264 bits */
	q1[0] = ((x[3] >> 56) | (x[4] << 8)) & 0xffffffffffffff
	q1[1] = ((x[4] >> 48) | (x[5] << 16)) & 0xffffffffffffff
	q1[2] = ((x[5] >> 40) | (x[6] << 24)) & 0xffffffffffffff
	q1[3] = ((x[6] >> 32) | (x[7] << 32)) & 0xffffffffffffff
	q1[4] = x[7] >> 24

	C.barrett_reduce256_modm(
		(*C.uint64_t)(unsafe.Pointer(out)),
		(*C.uint64_t)(unsafe.Pointer(&q1)),
		(*C.uint64_t)(unsafe.Pointer(out)))
}

// The scalars are GF(2^252 + 27742317777372353535851937790883648493).

// CurveMul function curve mul
// Input:
//   a[0]+256*a[1]+...+256^31*a[31] = a
//   b[0]+256*b[1]+...+256^31*b[31] = b
//   c[0]+256*c[1]+...+256^31*c[31] = c
//
// Output:
//   s[0]+256*s[1]+...+256^31*s[31] = (ab+c) mod l
//   where l = 2^252 + 27742317777372353535851937790883648493.
func CurveMul(s, a, b *Bignum256) { //bignum25519
	C.curve25519_mul((*C.uint64_t)(unsafe.Pointer(s)),
		(*C.uint64_t)(unsafe.Pointer(a)),
		(*C.uint64_t)(unsafe.Pointer(b)))
}

//ScMulAdd function
func ScMulAdd(s, a, b, c *Bignum256) {
	C.mul256_modm((*C.uint64_t)(unsafe.Pointer(s)),
		(*C.uint64_t)(unsafe.Pointer(a)),
		(*C.uint64_t)(unsafe.Pointer(b)))
	C.add256_modm((*C.uint64_t)(unsafe.Pointer(s)),
		(*C.uint64_t)(unsafe.Pointer(s)),
		(*C.uint64_t)(unsafe.Pointer(c)),
	)
}

//ScAdd function
func ScAdd(s, a, b *Bignum256) {
	C.add256_modm((*C.uint64_t)(unsafe.Pointer(s)),
		(*C.uint64_t)(unsafe.Pointer(a)),
		(*C.uint64_t)(unsafe.Pointer(b)),
	)
}

//CurveAdd function
func CurveAdd(out, a, b *Bignum256) {
	var c uint64
	out[0] = a[0] + b[0]
	c = out[0] >> 51
	out[0] &= reduceMask51
	out[1] = a[1] + b[1] + c
	c = out[1] >> 51
	out[1] &= reduceMask51
	out[2] = a[2] + b[2] + c
	c = out[2] >> 51
	out[2] &= reduceMask51
	out[3] = a[3] + b[3] + c
	c = out[3] >> 51
	out[3] &= reduceMask51
	out[4] = a[4] + b[4] + c
	c = out[4] >> 51
	out[4] &= reduceMask51
	out[0] += c * 19
}

const (
	twoP0        uint64 = 0x0fffffffffffda
	twoP1234     uint64 = 0x0ffffffffffffe
	fourP0       uint64 = 0x1fffffffffffb4
	fourP1234    uint64 = 0x1ffffffffffffc
	reduceMask51        = (uint64(1) << 51) - 1
)

//CurveSub function
func CurveSub(out, a, b *Bignum256) {
	var c uint64
	out[0] = a[0] + fourP0 - b[0]
	c = out[0] >> 51
	out[0] &= reduceMask51
	out[1] = a[1] + fourP1234 - b[1] + c
	c = out[1] >> 51
	out[1] &= reduceMask51
	out[2] = a[2] + fourP1234 - b[2] + c
	c = out[2] >> 51
	out[2] &= reduceMask51
	out[3] = a[3] + fourP1234 - b[3] + c
	c = out[3] >> 51
	out[3] &= reduceMask51
	out[4] = a[4] + fourP1234 - b[4] + c
	c = out[4] >> 51
	out[4] &= reduceMask51
	out[0] += c * 19
}

// GeScalarMultBase computes h = a*B, where
//   a = a[0]+256*a[1]+...+256^31 a[31]
//   B is the Ed25519 base point (x,4/5) with x positive.
//
// Preconditions:
//   a[31] <= 127
func GeScalarMultBase(h *ExtendedGroupElement, a *Bignum256) {
	C.ge25519_scalarmult_base_niels(
		(*C.ge25519)(unsafe.Pointer(h)),
		(*C.uint64_t)(unsafe.Pointer(a)))
}

// FeNeg sets h = -f
//
// Preconditions:
//    |f| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
//
// Postconditions:
//    |h| bounded by 1.1*2^25,1.1*2^24,1.1*2^25,1.1*2^24,etc.
func FeNeg(out, a *Bignum256) {
	//C.curve25519_neg(
	//	(*C.uint64_t)(unsafe.Pointer(h)), (*C.uint64_t)(unsafe.Pointer(f)))
	var c uint64
	out[0] = twoP0 - a[0]
	c = out[0] >> 51
	out[0] &= reduceMask51
	out[1] = twoP1234 - a[1] + c
	c = out[1] >> 51
	out[1] &= reduceMask51
	out[2] = twoP1234 - a[2] + c
	c = out[2] >> 51
	out[2] &= reduceMask51
	out[3] = twoP1234 - a[3] + c
	c = out[3] >> 51
	out[3] &= reduceMask51
	out[4] = twoP1234 - a[4] + c
	c = out[4] >> 51
	out[4] &= reduceMask51
	out[0] += c * 19
}

// GeDoubleScalarMultVartime sets r = a*A + b*B
// where a = a[0]+256*a[1]+...+256^31 a[31].
// and b = b[0]+256*b[1]+...+256^31 b[31].
// B is the Ed25519 base point (x,4/5) with x positive.
func GeDoubleScalarMultVartime(R *ExtendedGroupElement, A *ExtendedGroupElement, a *Bignum256, b *Bignum256) {
	C.ge25519_double_scalarmult_vartime(
		(*C.ge25519)(unsafe.Pointer(R)),
		(*C.ge25519)(unsafe.Pointer(A)),
		(*C.uint64_t)(unsafe.Pointer(a)),
		(*C.uint64_t)(unsafe.Pointer(b)),
	)
}
