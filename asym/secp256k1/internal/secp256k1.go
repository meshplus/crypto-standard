package internal

/*
#cgo CFLAGS: -DUSE_NUM_NONE -DUSE_ENDOMORPHISM -DUSE_FIELD_10X26 -DUSE_FIELD_INV_BUILTIN -DUSE_SCALAR_8X32 -DUSE_SCALAR_INV_BUILTIN -DNDEBUG -w -O3 -I./

//#define USE_SCALAR_4X64  // TODO: set USE_SCALAR_4X64 depending on platform?
#include "secp256k1_recovery.h"
#include "secp256k1.h"

#include "field.h"
#include "field_impl.h"
#include "ecdsa_impl.h"
#include "ecmult_const.h"
#include "eckey.h"
#include "group.h"
#include "group_impl.h"
#include "ecmult_const_impl.h"

int secp256k1_pubkey_scalar_mul(const secp256k1_context* ctx, unsigned char *point, const unsigned char *scalar) {
	int ret = 0;
	int overflow = 0;
	secp256k1_fe feX, feY;
	secp256k1_gej res;
	secp256k1_ge ge;
	secp256k1_scalar s;
	(void)ctx;

	secp256k1_fe_set_b32(&feX, point);
	secp256k1_fe_set_b32(&feY, point+32);
	secp256k1_ge_set_xy(&ge, &feX, &feY);
	secp256k1_scalar_set_b32(&s, scalar, &overflow);
	if (overflow || secp256k1_scalar_is_zero(&s)) {
		ret = 0;
	} else {
		secp256k1_ecmult_const(&res, &ge, &s);
		secp256k1_ge_set_gej(&ge, &res);
		 //Note: can't use secp256k1_pubkey_save here because it is not constant time.
		secp256k1_fe_normalize(&ge.x);
		secp256k1_fe_normalize(&ge.y);
		secp256k1_fe_get_b32(point, &ge.x);
		secp256k1_fe_get_b32(point+32, &ge.y);
		ret = 1;
	}
	secp256k1_scalar_clear(&s);
	return ret;
}
*/
import "C"
import (
	"errors"
	"io"
	"math/big"
	"unsafe"
)

var (
	context *C.secp256k1_context
)

//ErrInvalid defines error message
var (
	ErrInvalidMsgLen       = errors.New("invalid message length for signature recovery")
	ErrInvalidSignatureLen = errors.New("invalid signature length")
	ErrInvalidRecoveryID   = errors.New("invalid signature recovery id")
)

func init() {
	// around 20 ms on a modern CPU.
	context = C.secp256k1_context_create(3) // SECP256K1_START_SIGN | SECP256K1_START_VERIFY
}

//CurveScalarMult Curve Scalar Mult
func CurveScalarMult(Bx, By *big.Int, scalar []byte) (*big.Int, *big.Int) {
	// Ensure scalar is exactly 32 bytes. We pad always, even if
	// scalar is 32 bytes long, to avoid a timing side channel.
	if len(scalar) > 32 {
		panic("can't handle scalars > 256 bits")
	}
	padded := make([]byte, 32)
	copy(padded[32-len(scalar):], scalar)
	scalar = padded

	// Do the multiplication in C, updating point.
	point := make([]byte, 64)
	readBits(point[:32], Bx)
	readBits(point[32:], By)
	pointPtr := (*C.uchar)(unsafe.Pointer(&point[0]))
	scalarPtr := (*C.uchar)(unsafe.Pointer(&scalar[0]))
	res := C.secp256k1_pubkey_scalar_mul(context, pointPtr, scalarPtr)

	// Unpack the result and clear temporaries.
	x := new(big.Int).SetBytes(point[:32])
	y := new(big.Int).SetBytes(point[32:])
	for i := range point {
		point[i] = 0
	}
	for i := range padded {
		scalar[i] = 0
	}
	if res != 1 {
		return nil, nil
	}
	return x, y
}

//BaseMul base mul
func BaseMul(scalar []byte) (*big.Int, *big.Int) {
	padded := make([]byte, 32)
	copy(padded[32-len(scalar):], scalar)
	scalar = padded
	scalarPtr := (*C.uchar)(unsafe.Pointer(&scalar[0]))
	point := make([]uint8, 64)
	pointPtr := (*C.secp256k1_pubkey)(unsafe.Pointer(&point[0]))

	C.secp256k1_ec_pubkey_create(context, pointPtr, scalarPtr)
	x := new(big.Int).SetBytes(point[:32])
	y := new(big.Int).SetBytes(point[32:])
	return x, y
}

// reads num into buf as big-endian bytes.
func readBits(buf []byte, num *big.Int) {
	const wordLen = int(unsafe.Sizeof(big.Word(0)))
	i := len(buf)
	for _, d := range num.Bits() {
		for j := 0; j < wordLen && i > 0; j++ {
			i--
			buf[i] = byte(d)
			d >>= 8
		}
	}
}

//Sign return
func Sign(msg []byte, seckey []byte, rand io.Reader) ([]byte, error) {
	msgPtr := (*C.uchar)(unsafe.Pointer(&msg[0]))
	seckeyPtr := (*C.uchar)(unsafe.Pointer(&seckey[0]))

	sig := make([]byte, 65)
	sigPtr := (*C.secp256k1_ecdsa_recoverable_signature)(unsafe.Pointer(&sig[0]))

	nonce, err := csprng(32, rand)
	if err != nil {
		return nil, err
	}
	ndataPtr := unsafe.Pointer(&nonce[0])

	noncefpPtr := &(*C.secp256k1_nonce_function_default)

	if C.secp256k1_ec_seckey_verify(context, seckeyPtr) != C.int(1) {
		return nil, errors.New("Invalid secret key")
	}

	ret := C.secp256k1_ecdsa_sign_recoverable(
		context,
		sigPtr,
		msgPtr,
		seckeyPtr,
		noncefpPtr,
		ndataPtr,
	)

	if ret == C.int(0) {
		return Sign(msg, seckey, rand) //invalid secret, try again
	}

	sigSerialized := make([]byte, 65)
	sigSerializedPtr := (*C.uchar)(unsafe.Pointer(&sigSerialized[0]))
	var recid C.int

	C.secp256k1_ecdsa_recoverable_signature_serialize_compact(
		context,
		sigSerializedPtr, // 64 byte compact signature
		&recid,
		sigPtr, // 65 byte "recoverable" signature
	)

	sigSerialized[64] = byte(int(recid)) // add back recid to get 65 bytes sig

	return sigSerialized, nil

}

// RecoverPubkey returns the the public key of the signer.
// msg must be the 32-byte hash of the message to be signed.
// sig must be a 65-byte compact ECDSA signature containing the
// recovery id as the last element.
func RecoverPubkey(msg []byte, sig []byte) ([]byte, error) {
	if len(msg) != 32 {
		return nil, ErrInvalidMsgLen
	}
	if err := checkSignature(sig); err != nil {
		return nil, err
	}

	msgPtr := (*C.uchar)(unsafe.Pointer(&msg[0]))
	sigPtr := (*C.uchar)(unsafe.Pointer(&sig[0]))
	pubkey := make([]byte, 64)
	/*
		this slice is used for both the recoverable signature and the
		resulting serialized pubkey (both types in libsecp256k1 are 65
		bytes). this saves one allocation of 65 bytes, which is nice as
		pubkey recovery is one bottleneck during load in Ethereum
	*/
	bytes65 := make([]byte, 65)
	pubkeyPtr := (*C.secp256k1_pubkey)(unsafe.Pointer(&pubkey[0]))
	recoverableSigPtr := (*C.secp256k1_ecdsa_recoverable_signature)(unsafe.Pointer(&bytes65[0]))
	recid := C.int(sig[64])

	ret := C.secp256k1_ecdsa_recoverable_signature_parse_compact(
		context,
		recoverableSigPtr,
		sigPtr,
		recid)
	if ret == C.int(0) {
		return nil, errors.New("failed to parse signature")
	}

	ret = C.secp256k1_ecdsa_recover(
		context,
		pubkeyPtr,
		recoverableSigPtr,
		msgPtr,
	)
	if ret == C.int(0) {
		return nil, errors.New("failed to recover public key")
	}

	serializedPubkeyPtr := (*C.uchar)(unsafe.Pointer(&bytes65[0]))
	var outputLen C.size_t
	C.secp256k1_ec_pubkey_serialize( // always returns 1
		context,
		serializedPubkeyPtr,
		&outputLen,
		pubkeyPtr,
		0, // SECP256K1_EC_COMPRESSED
	)
	return bytes65, nil
}

func checkSignature(sig []byte) error {
	if len(sig) != 65 {
		return ErrInvalidSignatureLen
	}
	if sig[64] >= 4 {
		return ErrInvalidRecoveryID
	}
	return nil
}
