package ed25519

import (
	"crypto/sha512"
	"unsafe"
)

//VerifyPartSign V is commitment ,r = sign
func (leader *ed25519Leader) VerifyPartSign(message []byte, c Commitment, index int, V Commitment, r SignaturePart) (ret bool) {
	var bufForAggAllX [32]byte

	defer func() {
		if !ret {
			element := new(ExtendedGroupElement)
			element.FromBytes((*[32]byte)(unsafe.Pointer(&V[0])))
			leader.aggNonceCommit.Add(&leader.aggNonceCommit, element)
			leader.SetDisable(index)
		}
	}()
	if len(V) != 32 || len(c) != 32 || r == nil {
		return false
	}

	leader.aggAllX.ToBytes(&bufForAggAllX)
	ret = aggVerify(message, c, (*[32]byte)(unsafe.Pointer(&V[0])), r, leader.keys[index], &bufForAggAllX)
	return
}

//AggVerify verify
func (witness *ed25519Witness) AggVerify(threshold uint, message, sig, aggPublicKey []byte) (ret bool) {
	defer func() {
		_ = recover()
	}()

	var j uint
	for i := range sig[96:] {
		temp := sig[96:][i]
		for k := 0; k < 8; k++ {
			j += uint(temp&0x01 ^ 0x01)
			temp = temp >> 1
		}
	}

	// Check that this represents a sufficient set of signers
	if j < threshold {
		return false
	}

	aggX := ExtendedGroupElement{}
	tmp := new([32]byte)
	copy(tmp[:], aggPublicKey[:32])
	aggX.FromBytes(tmp)
	signR, signS := [32]byte{}, [32]byte{}
	copy(signR[:], sig[:32])

	//sub aggNonceCommit
	copy(tmp[:], sig[64:96])
	suber, subee := new(ExtendedGroupElement), new(ExtendedGroupElement)
	subee.FromBytes(&signR)
	suber.FromBytes(tmp)
	subee.Sub(subee, suber)
	subee.ToBytes(&signR)

	copy(signS[:], sig[32:64])
	signSBigNum := new(Bignum256)
	lE2Polynomial(signSBigNum, &signS)
	return aggVerify(message, sig[:32],
		&signR,
		signSBigNum,
		aggX, (*[32]byte)(unsafe.Pointer(&aggPublicKey[32])))
}

// 		| 4*G - H(2 || 6 || 1)5 ?= 3
//------+----------------------------
// agg  | sigS*G - H(c ||aggX||msg)aggX ?= c    aggR = sigR = c = aggV
//		| msg,c,sigR,sigS,aggX,aggX
//------+-----------------------------
// part	| sign*G - H(c ||aggX||msg)X ?= V      {sign = H(c || X || msg)x + v}
//		| msg,c, V, sign, X, aggX
func aggVerify(message, c []byte,
	sigR *[32]byte,
	sigS *Bignum256,
	X ExtendedGroupElement, aggAllX *[32]byte) bool {

	// Compute the digest against aggregate public key and commit
	h := sha512.New()
	_, err := h.Write(c)
	if err != nil {
		return false
	}
	_, err = h.Write(aggAllX[:]) //永远是聚合公钥,用于计算hash
	if err != nil {
		return false
	}
	_, err = h.Write(message)
	if err != nil {
		return false
	}
	var digest [64]byte
	h.Sum(digest[:0])      //c = H(R || X || msg)
	var hReduced Bignum256 //polynomial form
	scReduce(&hReduced, digest[:])

	// The public key used for checking is whichever part was signed
	neg(&X.X, &X.X) //有时候需要是用户的公钥
	neg(&X.T, &X.T)

	var projR ExtendedGroupElement
	geDoubleScalarMultVartime(&projR, &X, &hReduced, sigS) //projR = SG - cX  ?= R

	var checkFromProjR [32]byte
	projR.ToBytes(&checkFromProjR)
	return checkFromProjR == *sigR
}
