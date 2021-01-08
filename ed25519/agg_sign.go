package ed25519

import (
	"crypto/rand"
	"crypto/sha512"
	"io"
	"strconv"
	"unsafe"
)

// Commitment represents a byte-slice used in the collective signing process,
// which cosigners produce via Commit and send to the leader
// for combination via AggregateCommit.
type Commitment []byte

// SignaturePart represents a byte-slice used in collective signing,
// which cosigners produce via Cosign and send to the leader
// for combination via AggregateSignature.
type SignaturePart *Bignum256

// Secret represents a one-time random secret used
// in collectively signing a single message.
type Secret struct {
	reduced Bignum256
	valid   bool
}

//Commit commit
func (witness *ed25519Witness) Commit(reader io.Reader) Commitment {
	var secretFull [64]byte
	secret := new(Secret)
	_, _ = io.ReadFull(reader, secretFull[:])

	scReduce(&(secret.reduced), secretFull[:])
	secret.valid = true

	// compute R, the individual Schnorr commit to our one-time secret
	var R ExtendedGroupElement
	geScalarMultBase(&R, &secret.reduced)

	var encodedR [32]byte
	R.ToBytes(&encodedR)
	witness.s = secret
	return encodedR[:]
}

// Cosign signs the message with privateKey and returns a partial signature. It will
// panic if len(privateKey) is not PrivateKeySize.

// Cosign is used by a cosigner to produce its part of a collective signature.
// This operation requires the cosigner's private key,
// the local per-message Secret previously produced
// by the corresponding call to Commit,
// and the aggregate public key and aggregate commit
// that the leader obtained in this signing round
// from AggregatePublicKey and AggregateCommit respectively.
//
// Since it is security-critical that a particular Secret be used only once,
// Cosign invalidates the secret when it is called,
// and panics if called with a previously-used secret.
func (witness *ed25519Witness) Response(message, //r = cX + V
	challenge, aggPublicKey []byte) SignaturePart {

	if l := len(challenge); l != EddsaPKLen {
		panic("ed25519: bad challenge length: " + strconv.Itoa(l))
	}

	if l := len(aggPublicKey); l != EddsaPKLen*2 {
		panic("ed25519: bad aggPublicKey length: " + strconv.Itoa(l))
	}

	if !witness.s.valid {
		panic("ed25519: you must use a cosigning Secret only once")
	}

	//expanded secret key
	h := sha512.New()
	_, err := h.Write(witness.privateKey[:32])
	if err != nil {
		return nil
	}
	var digest1 [64]byte
	var expandedSecretKey [32]byte
	h.Sum(digest1[:0])
	copy(expandedSecretKey[:], digest1[:])
	expandedSecretKey[0] &= 248
	expandedSecretKey[31] &= 63
	expandedSecretKey[31] |= 64

	var hramDigest [64]byte
	h.Reset()
	_, err = h.Write(challenge)
	if err != nil {
		return nil
	}
	_, err = h.Write(aggPublicKey[32:])
	if err != nil {
		return nil
	}
	_, err = h.Write(message)
	if err != nil {
		return nil
	}
	h.Sum(hramDigest[:0]) //c =  H(c || X || msg)

	var hramDigestReduced Bignum256
	scReduce(&hramDigestReduced, hramDigest[:]) //c mod l

	// Produce our individual contribution to the collective signature
	var tmp, s Bignum256
	lE2Polynomial(&tmp, &expandedSecretKey)
	scMulAdd(&s, &hramDigestReduced, &tmp, &witness.s.reduced) //  cx + v

	// Erase the one-time secret and make darn sure it gets used only once,
	// even if a buggy caller invokes Cosign twice after a single Commit
	witness.s.reduced = Bignum256{}
	witness.s.valid = false

	return &s // individual partial signature
}

// AggregatePublicKey computes and returns an aggregate public key
// representing the set of cosigners
// currently enabled in the participation bitmask.
// The leader invokes this method during collective signing
// to determine the aggregate public key that needs to be passed
// to the cosigners and supplied to their Cosign operations.
func (leader *ed25519Leader) GetAggPublicKey() []byte {
	//aggX || aggAllX
	var keyBytes [64]byte
	leader.aggX.ToBytes((*[32]byte)(unsafe.Pointer(&keyBytes[0])))
	leader.aggAllX.ToBytes((*[32]byte)(unsafe.Pointer(&keyBytes[32])))
	return keyBytes[:]
}

// AggregateCommit is invoked by the leader during collective signing
// to combine all cosigners' individual commits into an aggregate commit,
// which it must pass back to all cosigners for use in their Cosign operations.
// The commits slice must have length equal to the total number of cosigners,
// but AggregateCommit uses only the entries corresponding to cosigners
// that are enabled in the participation mask.
func (leader *ed25519Leader) Challenge(commits []Commitment) Commitment {
	var aggR, indivR ExtendedGroupElement
	if len(commits) != len(leader.keys) {
		return nil
	}
	aggR.Zero()
	for i := range leader.keys {
		if leader.maskBit(i) == Disabled {
			continue
		}

		if l := len(commits[i]); l != EddsaPKLen {
			_, tmp := GenerateKey(rand.Reader)
			commits[i] = tmp[:]
		}

		buf := new([32]byte)
		copy(buf[:], commits[i])

		if !indivR.FromBytes(buf) {
			return nil
		}
		aggR.Add(&aggR, &indivR)
	}

	var aggRBytes [32]byte
	aggR.ToBytes(&aggRBytes)
	return aggRBytes[:]
}

// AggregateSignature is invoked by the leader during collective signing
// to combine all cosigners' individual signature parts
// into a final collective signature.
// The sigParts slice must have length equal to the total number of cosigners,
// but AggregateSignature uses only the entries corresponding to cosigners
// that are enabled in the participation mask,
// which must be identical to the one
// the leader previously used during AggregateCommit.
func (leader *ed25519Leader) AggSign(c Commitment, r []SignaturePart) []byte {

	if l := len(c); l != EddsaPKLen {
		panic("ed25519: bad aggregateR length: " + strconv.Itoa(l))
	}

	var aggS, indivS Bignum256
	for i := range leader.keys {
		if leader.maskBit(i) == Disabled {
			continue
		}

		indivS = *(r[i])
		scAdd(&aggS, &aggS, &indivS) // ∑r
	}

	muSigSize := EddsaSignLen + 32 + len(leader.mask)
	signature := make([]byte, muSigSize)
	copy(signature[:], c)
	polynomial2LE(signature[32:64], &aggS)
	leader.aggNonceCommit.ToBytes((*[32]byte)(unsafe.Pointer(&signature[64])))
	copy(signature[96:], leader.mask) //V || ∑r  || aggNonceCommit || mask
	return signature
}
