//+build !amd64

package ed25519

import "C"
import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"github.com/meshplus/crypto-standard/ed25519/curve25519"
	"github.com/meshplus/crypto-standard/ed25519/ge25519"
	"github.com/meshplus/crypto-standard/ed25519/modm"
	"io"
	"strconv"
)

// Copyright (c) 2016 The Go Authors. All rights reserved.
// Copyright (c) 2019 Oasis Labs Inc.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Package ed25519 implements the Ed25519 signature algorithm. See
// https://ed25519.cr.yp.to/.
//
// These functions are also compatible with the “Ed25519” function defined in
// RFC 8032. However, unlike RFC 8032's formulation, this package's private key
// representation includes a public key suffix to make multiple signing
// operations with the same key more efficient. This package refers to the RFC
// 8032 private key as the “seed”.

//BatchHeapGo
type BatchHeapGo = batchHeap

//ExtendedGroupElement
type ExtendedGroupElement = ge25519.Ge25519

//Bignum256
type Bignum256 = modm.Bignum256

//neg
var neg = curve25519.Neg

//lE2Polynomial
var lE2Polynomial = modm.ExpandRaw

//polynomial2LE
var polynomial2LE = modm.Contract

//geDoubleScalarMultVartime
var geDoubleScalarMultVartime = ge25519.DoubleScalarmultVartime

//geScalarMultBase
var geScalarMultBase = ge25519.ScalarmultBaseNiels

//scMulAdd
var scMulAdd = modm.MulAdd

//scAdd
var scAdd = modm.Add

//scReduce
var scReduce = modm.Expand

const (
	// SeedSize is the Size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
)

var _ crypto.Signer = (*EDDSAPrivateKey)(nil)

// Sign signs the given message with priv. rand is ignored. If opts.HashFunc()
// is crypto.SHA512, the pre-hashed variant Ed25519ph is used and message is
// expected to be a SHA-512 hash, otherwise opts.HashFunc() must be
// crypto.Hash(0) and the message must not be hashed, as Ed25519 performs two
// passes over messages to be signed.
func (priv *EDDSAPrivateKey) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) (signature []byte, err error) {
	r := sign(priv, message)
	if r == nil {
		return nil, fmt.Errorf("ed25519 sign err")
	}
	return r, nil
}

func sign(privateKey *EDDSAPrivateKey, message []byte) []byte {
	if l := len(privateKey); l != EddsaVKLen {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	var (
		extsk, hashr, hram [64]byte
		r, S, a            modm.Bignum256
		R                  ge25519.Ge25519

		RS [EddsaSignLen]byte
	)

	h := sha512.New()
	_, _ = h.Write(privateKey[:32])
	h.Sum(extsk[:0])
	extsk[0] &= 248
	extsk[31] &= 127
	extsk[31] |= 64

	// r = H(aExt[32..64], m)
	h.Reset()

	_, _ = h.Write(extsk[32:])
	_, _ = h.Write(message)
	h.Sum(hashr[:0])
	modm.Expand(&r, hashr[:])

	// R = rB
	ge25519.ScalarmultBaseNiels(&R, &r)
	ge25519.Pack(RS[:], &R)

	// S = H(R,A,m)..
	h.Reset()

	_, _ = h.Write(RS[:32])
	_, _ = h.Write(privateKey[32:])
	_, _ = h.Write(message)
	h.Sum(hram[:0])
	modm.Expand(&S, hram[:])

	// S = H(R,A,m)a
	modm.Expand(&a, extsk[:32])
	modm.Mul(&S, &S, &a)

	// S = (r + H(R,A,m)a)
	modm.Add(&S, &S, &r)

	// S = (r + H(R,A,m)a) mod L
	modm.Contract(RS[32:], &S)

	h.Reset()
	a.Reset()
	for i := range extsk {
		extsk[i] = 0
	}

	return RS[:]
}

//ed25519Verify for test function
func ed25519Verify(digest, pk, sign []byte) bool {
	return verify(pk, digest, sign)
}

// Verify reports whether sig is a valid signature of message by publicKey. It
// will panic if len(publicKey) is not PublicKeySize.
func (pk *EDDSAPublicKey) Verify(_ []byte, signature, message []byte) (bool, error) {
	if len(signature) != EddsaSignLen {
		return false, fmt.Errorf("signature length mast be 64")
	}
	return verify(pk[:], message, signature), nil
}

func verify(publicKey, message, sig []byte) bool {
	if l := len(publicKey); l != EddsaPKLen {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	var (
		hash    [64]byte
		checkR  [32]byte
		R, A    ge25519.Ge25519
		hram, S modm.Bignum256
	)

	if len(sig) != EddsaSignLen || (sig[63]&224 != 0) || !ge25519.UnpackVartime(&A, publicKey[:], true) {
		return false
	}

	// hram = H(R,A,m)
	h := sha512.New()

	_, _ = h.Write(sig[:32])
	_, _ = h.Write(publicKey[:])
	_, _ = h.Write(message)
	h.Sum(hash[:0])
	modm.Expand(&hram, hash[:])
	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.
	if !scMinimal(sig[32:]) {
		return false
	}

	// S
	modm.Expand(&S, sig[32:])

	// SB - H(R,A,m)A
	ge25519.DoubleScalarmultVartime(&R, &A, &hram, &S)

	ge25519.Pack(checkR[:], &R)
	// check that R = SB - H(R,A,m)A

	return bytes.Equal(checkR[:], sig[:32])
}

// newKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func newKeyFromSeed(seed []byte) *EDDSAPrivateKey {
	if l := len(seed); l != SeedSize {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}

	// `sha512.Sum512` does not call d.Zero(), but it's somewhat of a
	// moot point because the runtime library's SHA-512 implementation's
	// `Zero()` method doesn't actually clear the buffer currently.
	var digest [64]byte
	h := sha512.New()
	_, _ = h.Write(seed)
	h.Sum(digest[:0])
	h.Reset()

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var (
		a              modm.Bignum256
		A              ge25519.Ge25519
		publicKeyBytes [32]byte
	)
	modm.Expand(&a, digest[:32])
	ge25519.ScalarmultBaseNiels(&A, &a)
	ge25519.Pack(publicKeyBytes[:], &A)

	privateKey := new(EDDSAPrivateKey)
	copy(privateKey[:], seed)
	copy(privateKey[32:], publicKeyBytes[:])

	for i := range digest {
		digest[i] = 0
	}
	a.Reset()

	return privateKey
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*EDDSAPrivateKey, *EDDSAPublicKey) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil
	}

	privateKey := newKeyFromSeed(seed)
	publicKey := new(EDDSAPublicKey)
	copy(publicKey[:], privateKey[32:])

	for i := range seed {
		seed[i] = 0
	}

	return privateKey, publicKey
}

// order is the order of Curve25519 in little-endian form.
var order = [4]uint64{0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000}

// scMinimal returns true if the given scalar is less than the order of the
// curve.
func scMinimal(scalar []byte) bool {
	for i := 3; ; i-- {
		v := binary.LittleEndian.Uint64(scalar[i*8:])
		if v > order[i] {
			return false
		} else if v < order[i] {
			break
		} else if i == 0 {
			return false
		}
	}

	return true
}
