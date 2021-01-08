//Hyperchain License
//Copyright (C) 2016 The Hyperchain Authors.
package sha3

// This file provides functions for creating instances of the SHA-3
// and SHAKE hash functions, as well as utility functions for hashing
// bytes.

import (
	"hash"
)

// NewKeccak224 creates a new Keccak-224 hash.
func NewKeccak224() hash.Hash { return &state{rate: 144, outputLen: 28, dsbyte: 0x01} }

// NewKeccak256 creates a new Keccak-256 hash.
func NewKeccak256() hash.Hash { return &state{rate: 136, outputLen: 32, dsbyte: 0x01} }

// NewKeccak384 creates a new Keccak-384 hash.
func NewKeccak384() hash.Hash { return &state{rate: 104, outputLen: 48, dsbyte: 0x01} }

// NewKeccak512 creates a new Keccak-512 hash.
func NewKeccak512() hash.Hash { return &state{rate: 72, outputLen: 64, dsbyte: 0x01} }

// New224 creates a new SHA3-224 hash.
// Its generic security strength is 224 bits against preimage attacks,
// and 112 bits against collision attacks.
func New224() hash.Hash { return &state{rate: 144, outputLen: 28, dsbyte: 0x06} }

// New256 creates a new SHA3-256 hash.
// Its generic security strength is 256 bits against preimage attacks,
// and 128 bits against collision attacks.
func New256() hash.Hash { return &state{rate: 136, outputLen: 32, dsbyte: 0x06} }

// New384 creates a new SHA3-384 hash.
// Its generic security strength is 384 bits against preimage attacks,
// and 192 bits against collision attacks.
func New384() hash.Hash { return &state{rate: 104, outputLen: 48, dsbyte: 0x06} }

// New512 creates a new SHA3-512 hash.
// Its generic security strength is 512 bits against preimage attacks,
// and 256 bits against collision attacks.
func New512() hash.Hash { return &state{rate: 72, outputLen: 64, dsbyte: 0x06} }
