package ed25519

import (
	"io"
)

// MaskBit represents one bit of a Cosigners participation bitmask,
// indicating whether a given cosigner is Enabled or Disabled.
type MaskBit bool

//Enabled Disabled
const (
	Enabled  MaskBit = false
	Disabled MaskBit = true
)

//Witness Features
type Witness interface {
	Commit(reader io.Reader) Commitment
	Response(msg, challenge, aggPublicKey []byte) SignaturePart
	AggVerify(threshold uint, message, sig []byte, aggPublicKey []byte) (ret bool)
}

//Leader Features
type Leader interface {
	Challenge(commits []Commitment) Commitment
	AggSign(V Commitment, r []SignaturePart) []byte
	VerifyPartSign(message []byte, challenge Commitment, index int, commit Commitment, r SignaturePart) bool
	GetAggPublicKey() []byte
	SetDisable(signer int)
	ClearStatus()
}

// Cosigners represents a group of collective signers
// identified by an immutable, ordered list of their public keys.
// In addition, the Cosigners object includes a mutable bitmask
// indicating which cosigners are to participate in a signing operation,
// and which cosigners actually participated when verifying a signature.
// Finally, a Cosigners object contains a customizable Policy
// that determines what subsets of cosigners are and aren't acceptable
// when verifying a collective signature.
//
// Since a Cosigners object contains mutable fields
// and implements no thread-safety provisions internally,
// a given Cosigners instance must be used only by one thread at a time.
type ed25519Leader struct {
	// list of all cosigners' public keys in internalized form
	keys []ExtendedGroupElement
	// list of commits
	//commits map[int][32]byte
	// bit-vector of *disabled* cosigners, byte-packed little-endian,
	// or nil impplicitly all-enabled and aggr not yet computed.
	mask []byte

	// cached aggregate of all enabled cosigners' public keys
	aggX    ExtendedGroupElement
	aggAllX ExtendedGroupElement

	//aggNonceCommit
	aggNonceCommit ExtendedGroupElement
}

type ed25519Witness struct {
	privateKey *EDDSAPrivateKey
	s          *Secret
}

// NewEd25519Leader creates a new NewEd25519 Leader object
// for a particular list of cosigners identified by Ed25519 public keys.
//
// The specified list of public keys remains immutable
// for the lifetime of this Cosigners object.
// Collective signature verifiers must use a public key list identical
// to the one that was used in the collective signing process,
// although the participation bitmask may change
// from one collective signature to the next.
//
// The mask parameter may be nil to enable all participants initially,
// and otherwise is an initial participation bitmask as defined in SetMask.
func NewEd25519Leader(publicKeys []*EDDSAPublicKey) Leader {
	var publicKeyBytes [32]byte
	leader := &ed25519Leader{}
	leader.keys = make([]ExtendedGroupElement, len(publicKeys))
	for i, publicKey := range publicKeys {
		copy(publicKeyBytes[:], publicKey[:])
		if !leader.keys[i].FromBytes(&publicKeyBytes) {
			return nil
		}
	}

	// Start with an all-disabled participation mask, then set it correctly
	leader.mask = make([]byte, (len(leader.keys)+7)>>3)
	for i := range leader.mask {
		leader.mask[i] = 0xff // all disabled
	}
	leader.aggX.Zero()
	leader.aggNonceCommit.Zero()
	/* 7 6 5 4 3 2 1 0 | 15 14 13 12 11 10 9 8
	 */
	for i := range leader.keys {
		byt := i >> 3
		bit := byte(1) << uint(i&7)
		// Participant i enabled in new mask.
		leader.mask[byt] &^= bit // enable it
		leader.aggX.Add(&leader.aggX, &leader.keys[i])
	}
	leader.aggAllX = leader.aggX
	return leader
}

//NewEd25519Witness creates a new NewEd25519 Witness object
func NewEd25519Witness(privateKey *EDDSAPrivateKey) Witness {
	witness := &ed25519Witness{
		privateKey: privateKey,
	}
	return witness
}

// SetMaskBit enables or disables the mask bit for an individual cosigner.
func (leader *ed25519Leader) SetDisable(signer int) {
	byt := signer >> 3
	bit := byte(1) << uint(signer&7)

	if leader.mask[byt]&bit == 0 { // was enabled
		leader.mask[byt] |= bit // disable it
		leader.aggX.Sub(&leader.aggX, &leader.keys[signer])
	}
	// enable
	//if leader.mask[byt]&bit != 0 { // was disabled
	//	leader.mask[byt] &^= bit
	//	leader.aggX.add(&leader.aggX, &leader.keys[signer])
	//}

}

// MaskBit returns a boolean value indicating whether
// the indicated signer is Enabled or Disabled.
func (leader *ed25519Leader) maskBit(signer int) (value MaskBit) {
	byt := signer >> 3
	bit := byte(1) << uint(signer&7)
	return (leader.mask[byt] & bit) != 0
}

//ClearStatus clear mask
func (leader *ed25519Leader) ClearStatus() {
	length := len(leader.keys)
	for i := 0; i < length; i++ {
		byt := i >> 3
		bit := byte(1) << uint(i&7)
		if leader.mask[byt]&bit != 0 { //if disable
			leader.mask[byt] &^= bit
			leader.aggX.Add(&leader.aggX, &leader.keys[i])
		}
	}
	leader.aggNonceCommit.Zero()
}
