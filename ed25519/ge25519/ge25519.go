package ge25519

import (
	"crypto/subtle"
	"github.com/meshplus/crypto-standard/ed25519/curve25519"
	"github.com/meshplus/crypto-standard/ed25519/modm"
)

// Upstream: `ed25519-donna-impl-base.h`

//Ge25519 a point in curve25519
type Ge25519 struct {
	X curve25519.Bignum25519
	Y curve25519.Bignum25519
	Z curve25519.Bignum25519
	T curve25519.Bignum25519
}

//Zero set point to zero
func (r *Ge25519) Zero() {
	r.X.Reset()
	r.Y.Reset()
	r.Z.Reset()
	r.T.Reset()
	r.Y[0] = 1
	r.Z[0] = 1
}

type ge25519p1p1 struct {
	x curve25519.Bignum25519
	y curve25519.Bignum25519
	z curve25519.Bignum25519
	t curve25519.Bignum25519
}

type ge25519niels struct {
	ysubx curve25519.Bignum25519
	xaddy curve25519.Bignum25519
	t2d   curve25519.Bignum25519
}

type ge25519pniels struct {
	ysubx curve25519.Bignum25519
	xaddy curve25519.Bignum25519
	z     curve25519.Bignum25519
	t2d   curve25519.Bignum25519
}

//
// conversions
//

func p1p1ToPartial(r *Ge25519, p *ge25519p1p1) {
	// ge25519_p1p1_to_partial(ge25519 *r, const ge25519_p1p1 *p)
	curve25519.Mul(&r.X, &p.x, &p.t)
	curve25519.Mul(&r.Y, &p.y, &p.z)
	curve25519.Mul(&r.Z, &p.z, &p.t)
}

func p1p1ToFull(r *Ge25519, p *ge25519p1p1) {
	// ge25519_p1p1_to_full(ge25519 *r, const ge25519_p1p1 *p)
	curve25519.Mul(&r.X, &p.x, &p.t)
	curve25519.Mul(&r.Y, &p.y, &p.z)
	curve25519.Mul(&r.Z, &p.z, &p.t)
	curve25519.Mul(&r.T, &p.x, &p.y)
}

func fullToPniels(r *ge25519pniels, p *Ge25519) {
	// ge25519_full_to_pniels(ge25519_pniels *p, const ge25519 *r)

	// Note: Upstream's p/r being inconsistent with internal convention
	// is fixed for readability.

	curve25519.Sub(&r.ysubx, &p.Y, &p.X)
	curve25519.Add(&r.xaddy, &p.Y, &p.X)
	curve25519.Copy(&r.z, &p.Z)
	curve25519.Mul(&r.t2d, &p.T, &ec2d)
}

//
// adding & doubling
//

func addP1p1(r *ge25519p1p1, p, q *Ge25519) {
	// ge25519_add_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519 *q)
	var a, b, c, d, t, u curve25519.Bignum25519

	curve25519.Sub(&a, &p.Y, &p.X)
	curve25519.Add(&b, &p.Y, &p.X)
	curve25519.Sub(&t, &q.Y, &q.X)
	curve25519.Add(&u, &q.Y, &q.X)
	curve25519.Mul(&a, &a, &t)
	curve25519.Mul(&b, &b, &u)
	curve25519.Mul(&c, &p.T, &q.T)
	curve25519.Mul(&c, &c, &ec2d)
	curve25519.Mul(&d, &p.Z, &q.Z)
	curve25519.Add(&d, &d, &d)
	curve25519.Sub(&r.x, &b, &a)
	curve25519.Add(&r.y, &b, &a)
	curve25519.AddAfterBasic(&r.z, &d, &c)
	curve25519.SubAfterBasic(&r.t, &d, &c)
}

func doubleP1p1(r *ge25519p1p1, p *Ge25519) {
	// ge25519_double_p1p1(ge25519_p1p1 *r, const ge25519 *p)
	var a, b, c curve25519.Bignum25519

	curve25519.Square(&a, &p.X)
	curve25519.Square(&b, &p.Y)
	curve25519.Square(&c, &p.Z)
	curve25519.AddReduce(&c, &c, &c)
	curve25519.Add(&r.x, &p.X, &p.Y)
	curve25519.Square(&r.x, &r.x)
	curve25519.Add(&r.y, &b, &a)
	curve25519.Sub(&r.z, &b, &a)
	curve25519.SubAfterBasic(&r.x, &r.x, &r.y)
	curve25519.SubAfterBasic(&r.t, &c, &r.z)
}

func nielsAdd2P1p1Vartime(r *ge25519p1p1, p *Ge25519, q *ge25519niels, signbit uint8) {
	// ge25519_nielsadd2_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_niels *q, unsigned char signbit)
	var a, b, c curve25519.Bignum25519

	// Note: The upstream code typecasts q and r to pointers to avoid
	// the conditionals, but having them is safe as this routine is
	// only called from `ge25519_double_scalarmult_vartime`.
	curve25519.Sub(&a, &p.Y, &p.X)
	curve25519.Add(&b, &p.Y, &p.X)
	if signbit == 0 {
		curve25519.Mul(&a, &a, &q.ysubx)
		curve25519.Mul(&r.x, &b, &q.xaddy)
	} else {
		curve25519.Mul(&a, &a, &q.xaddy)
		curve25519.Mul(&r.x, &b, &q.ysubx)
	}
	curve25519.Add(&r.y, &r.x, &a)
	curve25519.Sub(&r.x, &r.x, &a)

	curve25519.Mul(&c, &p.T, &q.t2d)
	curve25519.AddReduce(&r.t, &p.Z, &p.Z)
	curve25519.Copy(&r.z, &r.t)
	if signbit == 0 {
		curve25519.Add(&r.z, &r.z, &c)
		curve25519.Sub(&r.t, &r.t, &c)
	} else {
		curve25519.Add(&r.t, &r.t, &c)
		curve25519.Sub(&r.z, &r.z, &c)
	}
}

func pnielsAddP1P1Vartime(r *ge25519p1p1, p *Ge25519, q *ge25519pniels, signbit uint8) {
	// ge25519_pnielsadd_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_pniels *q, unsigned char signbit)
	var a, b, c curve25519.Bignum25519

	// Note: The upstream code typecasts q and r to pointers to avoid
	// the conditionals, but having them is safe as this routine is
	// only called from `ge25519_double_scalarmult_vartime`.
	curve25519.Sub(&a, &p.Y, &p.X)
	curve25519.Add(&b, &p.Y, &p.X)
	if signbit == 0 {
		curve25519.Mul(&a, &a, &q.ysubx)
		curve25519.Mul(&r.x, &b, &q.xaddy)
	} else {
		curve25519.Mul(&a, &a, &q.xaddy)
		curve25519.Mul(&r.x, &b, &q.ysubx)
	}
	curve25519.Add(&r.y, &r.x, &a)
	curve25519.Sub(&r.x, &r.x, &a)
	curve25519.Mul(&c, &p.T, &q.t2d)
	curve25519.Mul(&r.t, &p.Z, &q.z)
	curve25519.AddReduce(&r.t, &r.t, &r.t)
	curve25519.Copy(&r.z, &r.t)
	if signbit == 0 {
		curve25519.Add(&r.z, &r.z, &c)
		curve25519.Sub(&r.t, &r.t, &c)
	} else {
		curve25519.Add(&r.t, &r.t, &c)
		curve25519.Sub(&r.z, &r.z, &c)
	}
}

func doublePartial(r *Ge25519, p *Ge25519) {
	// ge25519_double_partial(ge25519 *r, const ge25519 *p)
	var t ge25519p1p1
	doubleP1p1(&t, p)
	p1p1ToPartial(r, &t)
}

//Double r = p + p
func Double(r *Ge25519, p *Ge25519) {
	// ge25519_double(ge25519 *r, const ge25519 *p)
	var t ge25519p1p1
	doubleP1p1(&t, p)
	p1p1ToFull(r, &t)
}

//Add r = p + q
func Add(r, p, q *Ge25519) {
	// ge25519_add(ge25519 *r, const ge25519 *p,  const ge25519 *q)
	var t ge25519p1p1
	addP1p1(&t, p, q)
	p1p1ToFull(r, &t)
}

func nielsAdd2(r *Ge25519, q *ge25519niels) {
	// ge25519_nielsadd2(ge25519 *r, const ge25519_niels *q)
	var a, b, c, e, f, g, h curve25519.Bignum25519

	curve25519.Sub(&a, &r.Y, &r.X)
	curve25519.Add(&b, &r.Y, &r.X)
	curve25519.Mul(&a, &a, &q.ysubx)
	curve25519.Mul(&e, &b, &q.xaddy)
	curve25519.Add(&h, &e, &a)
	curve25519.Sub(&e, &e, &a)
	curve25519.Mul(&c, &r.T, &q.t2d)
	curve25519.Add(&f, &r.Z, &r.Z)
	curve25519.AddAfterBasic(&g, &f, &c)
	curve25519.SubAfterBasic(&f, &f, &c)
	curve25519.Mul(&r.X, &e, &f)
	curve25519.Mul(&r.Y, &h, &g)
	curve25519.Mul(&r.Z, &g, &f)
	curve25519.Mul(&r.T, &e, &h)
}

func pnielsAdd(r *ge25519pniels, p *Ge25519, q *ge25519pniels) {
	// ge25519_pnielsadd(ge25519_pniels *r, const ge25519 *p, const ge25519_pniels *q)
	var a, b, c, x, y, z, t curve25519.Bignum25519

	curve25519.Sub(&a, &p.Y, &p.X)
	curve25519.Add(&b, &p.Y, &p.X)
	curve25519.Mul(&a, &a, &q.ysubx)
	curve25519.Mul(&x, &b, &q.xaddy)
	curve25519.Add(&y, &x, &a)
	curve25519.Sub(&x, &x, &a)
	curve25519.Mul(&c, &p.T, &q.t2d)
	curve25519.Mul(&t, &p.Z, &q.z)
	curve25519.Add(&t, &t, &t)
	curve25519.AddAfterBasic(&z, &t, &c)
	curve25519.SubAfterBasic(&t, &t, &c)
	curve25519.Mul(&r.xaddy, &x, &t)
	curve25519.Mul(&r.ysubx, &y, &z)
	curve25519.Mul(&r.z, &z, &t)
	curve25519.Mul(&r.t2d, &x, &y)
	curve25519.Copy(&y, &r.ysubx)
	curve25519.Sub(&r.ysubx, &r.ysubx, &r.xaddy)
	curve25519.Add(&r.xaddy, &r.xaddy, &y)
	curve25519.Mul(&r.t2d, &r.t2d, &ec2d)
}

func windowbEqual(b, c uint32) uint32 {
	// uint32_t ge25519_windowb_equal(uint32_t b, uint32_t c)
	return ((b ^ c) - 1) >> 31
}

func scalarmultBaseChooseNiels(t *ge25519niels, table *[256][96]byte, pos int, b int8) {
	// ge25519_scalarmult_base_choose_niels(ge25519_niels *T, const uint8_t table[256][96], uint32_t pos, signed char b)
	var (
		neg  curve25519.Bignum25519
		sign = uint32(uint8(b) >> 7)
		mask = ^(sign - 1)
		u    = (uint32(b) + mask) ^ mask
	)

	// ysubx, xaddy, t2d in packed form. initialize to ysubx = 1, xaddy = 1, t2d = 0
	var packed [96]byte
	packed[0] = 1
	packed[32] = 1

	for i := 0; i < 8; i++ {
		moveConditionalBytes(&packed, &table[(pos*8)+i], uint64(windowbEqual(u, uint32(i+1))))
	}

	// expand in to T
	curve25519.Expand(&t.ysubx, packed[0:])
	curve25519.Expand(&t.xaddy, packed[32:])
	curve25519.Expand(&t.t2d, packed[64:])

	// adjust for sign
	curve25519.SwapConditional(&t.ysubx, &t.xaddy, uint64(sign))
	curve25519.Neg(&neg, &t.t2d)
	curve25519.SwapConditional(&t.t2d, &neg, uint64(sign))
}

//Pack point to bytes
func Pack(r []byte, p *Ge25519) {
	// ge25519_pack(unsigned char r[32], const ge25519 *p)
	var (
		tx, ty, zi curve25519.Bignum25519
		parity     [32]byte
	)

	curve25519.Recip(&zi, &p.Z)
	curve25519.Mul(&tx, &p.X, &zi)
	curve25519.Mul(&ty, &p.Y, &zi)
	curve25519.Contract(r, &ty)
	curve25519.Contract(parity[:], &tx)
	r[31] ^= (parity[0] & 1) << 7
}

//UnpackVartime point from bytes
func UnpackVartime(r *Ge25519, p []byte, negative bool) bool {
	// ge25519_unpack_negative_vartime(ge25519 *r, const unsigned char p[32])
	var (
		t, root, num, den, d3 curve25519.Bignum25519
		zero, check           [32]byte
		one                   = curve25519.Bignum25519{1}
		parity                = p[31] >> 7
	)

	curve25519.Expand(&r.Y, p)
	curve25519.Copy(&r.Z, &one)
	curve25519.Square(&num, &r.Y)          // X = Y^2
	curve25519.Mul(&den, &num, &ecd)       // den = dy^2
	curve25519.SubReduce(&num, &num, &r.Z) // X = Y^1 - 1
	curve25519.Add(&den, &den, &r.Z)       // den = dy^2 + 1

	// Computation of sqrt(num/den)
	// 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8)
	curve25519.Square(&t, &den)
	curve25519.Mul(&d3, &t, &den)
	curve25519.Square(&r.X, &d3)
	curve25519.Mul(&r.X, &r.X, &den)
	curve25519.Mul(&r.X, &r.X, &num)
	curve25519.PowTwo252m3(&r.X, &r.X)

	// 2. computation of r.X = num * den^3 * (num*den^7)^((p-5)/8)
	curve25519.Mul(&r.X, &r.X, &d3)
	curve25519.Mul(&r.X, &r.X, &num)

	// 3. Check if either of the roots works:
	curve25519.Square(&t, &r.X)
	curve25519.Mul(&t, &t, &den)
	curve25519.SubReduce(&root, &t, &num)
	curve25519.Contract(check[:], &root)
	if subtle.ConstantTimeCompare(check[:], zero[:]) == 0 {
		curve25519.AddReduce(&t, &t, &num)
		curve25519.Contract(check[:], &t)
		if subtle.ConstantTimeCompare(check[:], zero[:]) == 0 {
			return false
		}
		curve25519.Mul(&r.X, &r.X, &sqrtNeg1)
	}

	curve25519.Contract(check[:], &r.X)
	if negative && (check[0]&1) == parity {
		curve25519.Copy(&t, &r.X)
		curve25519.Neg(&r.X, &t)
	}
	if !negative && (check[0]&1) != parity {
		curve25519.Copy(&t, &r.X)
		curve25519.Neg(&r.X, &t)
	}
	curve25519.Mul(&r.T, &r.X, &r.Y)

	return true
}

//
// scalarmults
//

const (
	s1SWindowSize = 5
	s1TableSize   = 1 << (s1SWindowSize - 2)
	s2SWindowSize = 7
)

//DoubleScalarmultVartime computes [s1]p1 + [s2]basepoint
func DoubleScalarmultVartime(r, p1 *Ge25519, s1, s2 *modm.Bignum256) {
	// ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const bignum256modm s2)
	var (
		slide1, slide2 [256]int8
		pre1           [s1TableSize]ge25519pniels
		d1             Ge25519
		t              ge25519p1p1
		i              int
	)

	modm.ContractSlidingWindow(&slide1, s1, s1SWindowSize)
	modm.ContractSlidingWindow(&slide2, s2, s2SWindowSize)

	Double(&d1, p1)
	fullToPniels(&pre1[0], p1)
	for i = 0; i < s1TableSize-1; i++ {
		pnielsAdd(&pre1[i+1], &d1, &pre1[i])
	}

	// set neutral
	r.Zero()
	r.Y[0] = 1
	r.Z[0] = 1

	i = 255
	for (i >= 0) && ((slide1[i] | slide2[i]) == 0) {
		i--
	}

	abs := func(n int8) int {
		if n < 0 {
			return -int(n)
		}
		return int(n)
	}
	for ; i >= 0; i-- {
		doubleP1p1(&t, r)

		if slide1[i] != 0 {
			p1p1ToFull(r, &t)
			pnielsAddP1P1Vartime(&t, r, &pre1[abs(slide1[i])/2], uint8(slide1[i])>>7)
		}

		if slide2[i] != 0 {
			p1p1ToFull(r, &t)
			nielsAdd2P1p1Vartime(&t, r, &nielsSlidingMultiples[abs(slide2[i])/2], uint8(slide2[i])>>7)
		}

		p1p1ToPartial(r, &t)
	}
}

//ScalarmultBaseNiels computes [s]basepoint
func ScalarmultBaseNiels(r *Ge25519, s *modm.Bignum256) {
	// ge25519_scalarmult_base_niels(ge25519 *r, const uint8_t basepoint_table[256][96], const bignum256modm s)
	var (
		b [64]int8
		t ge25519niels
	)
	basepointTable := &NielsBaseMultiples

	modm.ContractWindow4(&b, s)

	scalarmultBaseChooseNiels(&t, basepointTable, 0, b[1])
	curve25519.SubReduce(&r.X, &t.xaddy, &t.ysubx)
	curve25519.AddReduce(&r.Y, &t.xaddy, &t.ysubx)
	r.Z.Reset()
	curve25519.Copy(&r.T, &t.t2d)
	r.Z[0] = 2
	for i := 3; i < 64; i += 2 {
		scalarmultBaseChooseNiels(&t, basepointTable, i/2, b[i])
		nielsAdd2(r, &t)
	}
	doublePartial(r, r)
	doublePartial(r, r)
	doublePartial(r, r)
	Double(r, r)
	scalarmultBaseChooseNiels(&t, basepointTable, 0, b[0])
	curve25519.Mul(&t.t2d, &t.t2d, &ecd)
	nielsAdd2(r, &t)
	for i := 2; i < 64; i += 2 {
		scalarmultBaseChooseNiels(&t, basepointTable, i/2, b[i])
		nielsAdd2(r, &t)
	}

	for i := range b {
		b[i] = 0
	}
}

//FromBytes FromBytes
func (r *Ge25519) FromBytes(s *[32]byte) bool {
	UnpackVartime(r, s[:], false)
	return true
}

//Add ge = a + b
func (r *Ge25519) Add(a, b *Ge25519) {
	Add(r, a, b)
}

//Sub ge = a -b
func (r *Ge25519) Sub(a, b *Ge25519) {
	var ryPlusX, ryMinusX, rZ, rT2d curve25519.Bignum25519
	var tmp Ge25519
	var t0 curve25519.Bignum25519
	//1

	curve25519.AddReduce(&ryPlusX, &b.Y, &b.X)
	curve25519.SubAfterBasic(&ryMinusX, &b.Y, &b.X)

	rZ = b.Z

	curve25519.Mul(&rT2d, &b.T, &ec2d)

	////2
	curve25519.AddReduce(&tmp.X, &a.Y, &a.X)

	curve25519.SubAfterBasic(&tmp.Y, &a.Y, &a.X)

	curve25519.Mul(&tmp.Z, &tmp.X, &ryMinusX) //ScMul(&tmp.Z, &tmp.X, &q.yPlusX)

	curve25519.Mul(&tmp.Y, &tmp.Y, &ryPlusX) //ScMul(&tmp.Y, &tmp.Y, &q.yMinusX)

	curve25519.Mul(&tmp.T, &rT2d, &a.T)
	curve25519.Mul(&tmp.X, &a.Z, &rZ)

	curve25519.AddReduce(&t0, &tmp.X, &tmp.X)
	curve25519.SubAfterBasic(&tmp.X, &tmp.Z, &tmp.Y)
	curve25519.AddReduce(&tmp.Y, &tmp.Z, &tmp.Y)
	curve25519.SubAfterBasic(&tmp.Z, &t0, &tmp.T) //ScAdd(&tmp.Z, &t0, &tmp.T)
	curve25519.AddReduce(&tmp.T, &t0, &tmp.T)     //ScSub(&tmp.T, &t0, &tmp.T)

	//3
	curve25519.Mul(&r.X, &tmp.X, &tmp.T)
	curve25519.Mul(&r.Y, &tmp.Y, &tmp.Z)

	curve25519.Mul(&r.Z, &tmp.Z, &tmp.T)

	curve25519.Mul(&r.T, &tmp.X, &tmp.Y)
}

//ToBytes using Pack
func (r *Ge25519) ToBytes(s *[32]byte) {
	Pack(s[:], r)
}
