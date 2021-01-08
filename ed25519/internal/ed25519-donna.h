/*
	Public domain by Andrew M. <liquidsun@gmail.com>
	Modified from the amd64-51-30k implementation by
		Daniel J. Bernstein
		Niels Duif
		Tanja Lange
		Peter Schwabe
		Bo-Yin Yang
*/
#ifndef ED25519_DONNA_H
#define ED25519_DONNA_H

#include "ed25519-donna-portable.h"

#define ED25519_64BIT

//ED25519_GCC_64BIT_X86_CHOOSE
#if !defined(ED25519_NO_INLINE_ASM)
	/* detect extra features first so un-needed functions can be disabled throughout */
    #if defined(CPU_X86_64)
        #if defined(COMPILER_GCC)
            #if defined(ED25519_64BIT)
                #define ED25519_GCC_64BIT_X86_CHOOSE
            #else
                #define ED25519_GCC_64BIT_32BIT_CHOOSE
            #endif
        #endif
    #endif
#endif

#include "curve25519-donna-64bit.h"

#include "curve25519-donna-helpers.h"

/* separate uint128 check for 64 bit sse2 */
#include "modm-donna-64bit.h"

typedef unsigned char hash_512bits[64];

/*
	Timing safe memory compare
*/
static int
ed25519_verify(const unsigned char *x, const unsigned char *y, size_t len) {
	size_t differentbits = 0;
	while (len--)
		differentbits |= (*x++ ^ *y++);
	//return (int) (1 & ((differentbits - 1) >> 8));
    return differentbits == 0;
}


/*
 * Arithmetic on the twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2
 * with d = -(121665/121666) = 37095705934669439343138083508754565189542113879843219016388785533085940283555
 * Base point: (15112221349535400772501151409588531511454012693041857206046113283949847762202,46316835694926478169428394003475163141307993866256225615783033603165251855960);
 */

typedef struct ge25519_t {
	bignum25519 x, y, z, t;   //t = xy  标准射影坐标
} ge25519;

typedef struct ge25519_p1p1_t {
	bignum25519 x, y, z, t;
} ge25519_p1p1;

/*

Group elements are members of the elliptic curve -x^2 + y^2 = 1 + d * x^2 *
y^2 where d = -121665/121666.

Several representations are used:
ProjectiveGroupElement: (X:Y:Z) satisfying x=X/Z, y=Y/Z
ExtendedGroupElement: (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
CompletedGroupElement: ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
PreComputedGroupElement: (y+x,y-x,2dxy)

ed25519 <=> ExtendedGroupElement
ge25519_p1p1 <=> CompletedGroupElement
ge25519_niels_t <=> PreComputedGroupElement

*/


typedef struct ge25519_niels_t {
	bignum25519 ysubx, xaddy, t2d;
} ge25519_niels;

typedef struct ge25519_pniels_t {
	bignum25519 ysubx, xaddy, z, t2d;
} ge25519_pniels;

#include "ed25519-donna-basepoint-table.h"

#if defined(ED25519_64BIT)
	#include "ed25519-donna-64bit-tables.h"
	#include "ed25519-donna-64bit-x86.h"
#endif


#include "ed25519-donna-impl-base.h"

#endif //ED25519_DONNA_H