
//+build ignore


#include <stdio.h>
#include "ed25519-donna.h"

static int
test_adds() {
#if defined(HAVE_UINT128) && !defined(ED25519_SSE2)
	/* largest result for each limb from a mult or square: all elements except r1 reduced, r1 overflowed as far as possible */
	static const bignum25519 max_bignum = {
		0x7ffffffffffff,0x8000000001230,0x7ffffffffffff,0x7ffffffffffff,0x7ffffffffffff
	};

	/* what max_bignum should fully reduce to */
	static const unsigned char max_bignum_raw[32] = {
		0x12,0x00,0x00,0x00,0x00,0x00,0x88,0x91,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};

	/* (max_bignum + max_bignum)^2 */
	static const unsigned char max_bignum2_squared_raw[32] = {
		0x10,0x05,0x00,0x00,0x00,0x00,0x80,0xdc,0x51,0x00,0x00,0x00,0x00,0x61,0xed,0x4a,
		0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	};

	/* ((max_bignum + max_bignum) + max_bignum)^2 */
	static const unsigned char max_bignum3_squared_raw[32] = {
		0x64,0x0b,0x00,0x00,0x00,0x00,0x20,0x30,0xb8,0x00,0x00,0x00,0x40,0x1a,0x96,0xe8,
		0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	};
#else
	/* largest result for each limb from a mult or square: all elements except r1 reduced, r1 overflowed as far as possible */
	static const bignum25519 ALIGN(16) max_bignum = {
		0x3ffffff,0x2000300,0x3ffffff,0x1ffffff,0x3ffffff,
		0x1ffffff,0x3ffffff,0x1ffffff,0x3ffffff,0x1ffffff
	};

	/* what max_bignum should fully reduce to */
	static const unsigned char max_bignum2_squared_raw[32] = {
		0x10,0x05,0x00,0x40,0xc2,0x06,0x40,0x80,0x41,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	};

	/* (max_bignum * max_bignum) */
	static const unsigned char max_bignum3_squared_raw[32] = {
		0x64,0x0b,0x00,0x10,0x35,0x0f,0x90,0x60,0x13,0x05,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	};
#endif
	unsigned char result[32];
	static const bignum25519 ALIGN(16) zero = {0};
	bignum25519 ALIGN(16) a, b, c;
	size_t i;

	/* a = (max_bignum + max_bignum) */
	curve25519_add(a, max_bignum, max_bignum);

	/* b = ((max_bignum + max_bignum) * (max_bignum + max_bignum)) */
	curve25519_mul(b, a, a);
	curve25519_contract(result, b);
	if (memcmp(result, max_bignum2_squared_raw, 32) != 0)
		return -1;
	curve25519_square(b, a);
	curve25519_contract(result, b);
	if (memcmp(result, max_bignum2_squared_raw, 32) != 0)
		return -1;

	/* b = (max_bignum + max_bignum + max_bignum) */
	curve25519_add_after_basic(b, a, max_bignum);

	/* a = ((max_bignum + max_bignum + max_bignum) * (max_bignum + max_bignum + max_bignum)) */
	curve25519_mul(a, b, b);
	curve25519_contract(result, a);
	if (memcmp(result, max_bignum3_squared_raw, 32) != 0)
		return -1;
	curve25519_square(a, b);
	curve25519_contract(result, a);
	if (memcmp(result, max_bignum3_squared_raw, 32) != 0)
		return -1;

	return 0;
}

static int
test_subs() {
#if defined(HAVE_UINT128) && !defined(ED25519_SSE2)
	/* largest result for each limb from a mult or square: all elements except r1 reduced, r1 overflowed as far as possible */
	static const bignum25519 max_bignum = {
		0x7ffffffffffff,0x8000000001230,0x7ffffffffffff,0x7ffffffffffff,0x7ffffffffffff
	};

	/* what max_bignum should fully reduce to */
	static const unsigned char max_bignum_raw[32] = {
		0x12,0x00,0x00,0x00,0x00,0x00,0x88,0x91,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};

	/* (max_bignum * max_bignum) */
	static const unsigned char max_bignum_squared_raw[32] = {
		0x44,0x01,0x00,0x00,0x00,0x00,0x20,0x77,0x14,0x00,0x00,0x00,0x40,0x58,0xbb,0x52,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
	};
#else
	/* largest result for each limb from a mult or square: all elements except r1 reduced, r1 overflowed as far as possible */
	static const bignum25519 ALIGN(16) max_bignum = {
		0x3ffffff,0x2000300,0x3ffffff,0x1ffffff,0x3ffffff,
		0x1ffffff,0x3ffffff,0x1ffffff,0x3ffffff,0x1ffffff
	};

	/* what max_bignum should fully reduce to */
	static const unsigned char max_bignum_raw[32] = {
		0x12,0x00,0x00,0x04,0x0c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	};

	/* (max_bignum * max_bignum) */
	static const unsigned char max_bignum_squared_raw[32] = {
		0x44,0x01,0x00,0x90,0xb0,0x01,0x10,0x60,0x90,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	};
#endif
	unsigned char result[32];
	static const bignum25519 ALIGN(16) zero = {0};
	bignum25519 ALIGN(16) a, b, c;
	size_t i;

	/* a = max_bignum - 0, which expands to 2p + max_bignum - 0 */
	curve25519_sub(a, max_bignum, zero);
	curve25519_contract(result, a);
	if (memcmp(result, max_bignum_raw, 32) != 0)
		return -1;

	/* b = (max_bignum * max_bignum) */
	curve25519_mul(b, a, a);
	curve25519_contract(result, b);
	if (memcmp(result, max_bignum_squared_raw, 32) != 0)
		return -1;
	curve25519_square(b, a);
	curve25519_contract(result, b);
	if (memcmp(result, max_bignum_squared_raw, 32) != 0)
		return -1;

	/* b = ((a - 0) - 0) */
	curve25519_sub_after_basic(b, a, zero);
	curve25519_contract(result, b);
	if (memcmp(result, max_bignum_raw, 32) != 0)
		return -1;

	/* a = (max_bignum * max_bignum) */
	curve25519_mul(a, b, b);
	curve25519_contract(result, a);
	if (memcmp(result, max_bignum_squared_raw, 32) != 0)
		return -1;
	curve25519_square(a, b);
	curve25519_contract(result, a);
	if (memcmp(result, max_bignum_squared_raw, 32) != 0)
		return -1;


	return 0;
}

void test_uint82uint64(){
    printf("uint64_t: %d byte\n", sizeof(uint64_t));
    printf("unsigned long: %d byte\n", sizeof(unsigned long));
    printf("unsigned long long: %d byte\n", sizeof(unsigned long long));
    uint64_t a = 0x307c83864f2833cb;
    unsigned char b[8] = {};
    U64TO8_LE(b, a);
    int i;
    printf("uint8 : ");for (i=0;i<8;i++)printf("%02x",b[i]);printf("\n");
    printf("uint64: %lx\n",U8TO64_LE(b));
}

void test_encode_only() {

    unsigned char input[32] = {0x6a,0x62,0xa6,0x20,0x55,0x07,0xfc,0xaf,0xe9,0xee,0x43,0xd6,0xf8,0x33,0x2a,0x37,
                               0x14,0x40,0x85,0xf9,0xae,0x45,0x46,0x11,0x26,0x32,0x32,0xec,0x77,0x11,0x07,0xc6};
    unsigned char output[32] = {0};
    int i;
    ge25519 point;
    ge25519_unpack_vartime(&point,input,0);
    //打印出x和y

    curve25519_contract(output,point.x);
    for (i=0;i<32;i++)printf("%02x",output[i]);printf("\n");memset(output,0,32);
    curve25519_contract(output,point.y);
    for (i=0;i<32;i++)printf("%02x",output[i]);printf("\n");memset(output,0,32);
    curve25519_contract(output,point.z);
    for (i=0;i<32;i++)printf("%02x",output[i]);printf("\n");memset(output,0,32);
    curve25519_contract(output,point.t);
    for (i=0;i<32;i++)printf("%02x",output[i]);printf("\n");memset(output,0,32);

    ge25519_pack(output, &point);
    for (i=0;i<32;i++)printf("%02x",output[i]);printf("\n");

    ge25519_unpack_vartime(&point,output,0);
    ge25519_pack(output, &point);
    for (i=0;i<32;i++)printf("%02x",output[i]);printf("\n");

    //modm_m的大端表示
    memset(output, 0 ,32);
    curve25519_contract(output,modm_m);
    printf("modm_m.x:");for (i=0;i<32;i++)printf("%02x",output[i]);printf("\n");memset(output,0,32);

}

int
main() {
    test_uint82uint64();
    test_encode_only();
	int ret = 0;
	int single;
	single = test_adds();
	if (single) printf("test_adds: FAILED\n");
	ret |= single;
	single = test_subs();
	if (single) printf("test_subs: FAILED\n");
	ret |= single;
	if (!ret) printf("success\n");
	return ret;
}


