//
// Created by 乔沛杨 on 2020-03-10.
//

#ifndef ED25519_HEAP_H
#define ED25519_HEAP_H


/* platform */
#if defined(COMPILER_MSVC)
	#define ALIGN(x) __declspec(align(x))
#else
	#define ALIGN(x) __attribute__((aligned(x)))
#endif

#define max_batch_size 64
#define heap_batch_size ((max_batch_size * 2) + 1)

#define bignum256modm_bits_per_limb 56
#define bignum256modm_limb_size 5

/* which limb is the 128th bit in? */
static const size_t limb128bits = (128 + bignum256modm_bits_per_limb - 1) / bignum256modm_bits_per_limb;

typedef size_t heap_index_t;


struct batch_heap_t {
    size_t size;
    heap_index_t heap[heap_batch_size];
    bignum256modm scalars[heap_batch_size];
    ge25519 points[heap_batch_size];
    //unsigned char r[heap_batch_size][16]; /* 128 bit random values */
} ALIGN(8);

typedef struct batch_heap_t batch_heap;

#endif //ED25519_HEAP_H
