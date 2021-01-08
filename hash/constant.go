package hash

//HashType represent hash algorithm type
type HashType uint32

const (
	//SHA1 sha1
	SHA1 HashType = 0x11
	//SHA2_256 sha2 with 256bits
	SHA2_256 HashType = 0x12
	//SHA2_512 sha2 with 512bits
	SHA2_512 HashType = 0x13
	//SHA3_224 sha3 with 224bits
	SHA3_224 HashType = 0x17
	//SHA3_256 sha3 with 256bits
	SHA3_256 HashType = 0x16
	//SHA3_384 sha3 with 384bits
	SHA3_384 HashType = 0x15
	//SHA3_512 sha3 with 512bits
	SHA3_512 HashType = 0x14
	//SHA3 sha3 with 512bits
	SHA3 = SHA3_512
	//KECCAK_224 KECCAK with 224bits
	KECCAK_224 HashType = 0x1A
	//KECCAK_256 KECCAK with 256bits
	KECCAK_256 HashType = 0x1B
	//KECCAK_384 KECCAK with 384bits
	KECCAK_384 HashType = 0x1C
	//KECCAK_512 KECCAK with 512bits
	KECCAK_512 HashType = 0x1D
)
