package hash

//HashType represent hash algorithm type
type HashType uint32

//nolint
const (
	//SHA1 sha1
	SHA1   HashType = 0x10
	SHA2   HashType = 0x20
	SHA3   HashType = 0x30
	KECCAK HashType = 0x40

	Size224 HashType = 0x01
	Size256 HashType = 0x00
	Size384 HashType = 0x02
	Size512 HashType = 0x03

	//SHA2_224 sha2 with 224bits
	SHA2_224 = SHA2 | Size224
	//SHA2_256 sha2 with 224bits
	SHA2_256 = SHA2 | Size256
	//SHA2_384 sha2 with 384bits
	SHA2_384 = SHA2 | Size384
	//SHA2_512 sha2 with 512bits
	SHA2_512 = SHA2 | Size512
	//SHA3_224 sha3 with 224bits
	SHA3_224 = SHA3 | Size224
	//SHA3_256 sha3 with 256bits
	SHA3_256 = SHA3 | Size256
	//SHA3_384 sha3 with 384bits
	SHA3_384 = SHA3 | Size384
	//SHA3_512 sha3 with 512bits
	SHA3_512 = SHA3 | Size512
	//KECCAK_224 KECCAK with 224bits
	KECCAK_224 = KECCAK | Size224
	//KECCAK_256 KECCAK with 256bits
	KECCAK_256 = KECCAK | Size256
	//KECCAK_384 KECCAK with 384bits
	KECCAK_384 = KECCAK | Size384
	//KECCAK_512 KECCAK with 512bits
	KECCAK_512 = KECCAK | Size512
)
