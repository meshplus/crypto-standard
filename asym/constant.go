package asym

import "errors"

//AlgorithmOption represent ECDSA curve
type AlgorithmOption string

const (
	//AlgoP256K1 secp256k1
	AlgoP256K1 AlgorithmOption = "SECP256K1"
	//AlgoP256K1Recover secp256k1 with recover mode
	AlgoP256K1Recover AlgorithmOption = "SECP256K1RECOVER"
	//AlgoP224R1 secp224r1
	AlgoP224R1 AlgorithmOption = "SECP224R1"
	//AlgoP256R1 secp256r1
	AlgoP256R1 AlgorithmOption = "SECP256R1"
	//AlgoP384R1 secp384r1
	AlgoP384R1 AlgorithmOption = "SECP384R1"
	//AlgoP521R1 secp512r1
	AlgoP521R1 AlgorithmOption = "SECP521R1"

	errIllegalInputParameter = "illegal input parameter "
	//errSignatureLengthIllegal    = "signature length is not 65"
	//errInvalidSignatureRecoverID = "invalid signature recover ID"
	errInvalidSignature = "invalid signature"

	keyStoreTypeTEESGX = "tee_sgx"
)

// KeyStoreOption KeyStoreOption
type KeyStoreOption struct {
	keyStoreType string
	algo         AlgorithmOption
}

//WithTEESGXKeyStore WithTEESGXKeyStore
func (a AlgorithmOption) WithTEESGXKeyStore() (*KeyStoreOption, error) {
	//todo 检查当前是否有enclave实例
	switch a {
	case AlgoP256R1:
		return &KeyStoreOption{algo: a, keyStoreType: keyStoreTypeTEESGX}, nil
	default:
		return nil, errors.New("not support tee-sgx key store")
	}
}
