package inter

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

//AES a AES instance is a tool to encrypt and decrypt
type AES struct {
}

//Encrypt encrypt
func (ea *AES) Encrypt(key, originMsg []byte, reader io.Reader) (encryptedMsg []byte, err error) {
	return aesEnc(key, originMsg, reader)
}

//Decrypt decrypt
func (ea *AES) Decrypt(key, encryptedMsg []byte) (originMsg []byte, err error) {
	return aesDec(key, encryptedMsg)
}

//AESKey represent aes key
type AESKey []byte

//Bytes return bytes
func (a AESKey) Bytes() ([]byte, error) {
	r := make([]byte, len(a))
	copy(r, a)
	return r, nil
}

//FromBytes get a key from bytes
func (a AESKey) FromBytes(k []byte, opt interface{}) []byte {
	copy(a, k)
	return a
}

func aesEnc(key, src []byte, reader io.Reader) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("the secret len must be 32")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	msg := PKCS5Padding(src, block.BlockSize())
	iv := make([]byte, block.BlockSize())
	if _, err := reader.Read(iv); err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(msg)+len(iv))
	blockMode.CryptBlocks(crypted[block.BlockSize():], msg)
	copy(crypted[0:block.BlockSize()], iv)
	return crypted, nil
}

func aesDec(key, src []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("the secret len must be 32")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, src[:block.BlockSize()])
	origData := make([]byte, len(src)-block.BlockSize())
	blockMode.CryptBlocks(origData, src[block.BlockSize():])
	origData, err = PKCS5UnPadding(origData)
	if err != nil {
		return nil, err
	}
	return origData, nil
}
