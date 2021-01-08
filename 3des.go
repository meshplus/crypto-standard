package inter

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"errors"
	"io"
)

//TripleDES a 3DES instance is a tool to encrypt and decrypt
// Very not recommended to use 3des!!! It's slow and unsafe
type TripleDES struct {
}

//Encrypt encrypt
func (ea *TripleDES) Encrypt(key, plaintext []byte, reader io.Reader) (cipherText []byte, err error) {
	return TripleDesEnc(key, plaintext, reader)
}

//Decrypt decrypt
func (ea *TripleDES) Decrypt(key, cipherTex []byte) (plaintext []byte, err error) {
	return TripleDesDec(key, cipherTex)
}

//TripleDESKey represent 3des key
type TripleDESKey []byte

//Bytes return bytes
func (t TripleDESKey) Bytes() ([]byte, error) {
	r := make([]byte, len(t))
	copy(r, t)
	return r, nil
}

//FromBytes get a key from bytes
func (t TripleDESKey) FromBytes(k []byte, opt interface{}) []byte {
	copy(t, k)
	return t
}

//TripleDesEncrypt8 3DES with 8 bytes key
func TripleDesEncrypt8(origData, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	origData = PKCS5Padding(origData, block.BlockSize())
	// origData = ZeroPadding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key[:8])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//TripleDesDecrypt8 3DES with 8 bytes key
func TripleDesDecrypt8(crypted, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key[:8])
	origData := make([]byte, len(crypted))
	// origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	origData, err = PKCS5UnPadding(origData)
	if err != nil {
		return nil, err
	}
	// origData = ZeroUnPadding(origData)
	return origData, nil
}

// TripleDesEnc encryption algorithm implements
func TripleDesEnc(key, src []byte, reader io.Reader) ([]byte, error) {
	if len(key) < 24 {
		return nil, errors.New("the secret len is less than 24")
	}
	block, err := des.NewTripleDESCipher(key[:24])
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

// TripleDesDec decryption algorithm implements
func TripleDesDec(key, src []byte) ([]byte, error) {
	//log.Criticalf("to descrypt msg is : %s",common.ToHex(src))
	if len(key) < 24 {
		return nil, errors.New("the secret len is less than 24")
	}
	block, err := des.NewTripleDESCipher(key[:24])
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, src[:block.BlockSize()])
	//log.Criticalf("dec block size:%d , src len %d, %d",blockMode.BlockSize(),len(src),len(src)%block.BlockSize())
	origData := make([]byte, len(src)-block.BlockSize())
	blockMode.CryptBlocks(origData, src[block.BlockSize():])
	origData, err = PKCS5UnPadding(origData)
	if err != nil {
		return nil, err
	}
	return origData, nil
}

//PKCS5Padding padding with pkcs5
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

//PKCS5UnPadding unpadding with pkcs5
func PKCS5UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	if unpadding > length {
		return nil, errors.New("decrypt failed,please check it")
	}
	return origData[:(length - unpadding)], nil
}
