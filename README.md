crypto-standard
============

> Standard crypto algorithm implement.

## Table of Contents

- [Usage](#usage)
- [API](#api)
- [Mockgen](#mockgen)
- [GitCZ](#gitcz)
- [Contribute](#contribute)
- [License](#license)

## usage
### hash
```
    hasher := NewHasher(SHA3_512)
	hash, _ := hasher.Hash([]byte(msg))
	hashHex := hex.EncodeToString(hash)
```
### symmetric encryption
```
    aes := new(AES)
    key := []byte("12345678123456781234567812345678")
    c, _ := aes.Encrypt(key, []byte(msg))
    o, _ := aes.Decrypt(key, c)
```
### signature
```
    h, _ := hash.NewHasher(hash.KECCAK_256).Hash(msg)
    priv, _ := GenerateKey(AlgoP256K1)
    bytes, _ := priv.Bytes()
    //r, s is encoded, then about 72bytes
    sign, _ := priv.Sign(bytes, h)
    pub, _ := priv.PublicKey()
    b, err := pub.Verify(nil, sign, h)
```
The vast majority of flato's ecdsa check (non-guomi) actually uses the recovery method, which is called the 'recovery mode' of the check in this package. This method is more efficient.
The main feature of using this kind of check in flato is that the public key is not provided during the verification, but the public key value is calculated by sign, then the address is calculated by the public key value, and the address is compared to complete the check.


Note: The use of this check in flato cannot use the above check method. If this is the case, please refer to the code below.
```
    //Calculation signature
    h, _ := hash.NewHasher(hash.KECCAK_256).Hash(msg)
    //The effect of incoming AlgoP256K1 or AlgoP256K1Recover is the same here
    priv, _ := GenerateKey(AlgoP256K1)  
    bytes, _ := priv.Bytes()
    //r, s is encoded, then about 72bytes
    sign, _ := priv.Sign(bytes, h) 

    //You may get an address from some way, but you can also calculate the address in this way here.
    pub, _ := priv.PublicKey()
    pubByte,_ := pub.Bytes()
    temp,_ := hash.NewHasher(hash.KECCAK_256).Hash(pubByte)
    address:= temp[12:]

    //Here's how you can use the address, hash, and signature data to complete the check.
    recoverPub := NewECDSAPublicKey().FromBytes(address, AlgoP256K1Recover)
    b, err := recoverPub.Verify(nil, sign, h)
```
## api
### hash
Instantiate Hasher
```func NewHasher(hashType HashType) *Hasher```

Computational hash
```func (h *Hasher) Hash(msg []byte) (hash []byte, err error)```

### symmetric encryption
Encrypt
```func (ea *AES) Encrypt(key AESKey, originMsg []byte) (encryptedMsg []byte, err error)```

Decrypt
```func (ea *AES) Decrypt(key AESKey, encryptedMsg []byte) (originMsg []byte, err error)```

### signature
Generate key pair
```func GenerateKey(opt AlgorithmOption) (ECDSAPrivateKey, error) ```

Generate signature
```func (key *ECDSAPrivateKey) Sign(_ []byte, digest []byte) ([]byte, error) ```

Verification signature
```func (key *ECDSAPublicKey) Verify(_ []byte, signature, digest []byte) (valid bool, err error) ```


## Mockgen

Install **mockgen** : `go get github.com/golang/mock/mockgen`

How to use?

- source： Specify interface file
- destination: Generated file name
- package:The package name of the generated file
- imports: Dependent package that requires import
- aux_files: Attach a file when there is more than one file in the interface file
- build_flags: Parameters passed to the build tool

Eg.`mockgen -destination mock/mock_crypto.go -package crypto -source crypto.go`

## GitCZ

**Note**: Please use command `npm install` if you are the first time to use `git cz` in this repo.

## Contribute

PRs are welcome!

Small note: If editing the Readme, please conform to the [standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## License

LGPL © Ultramesh
