package asym

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/meshplus/crypto-standard/asym/secp256k1"
	"github.com/meshplus/crypto-standard/hash"
	"github.com/stretchr/testify/assert"
	"testing"
)

var msg = make([]byte, 961)

func init() {
	_, _ = rand.Read(msg)
}

func TestSignK1(t *testing.T) {
	h, err := hash.NewHasher(hash.KECCAK_256).Hash(msg)
	assert.Nil(t, err)
	priv, err := GenerateKey(AlgoP256K1)
	assert.Nil(t, err)
	bytes, _ := priv.Bytes()
	assert.NotNil(t, bytes)
	sign, err := priv.Sign(nil, h, rand.Reader) //r,s经过编码，之后是72bytes
	assert.Nil(t, err)
	assert.NotEqual(t, nil, sign)
	pub := priv.Public().(*ECDSAPublicKey)
	assert.Nil(t, err)
	if b, err := pub.Verify(nil, sign, h); !b || err != nil {
		t.Error("fail")
	}
}

func TestSignR1(t *testing.T) {
	h, err := hash.NewHasher(hash.KECCAK_256).Hash(msg)
	assert.Nil(t, err)
	priv, err := GenerateKey(AlgoP256R1)
	assert.Nil(t, err)
	bytes, _ := priv.Bytes()
	assert.NotNil(t, bytes)
	sign, err := priv.Sign(nil, h, rand.Reader)
	assert.Nil(t, err)
	assert.NotNil(t, sign)
	pub := priv.Public().(*ECDSAPublicKey)
	assert.Nil(t, err)
	b, err := pub.Verify(nil, sign, h)
	assert.Nil(t, err)
	assert.True(t, b)
}

//Test compatibility
func TestSign(t *testing.T) {
	//{"address":"ec24bd2c319463b5fa10cb829ebc95de6520c2fe","algo":"0x03","encrypted":"3e83c9cd9a39bf96d1f77a978e1fb32be0ad1732eee157011e162e9749b2e90a","version":"2.0"}
	privateFromJSON := "3e83c9cd9a39bf96d1f77a978e1fb32be0ad1732eee157011e162e9749b2e90a"
	publicFromSDK := "0454f73fc55299a40b20638f10c2d704dcb605e7e61b56ea11b4ad9528e533ab8501089fc3a87512ad4f6a6631086ab2734c56811268a1b7816d684d709c6becb8"
	addrFromJSON := "ec24bd2c319463b5fa10cb829ebc95de6520c2fe"

	//calculate publicKey and compare
	privateBytes, _ := hex.DecodeString(privateFromJSON)
	privKey := new(ECDSAPrivateKey)
	assert.Nil(t, privKey.FromBytes(privateBytes, AlgoP256K1))
	privKey.CalculatePublicKey()
	pubKey := privKey.Public().(*ECDSAPublicKey)
	pubKeyBytes, _ := pubKey.Bytes()
	if publicFromSDK != hex.EncodeToString(pubKeyBytes) {
		t.Error(hex.EncodeToString(pubKeyBytes))
	}

	//calculate address and compare
	addrBytes, _ := hash.NewHasher(hash.KECCAK_256).Hash(pubKeyBytes[1:]) //remove first byte 04
	if addrFromJSON != hex.EncodeToString(addrBytes[12:]) {
		t.Error(hex.EncodeToString(addrBytes))
	}
}

func TestECDSA_K1(t *testing.T) {
	key := "3e83c9cd9a39bf96d1f77a978e1fb32be0ad1732eee157011e162e9749b2e90a"
	pub := "0454f73fc55299a40b20638f10c2d704dcb605e7e61b56ea11b4ad9528e533ab8501089fc3a87512ad4f6a6631086ab2734c56811268a1b7816d684d709c6becb8"
	msg := "hello"
	keyBytes, _ := hex.DecodeString(key)
	pubBytes, _ := hex.DecodeString(pub)
	h, _ := hash.NewHasher(hash.KECCAK_256).Hash([]byte(msg))
	sign, _ := NewECDSA(AlgoP256K1).Sign(keyBytes, h, rand.Reader)

	b, err := NewECDSA(AlgoP256K1).Verify(pubBytes, sign, h)
	assert.Nil(t, err)
	assert.True(t, b)
}

func TestECDSA_K1_SDKCert(t *testing.T) {
	pubkey := "04e0133813bb9bb7d1588ba31d2b06c888416f688da98543d8330ff9ad8f78d46c285635277c39a5f3c882c8261f16f30b70fd4e6b085ce8eb5bf2b0a458afd911"
	msg := "7b226a736f6e727063223a22322e31222c226e616d657370616365223a22676c6f62616c222c226d6574686f64223a2274785f73656e645472616e73616374696f6e222c22706172616d73223a5b7b2274696d657374616d70223a313539363532353139333035333134363137392c22746f223a22307837393442463031414233443337444632443145413141413445364634413045393838463444454135222c2273696d756c617465223a66616c73652c226e6f6e6365223a333733383436333337323535343837382c2276616c7565223a35332c2266726f6d223a22307838353645324239413546413832464431423033314431464636383633383634444241433739393544222c2274797065223a225452414e53464552222c227369676e6174757265223a2230313034376561343634373632633333333736326433626538613034353336623232393535643937323331303632343432663831613363666634366362303039626264626230663330653631616465353730353235346434653465306330373435666233626136393030366434623337376638326563656330356564303934646265383733303435303232313030626232613638656162316464663664386639313536376333383466306262303466653936666337323633613863373335366130633062336439636262326639633032323037363566343766626437643933376533613838343336613462326135623132316238636661333839333138616364616337353837313936313062343863626561227d5d2c226964223a317d"
	sign := "304502207355ed473e7db7008d5bdf68fcbf835bd288cbe7968845f212586860bf04880e022100bb4c94e192981e245921651faef7453961009a2f35c71591de18bab571307698"

	pubByte, _ := hex.DecodeString(pubkey)
	msgByte, _ := hex.DecodeString(msg)
	signByte, _ := hex.DecodeString(sign)

	h, _ := hash.NewHasher(hash.SHA2_256).Hash(msgByte)

	k := new(ECDSAPublicKey)
	assert.Nil(t, k.FromBytes(pubByte, AlgoP256K1))
	b, err := k.Verify(nil, signByte, h)
	assert.Nil(t, err)
	assert.True(t, b)
}

func TestECDSA_R1(t *testing.T) {
	key := "3e83c9cd9a39bf96d1f77a978e1fb32be0ad1732eee157011e162e9749b2e90a"
	msg := "hello"
	keyBytes, _ := hex.DecodeString(key)

	sk := new(ECDSAPrivateKey)
	assert.Nil(t, sk.FromBytes(keyBytes, AlgoP256R1))
	pub, ok := sk.Public().(*ECDSAPublicKey)
	assert.True(t, ok)
	pubBytes, _ := pub.Bytes()

	h, _ := hash.NewHasher(hash.KECCAK_256).Hash([]byte(msg))
	sign, _ := NewECDSA(AlgoP256R1).Sign(keyBytes, h, rand.Reader)
	b, err := NewECDSA(AlgoP256R1).Verify(pubBytes, sign, h)
	assert.Nil(t, err)
	assert.True(t, b)
}

func TestBytesAndFromBytes(t *testing.T) {
	key := "3e83c9cd9a39bf96d1f77a978e1fb32be0ad1732eee157011e162e9749b2e90a"
	keyBytes, _ := hex.DecodeString(key)
	priv := new(ECDSAPrivateKey)
	assert.Nil(t, priv.FromBytes(keyBytes, AlgoP256R1))
	pub, ok := priv.Public().(*ECDSAPublicKey)
	assert.True(t, ok)
	tmp, err := priv.Bytes()
	assert.Nil(t, err)
	assert.Equal(t, tmp, keyBytes)
	newPriv := new(ECDSAPrivateKey)
	assert.Nil(t, newPriv.FromBytes(keyBytes, AlgoP256R1))
	assert.True(t, priv.D.Cmp(newPriv.D) == 0)

	tmp2, err := pub.Bytes()
	assert.Nil(t, err)

	newPub := new(ECDSAPublicKey)
	assert.Nil(t, newPub.FromBytes(tmp2, AlgoP256R1))
	assert.True(t, pub.X.Cmp(newPub.X) == 0)
	assert.True(t, pub.Y.Cmp(newPub.Y) == 0)
}

func TestBytesAndFromBytes2(t *testing.T) {
	keyBytes := make([]byte, 32)
	_, _ = rand.Read(keyBytes)
	keyBytes[0] = 0
	priv := new(ECDSAPrivateKey)
	assert.Nil(t, priv.FromBytes(keyBytes, AlgoP256R1))
	pub, ok := priv.Public().(*ECDSAPublicKey)
	assert.True(t, ok)
	tmp, err := priv.Bytes()
	assert.Nil(t, err)
	assert.Equal(t, tmp, keyBytes)
	newPriv := new(ECDSAPrivateKey)
	assert.Nil(t, newPriv.FromBytes(keyBytes, AlgoP256R1))
	assert.True(t, priv.D.Cmp(newPriv.D) == 0)

	tmp2, err := pub.Bytes()
	assert.Nil(t, err)

	newPub := new(ECDSAPublicKey)
	assert.Nil(t, newPub.FromBytes(tmp2, AlgoP256R1))
	assert.True(t, pub.X.Cmp(newPub.X) == 0)
	assert.True(t, pub.Y.Cmp(newPub.Y) == 0)
}

func BenchmarkSignK1(t *testing.B) {
	priv, err := GenerateKey(AlgoP256K1)
	assert.Nil(t, err)
	for i := 0; i < t.N; i++ {
		t.StartTimer()
		h, err := hash.NewHasher(hash.KECCAK_256).Hash(msg)
		assert.Nil(t, err)
		bytes, _ := priv.Bytes()
		assert.NotNil(t, bytes)
		sign, err := priv.Sign(nil, h, rand.Reader)
		t.StopTimer()
		assert.Nil(t, err)
		assert.NotEqual(t, nil, sign)
		pub, ok := priv.Public().(*ECDSAPublicKey)
		assert.True(t, ok)
		if b, err := pub.Verify(nil, sign, h); !b || err != nil {
			t.Error("fail")
		}
	}
}

func BenchmarkVerifyK1(t *testing.B) {
	priv, err := GenerateKey(AlgoP256K1)
	assert.Nil(t, err)
	for i := 0; i < t.N; i++ {
		h, err := hash.NewHasher(hash.KECCAK_256).Hash(msg)
		assert.Nil(t, err)
		bytes, _ := priv.Bytes()
		assert.NotNil(t, bytes)
		sign, err := priv.Sign(nil, h, rand.Reader)
		assert.Nil(t, err)
		assert.NotEqual(t, nil, sign)
		pub, ok := priv.Public().(*ECDSAPublicKey)
		assert.True(t, ok)
		t.StartTimer()
		h2, err := hash.NewHasher(hash.KECCAK_256).Hash(msg)
		assert.Nil(t, err)
		b, err := pub.Verify(nil, sign, h2)
		t.StopTimer()
		assert.Nil(t, err)
		assert.True(t, b)
	}
}

func BenchmarkSignR1(t *testing.B) {
	priv, err := GenerateKey(AlgoP256R1)
	assert.Nil(t, err)
	for i := 0; i < t.N; i++ {
		t.StartTimer()
		h, err := hash.NewHasher(hash.KECCAK_256).Hash(msg)
		assert.Nil(t, err)
		sign, err := priv.Sign(nil, h, rand.Reader)
		t.StopTimer()
		assert.Nil(t, err)
		assert.NotNil(t, sign)
		pub, ok := priv.Public().(*ECDSAPublicKey)
		assert.True(t, ok)
		b, err := pub.Verify(nil, sign, h)
		assert.Nil(t, err)
		assert.True(t, b)
	}
}

func BenchmarkVerifyR1(t *testing.B) {
	priv, err := GenerateKey(AlgoP256R1)
	assert.Nil(t, err)
	for i := 0; i < t.N; i++ {
		h, err := hash.NewHasher(hash.KECCAK_256).Hash(msg)
		assert.Nil(t, err)
		sign, err := priv.Sign(nil, h, rand.Reader)
		assert.Nil(t, err)
		assert.NotNil(t, sign)
		pub, ok := priv.Public().(*ECDSAPublicKey)
		assert.True(t, ok)
		t.StartTimer()
		h2, err := hash.NewHasher(hash.KECCAK_256).Hash(msg)
		assert.Nil(t, err)
		b, err := pub.Verify(nil, sign, h2)
		t.StopTimer()
		assert.Nil(t, err)
		assert.True(t, b)
	}
}

func TestJudge(t *testing.T) {
	priv, err := GenerateKey(AlgoP256R1)
	assert.Nil(t, err)
	assert.Equal(t, AlgoP256R1, priv.AlgorithmType())
	priv, err = GenerateKey(AlgoP256K1)
	assert.Nil(t, err)
	assert.Equal(t, AlgoP256K1, priv.AlgorithmType())
	pub, ok := priv.Public().(*ECDSAPublicKey)
	assert.True(t, ok)
	assert.Nil(t, err)
	assert.NotNil(t, pub)
}

func TestSetPublicKey(t *testing.T) {
	for i := 0; i < 99; i++ {
		priv, err := GenerateKey(AlgoP256K1)
		assert.Nil(t, err)
		bs, err := priv.Bytes()
		assert.Nil(t, err)
		privKey := new(ECDSAPrivateKey)
		assert.Nil(t, privKey.FromBytes(bs, AlgoP256K1))
		pub, ok := priv.Public().(*ECDSAPublicKey)
		assert.True(t, ok)
		privKey = privKey.SetPublicKey(pub)
		pubKey, ok := priv.Public().(*ECDSAPublicKey)
		assert.True(t, ok)
		assert.Equal(t, pub, pubKey)
	}
}

func TestRecover(t *testing.T) {
	/*
		只有验签r1k账户实际使用recover并配合address验证，其他如msp中证书等都是用asn1模式
		有可能早期k1证书中的证书签名是revcover的，因此需要兼容
		txgen中已经修改为k1证书对应k1r账户

		关于地址计算，ECDSA的都是remove04的
	*/
	h, _ := hex.DecodeString("c336dd3813da656a8ff31136a163809eaaf762cc5445b8de8299489301486009")
	priv, err := GenerateKey(AlgoP256K1Recover) //这里传入AlgoP256K1或AlgoP256K1Recover效果是一样的
	assert.Nil(t, err)
	sign, err := priv.Sign(nil, h, rand.Reader)
	assert.Nil(t, err)
	assert.Equal(t, 65, len(sign))

	//你可能是从其他途径获得的地址，但是这里用这种方式也可以计算出地址
	pub, _ := priv.Public().(*ECDSAPublicKey)
	address, perr := pub.Bytes()
	assert.Nil(t, perr)

	//下面是你关心的怎么用通过地址、hash和签名三种数据来完成验签
	recoverPub := new(ECDSAPublicKey)
	assert.Nil(t, recoverPub.FromBytes(address, AlgoP256K1Recover))
	b, rerr := recoverPub.Verify(nil, sign, h)
	assert.Nil(t, rerr)
	assert.True(t, b)

	t.Run("non recover", func(t *testing.T) {
		privNR, _ := GenerateKey(AlgoP256K1)
		signNR, _ := privNR.Sign(nil, h, rand.Reader)
		recoverPubNR := new(ECDSAPublicKey)
		pk, _ := privNR.ECDSAPublicKey.Bytes()
		assert.Nil(t, recoverPubNR.FromBytes(pk, AlgoP256K1))
		r, errNR := recoverPubNR.Verify(nil, signNR, h)
		assert.Nil(t, errNR)
		assert.True(t, r)
	})

	t.Run("address with AlgoP256K1", func(t *testing.T) {
		recoverPub = new(ECDSAPublicKey)
		assert.Equal(t, 20, len(address))
		assert.Nil(t, recoverPub.FromBytes(address, AlgoP256K1))
		assert.Equal(t, true, recoverPub.recover)
		assert.Nil(t, recoverPub.FromBytes(get65BytesPub(pub.X, pub.Y, 256), AlgoP256K1))
		_, rerr = recoverPub.Verify(nil, sign, h)
		assert.Nil(t, rerr) // recoverPub应该是recover的，但是错误的传入了非recover的模式
	})

	t.Run("asn1 with recover", func(t *testing.T) {
		priv, err = GenerateKey(AlgoP256K1) //这里传入AlgoP256K1或AlgoP256K1Recover效果是一样的
		assert.Nil(t, err)
		sign, err = priv.Sign(nil, h, rand.Reader) //r,s经过编码，之后是72bytes
		assert.Nil(t, err)

		//你可能是从其他途径获得的地址，但是这里用这种方式也可以计算出地址
		pub, ok := priv.Public().(*ECDSAPublicKey)
		assert.True(t, ok)
		pk, perr := pub.Bytes()
		assert.Nil(t, perr)

		//下面是你关心的怎么用通过地址、hash和签名三种数据来完成验签
		recoverPub = new(ECDSAPublicKey)
		assert.Nil(t, recoverPub.FromBytes(pk, AlgoP256K1Recover)) //non recover
		_, rerr = recoverPub.Verify(nil, sign, h)
		assert.Nil(t, rerr)
	})
}

func TestRecover2(t *testing.T) {
	//{"address":"ec24bd2c319463b5fa10cb829ebc95de6520c2fe","algo":"0x03","encrypted":"3e83c9cd9a39bf96d1f77a978e1fb32be0ad1732eee157011e162e9749b2e90a","version":"2.0"}
	privateFromJSON := "3e83c9cd9a39bf96d1f77a978e1fb32be0ad1732eee157011e162e9749b2e90a"
	addrFromJSON := "ec24bd2c319463b5fa10cb829ebc95de6520c2fe"
	addr, _ := hex.DecodeString(addrFromJSON)
	//calculate publicKey and compare
	privateBytes, _ := hex.DecodeString(privateFromJSON)
	privKey := new(ECDSAPrivateKey)
	assert.Nil(t, privKey.FromBytes(privateBytes, AlgoP256K1Recover))
	privKey.CalculatePublicKey()

	helloDigt, err := hash.NewHasher(hash.KECCAK_256).Hash([]byte("hello\n"))
	assert.Nil(t, err)
	s, err := privKey.Sign(nil, helloDigt, rand.Reader)
	assert.Nil(t, err)
	v := new(ECDSAPublicKey)
	assert.Nil(t, v.FromBytes(addr, AlgoP256K1Recover))
	_, err = v.Verify(nil, s, helloDigt)
	assert.Nil(t, err)

	_, err = v.Bytes()
	assert.NotNil(t, err)

}

var testAddrHex = "970e8128ab834e8eac17ab8e3812f010678cf791"
var testPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"

func TestRecover3(t *testing.T) {
	key, _ := hex.DecodeString(testPrivHex)
	addr, _ := hex.DecodeString(testAddrHex)

	privateKey := new(ECDSAPrivateKey)
	assert.Nil(t, privateKey.FromBytes(key, AlgoP256K1Recover))

	//sign
	h, _ := hash.NewHasher(hash.KECCAK_256).Hash([]byte("foo"))
	sig, err := privateKey.Sign(nil, h, rand.Reader)
	if err != nil {
		t.Errorf("Sign error: %s", err)
	}

	//verify
	k := new(ECDSAPublicKey)
	assert.Nil(t, k.FromBytes(addr, AlgoP256K1Recover))
	b, verr := k.Verify(nil, sig, h)
	assert.True(t, b)
	assert.Nil(t, verr)
}

func TestRecover4(t *testing.T) {
	for i := 1000; i > 0; i-- {
		privateKey, err := GenerateKey(AlgoP256K1Recover)
		assert.Nil(t, err)
		pub, ok := privateKey.Public().(*ECDSAPublicKey)
		assert.True(t, ok)

		addr, err := pub.Bytes()
		assert.Nil(t, err)

		//sign
		msg, _ := hash.NewHasher(hash.KECCAK_256).Hash([]byte("foo"))
		sig, err := privateKey.Sign(nil, msg, rand.Reader)
		if err != nil {
			t.Errorf("Sign error: %s", err)
		}

		//verify
		tmpKey := new(ECDSAPublicKey)
		assert.Nil(t, tmpKey.FromBytes(addr, AlgoP256K1Recover))
		b, _ := tmpKey.Verify(nil, sig, msg)
		if !b {
			privBytes, _ := privateKey.Bytes()
			t.Log("vk")
			t.Log(hex.EncodeToString(privBytes))
			t.Log("addr")
			t.Log(hex.EncodeToString(addr))
			t.Fail()
		}
		if err != nil {
			t.Log(err)
		}
	}
}

func BenchmarkSecp256k1_add(B *testing.B) {
	r1 := make([]byte, 32)
	r2 := make([]byte, 32)
	_, _ = rand.Read(r1)
	_, _ = rand.Read(r2)
	c := secp256k1.S256()
	x1, y1 := c.ScalarBaseMult(r1)
	x2, y2 := c.ScalarBaseMult(r2)
	for i := 0; i < B.N; i++ {
		c.Add(x1, y1, x2, y2)
	}
}

func TestAsn1(t *testing.T) {

}
