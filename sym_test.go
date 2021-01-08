package inter

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	hash2 "github.com/meshplus/crypto-standard/hash"
	"github.com/stretchr/testify/assert"
	"os"
	"os/exec"
	"testing"
)

const msg = `Qulian Technology is an international leading blockchain team with all core team members graduated from Zhejiang University, Tsinghua University and other first-class universities at home and abroad, and Academician Chen Chun of the Chinese Academy of Engineering acted as chairman of the board. The company has a team of nearly 200 people, 90% of whom are technicians, more than 10 have doctoral degrees and 140 have master's degrees. The core competitiveness of the company is Hyperchain bottom technology platform. This platform ranks first in the technical evaluation of several large and medium-sized financial institutions. It is also the first batch of bottom platforms to pass the Blockchain Standard Test of the China Electronics Standardization Institute (CESI) and China Academy of Information and Communications Technology (CAICT) of Ministry of Industry and Information Technology (MIIT). It has applied for 28 patents in blockchain related fields.`

func TestAES(t *testing.T) {
	aes := new(AES)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	_, err := aes.Encrypt(key, []byte(msg), rand.Reader)
	assert.Nil(t, err)
	c, err := aes.Encrypt(AESKey(key), []byte(msg), rand.Reader)
	assert.Nil(t, err)
	_, err = aes.Decrypt(key, c)
	assert.Nil(t, err)
	o, err := aes.Decrypt(key, c)
	if err != nil {
		t.Error(err)
	}
	if msg != string(o) {
		t.Error("fail")
	}
}

func TestAES2(t *testing.T) {
	aes := new(AES)
	key := make([]byte, 12)
	_, _ = rand.Read(key)
	_, err := aes.Encrypt(AESKey(key), []byte(msg), rand.Reader)
	if err == nil {
		t.Error()
	}
}

func Test3DES(t *testing.T) {
	des3 := new(TripleDES)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	_, err := des3.Encrypt(key, []byte(msg), rand.Reader)
	assert.Nil(t, err)
	c, err := des3.Encrypt(key, []byte(msg), rand.Reader)
	assert.Nil(t, err)
	_, err = des3.Decrypt(key, c)
	assert.Nil(t, err)
	o, err := des3.Decrypt(key, c)
	if err != nil {
		t.Error(err)
	}
	if msg != string(o) {
		t.Error("fail")
	}
}

func Test3DES2(t *testing.T) {
	aes := new(TripleDES)
	key := make([]byte, 12)
	_, _ = rand.Read(key)
	_, err := aes.Encrypt(TripleDESKey(key), []byte(msg), rand.Reader)
	if err == nil {
		t.Error()
	}
}

func BenchmarkAES(b *testing.B) {
	aes := new(AES)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		c, err := aes.Encrypt(key, []byte(msg), rand.Reader)
		assert.Nil(b, err)
		o, err := aes.Decrypt(key, c)
		if err != nil {
			b.Error(err)
		}
		b.StopTimer()
		if msg != string(o) {
			b.Error("fail")
		}
	}

}

func Benchmark3DES(b *testing.B) {
	des3 := new(TripleDES)
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	for i := 0; i < b.N; i++ {
		b.StartTimer()
		c, err := des3.Encrypt(TripleDESKey(key), []byte(msg), rand.Reader)
		assert.Nil(b, err)
		o, err := des3.Decrypt(TripleDESKey(key), c)
		if err != nil {
			b.Error(err)
		}
		b.StopTimer()
		assert.Equal(b, msg, string(o))
	}
}

func TestTripleDesEncrypt8(t *testing.T) {
	key := make([]byte, 24)
	c, err := TripleDesEncrypt8([]byte(msg), key)
	assert.Nil(t, err)
	s, err := TripleDesDecrypt8(c, key)
	assert.Nil(t, err)
	assert.Equal(t, []byte(msg), s)
}

func TestKey(t *testing.T) {
	des3 := TripleDESKey(make([]byte, 32))
	des3.FromBytes(bytes.Repeat([]byte{1}, 32), nil)
	temp, err := des3.Bytes()
	assert.Nil(t, err)
	assert.Equal(t, temp, []byte(des3))
}

func TestKey2(t *testing.T) {
	aes := AESKey(make([]byte, 32))
	aes.FromBytes(bytes.Repeat([]byte{1}, 32), nil)
	temp, err := aes.Bytes()
	assert.Nil(t, err)
	assert.Equal(t, temp, []byte(aes))
}

func TestName(t *testing.T) {
	msg := `To be or not to be,that's a question.`
	aesKey := AESKey("12345678123456781234567812345678")
	aes := new(AES)
	cipher, err := aes.Encrypt(aesKey, []byte(msg), rand.Reader)
	fmt.Println(base64.URLEncoding.EncodeToString(cipher))
	if err != nil {
		//handle error
	}
	t.Log(len(cipher))
	_, err = aes.Decrypt(aesKey, cipher)
	assert.Nil(t, err)
}

func creatFile() error {
	_, err := os.Create("./in")
	if err != nil {
		return err
	}
	_, err = os.Create("./out")
	return err
}
func removeFile() {
	_ = os.Remove("./in")
	_ = os.Remove("./out")
}
func TestSHA3_256(t *testing.T) {
	type args struct {
		msg string
	}
	tests := []struct {
		name     string
		args     args
		wantHash string
	}{
		{"sha3-256TestCase1",
			args{"ABCD"},
			"0f1108bfb4ddb5cd6a8b05ad6dbc8244f0b0ef94cf77475a60a7bc952058425b"},
		{"sha3-256TestCase2",
			args{"507550364A00"},
			"042bc8585a5e7d8ad1a29cbda02ac84dafb11f6466eb0d8c85edc3b6b9c98358"},
		{"sha3-256TestCase3",
			args{"5F677D293D4B3038406E2A4C4E5E6774705A5B247D402B50294057227D5F4836A336A6C214A6D52234468345F2524795969522"},
			"88f2b4af8167089c81f6f230b07c05d6ee1144d026a8105a98705f6306b95476"},
		{"sha3-256TestCase4",
			args{"ABCD657170426B556E264C4C764A306C26574F72426C5471374C366E2377227B6259"},
			"1e613bf22ee0134284ca58ad41d7d6e624dd5cb697f208f015d26bbe04e5f035"},
		{"sha3-256TestCase5",
			args{"682A34516B2163505F49675D475B764A652A5842674F33453261365C75736936456F255B2B237674714D66303933696C7D425B"},
			"61a1def246f6a6c0d360dec785ecd7a579dcbb0665dec1e18195918cce14d1f6"},
	}
	err := creatFile()
	if err != nil {
		fmt.Println("can not creat file")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, _ := hex.DecodeString(tt.args.msg)
			hash := hash2.NewHasher(hash2.SHA3_256)
			gotHash, err := hash.Hash(msg)
			assert.Nil(t, err)
			if hex.EncodeToString(gotHash) != tt.wantHash {
				t.Errorf("Hash() gotHash = %s, want %s", hex.EncodeToString(gotHash), tt.wantHash)
				return
			}
			//compare result in openssl
			fmt.Println("hash :", hex.EncodeToString(gotHash))
			file, err := os.OpenFile("./in", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
			if err != nil {
				fmt.Println("can not open file")
				return
			}
			_, _ = file.Write(msg)
			cmd := exec.Command("/bin/sh", "-c", "openssl dgst -sha3-256  -out ./out ./in ")
			_, err = cmd.Output()
			if err != nil {
				fmt.Println(err)
				return
			}
			file, err = os.OpenFile("./out", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
			if err != nil {
				fmt.Println("can not open file", err)
				return
			}
			newdst := make([]byte, 80)
			_, err = file.Read(newdst)
			if err != nil {
				fmt.Println(err)
				return
			}
			if string(newdst[16:]) != hex.EncodeToString(gotHash) {
				t.Errorf("different result with openssl, openssl = %v, got=%s", string(newdst[11:]), hex.EncodeToString(gotHash))
			}
		})
	}
	removeFile()

}

func TestAesEnc(t *testing.T) {
	type args struct {
		key string
		iv  string
		src string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"aesEncCBC1",
			args{"999E2AA664352F3D1B5DE3A17BC4B83D5DBA0E1DFA37C844038D77A4D4FB35B3",
				"09b9bcd6a80841c1163dd1ea86fd86a1",
				"6B"},
			"122561983217b92bb17e30d05fbc6d03",
			false},
		{"aesEncCBC2",
			args{"70206495b43ee88cdd0486848bf5cfd3e6091ede5beaff16ce7803bbb5de95a8",
				"19041c2c0552d259914be574a8313ee1",
				"5b9f25370d4023f7b4ea44d57905e987"},
			"949c46ffc58da4167c548afe9a7cc17af5bbe101ed907bb75708376d87397417",
			false},
		{"aesEncCBC3",
			args{"b98f1dce690b64368a77bae409038239789840a08ca004ca3a2be270dbc0b2df",
				"2887bf96b2805cb3e1b3c79255677080",
				"36ec9c5c7c9280e20064a385b5ce62d9aa395b7d"},
			"a643d28ba87b500bef799e8b276ac83b8943b94c570431dcdf474a3ecc35583e",
			false},
		{"aesEncCBC4",
			args{"1f542c0c4ae6bf8a4c96dd7ae4fd01b9502c741196910bc2a1995cba3e89b502",
				"398a41593f50c33b815580c0bf52a141",
				"95d9d2f07d3eeb57fcc006dd8520d90eb2600a2f7c68114cc7add472557cde4a"},
			"3f7e669dce0be550d98b7209116fe9afc22b203424e1317e99cb6ea82a5c5c874c987b451e7ef002617af8ba21bd7dc8",
			false},
		{"aesEncCBC5",
			args{"3eaae9978a60c5655196dead4482eaa3e947fe3a5e03b8f651db1dde6a197cfc",
				"0d9fad69e07cb384880272745fd0138c",
				"da107873a8fc8266b3336fa0486fcd32085344f22a5955b8d8731a1a0007dc57959ad295ad"},
			"699632cebdb5f3a5955a681c44e49ac8d9737c9ee404188bd0a42ba63bdee9d80b0fafe795b410f14da2fa628e4efd4e",
			false},
	}
	err := creatFile()
	if err != nil {
		fmt.Println("can not creat file")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aes := new(AES)
			src, _ := hex.DecodeString(tt.args.src)
			key, _ := hex.DecodeString(tt.args.key)
			iv, _ := hex.DecodeString(tt.args.iv)
			dst, _ := aes.Encrypt(key, src, bytes.NewReader(iv))
			if hex.EncodeToString(dst[16:]) != tt.want {
				t.Errorf("aes encrypt faild got = %s, want = %s\n", hex.EncodeToString(dst[16:]), tt.want)
				return
			}
			// compare result in openssl
			file, err := os.OpenFile("./in", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
			if err != nil {
				fmt.Println("can not open file")
				return
			}
			_, _ = file.Write(src)
			cmd := exec.Command("/bin/sh", "-c", "openssl enc -aes-256-cbc -e -K "+tt.args.key+" -iv "+tt.args.iv+" -in ./in -out out")
			_, err = cmd.Output()
			if err != nil {
				fmt.Println("err:", err)
				return
			}
			file, err = os.OpenFile("./out", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
			if err != nil {
				fmt.Println("can not open file", err)
				return
			}
			newdst := make([]byte, len(dst)-16)
			_, err = file.Read(newdst)
			if err != nil {
				fmt.Println("err: ", err)
				return
			}
			if !bytes.Equal(newdst, dst[16:]) {
				t.Errorf("different result with openssl, openssl = %s, got=%s", hex.EncodeToString(newdst), hex.EncodeToString(dst[16:]))
			}
		})
	}
	removeFile()
}

func TestAesDec(t *testing.T) {
	type args struct {
		key string
		iv  string
		src string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"aesDecCBC1",
			args{"3a172586a53fc0c5a2d48a0e6971d5ce8511f6de527310ebeabb2124877cfed5",
				"11b373cfd3f1a747f0563222bf105f47",
				"B26E31934D511ABDA2F6D70CD1A3DA1E"},
			"4d48ff7bb60927", false},
		{"aesDecCBC2",
			args{"fba4b60702928a351788e90d1ba25ec1972da87b7eb9346539625a9954250b84",
				"1357d4a13f9e6c71e806094ce433d10e",
				"E988304040612C746676E85B814B051A7DAAD3F62860F82EC7AA073AFFA8EE75"},
			"1e6a36b3f4e2be20ea23542ed9310144",
			false},
		{"aesDecCBC3",
			args{"0b70187175a1b56ec1ee55b8f35bbd28a59e9404ed26e0d86c9c7604caadf495",
				"686d46d0c6cdbe91ce1e0449f6022ebf",
				"F35F551E26FAC67933DB6EE628B136C519D80310C64AE9F6F4E66379773EC9C3"},
			"0d6a2389e618b8af8119577bce3171d9cf10f1f4",
			false},
		{"aesDecCBC4",
			args{"323532577576fd3bd649ee3c2277e7b951412813b10cea098b429db31c6e1c12",
				"0da43214e2efb7892cc1ccde6723946d",
				"AC62F37C99CCA3F5C29831574C29A61CDF58B5B3529DAD1B79467488E0A5CDC569F4509C4513AC9C1876F56B3C941CAA"},
			"dafb6e42667c6a44fd7d8dfe3ded7bd9b982843e7882f6fc35d74d9eafff5cf7",
			false},
		{"aesDecCBC5",
			args{"67df45f8deea6de890514745386e13648a908cca18b3d9446f8574a87f35d900",
				"0e95db309f4305b621f51f93588a2678",
				"8C54052F0C5AB0B4CEE2FA2C47B9EBD9AB5F93F1F5340F20AED6BAFF33BA3B101825FAAF059E4DC3303D8B7593383775"},
			"1177eefc44b6070e2c41537e75c91e2f08908c0d950bc90cd2f4720b3350f751312dde55b1bcab", false},
	}
	err := creatFile()
	if err != nil {
		fmt.Println("can not creat file")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aes := new(AES)
			src, _ := hex.DecodeString(tt.args.src)
			key, _ := hex.DecodeString(tt.args.key)
			iv, _ := hex.DecodeString(tt.args.iv)
			newSrc := append(iv, src...)
			dst, err := aes.Decrypt(key, newSrc)
			assert.Nil(t, err)
			if hex.EncodeToString(dst) != tt.want {
				t.Errorf("aes decrypt faild got =%s, want=%s\n", hex.EncodeToString(dst), tt.want)
			}
			fmt.Println("plaintext :", hex.EncodeToString(dst))
			// compare result in openssl
			file, err := os.OpenFile("./in", os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0644)
			if err != nil {
				fmt.Println("can not open file")
				return
			}
			_, _ = file.Write(src)
			cmd := exec.Command("/bin/sh", "-c", "openssl enc -aes-256-cbc -d -K "+tt.args.key+" -iv "+tt.args.iv+" -in ./in -out out")
			_, err = cmd.Output()
			if err != nil {
				fmt.Println("err:", err)
				return
			}
			file, err = os.OpenFile("./out", os.O_CREATE|os.O_APPEND|os.O_RDWR, 0644)
			if err != nil {
				fmt.Println("can not open file", err)
				return
			}
			newdst := make([]byte, len(dst))
			_, err = file.Read(newdst)
			if err != nil {
				fmt.Println("err: ", err)
				return
			}
			if !bytes.Equal(newdst, dst) {
				t.Errorf("different result with openssl, openssl = %s, got=%s", hex.EncodeToString(newdst), hex.EncodeToString(dst[16:]))
			}
		})
	}
	removeFile()
}
