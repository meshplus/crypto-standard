package asym

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestGenerateKey(t *testing.T) {
	for i := 0; i < 5; i++ {
		key, err := GenerateKey(AlgoP256K1)
		assert.Nil(t, err)
		fmt.Println("private key:", hex.EncodeToString(key.D.Bytes()))
		fmt.Println("public key:", hex.EncodeToString(key.X.Bytes()), hex.EncodeToString(key.Y.Bytes()))
	}
}

func TestECDSA_Sign(t *testing.T) {
	type fields struct {
		Opt AlgorithmOption
	}
	type args struct {
		k      string
		digest string
		reader string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{"ecdsaTestCase1",
			fields{AlgoP256K1},
			args{"5C37B54A4FBBB17FEE1A428922371AE45CF138F8B436EC239D08C9C97F8D2FD4",
				"a3f91ae21ba6b3039864472f184144c6af62cd0e",
				"A3B775CB1CFB8A7D3D340F01E6C9B2A7C0975118C089D6544A445418EB2ECE3F"},
			false},
		{"ecdsaTestCase2",
			fields{AlgoP256K1},
			args{"AB4D075BB3FC70AD3B7A55842BDFABB59A6128E05247259ADE04AA718E0539AF",
				"cb0abc7043a10783684556fb12c4154d57bc31a289685f25",
				"651A7291F9E635320EA0B59733F4D39E6143B79E713D75E58E01A354A8B1229D"},
			false},
		{"ecdsaTestCase3",
			fields{AlgoP256K1},
			args{"77D240D20DBA9C6678FF13995D6C58016309E56BBA1DCA0EFD0A95F7537E9E50",
				"902b55b79c29c0de27386e4fadb3469fc124f1225ad0fac06bd4a3a1e351c09e",
				"94DD9A7D92C4D50DB3C3485DFDD7792DCF924AB15393AA4B805B1033BBA17CB4"},
			false},
		{"ecdsaTestCase4",
			fields{AlgoP256K1},
			args{"1ED4826DAD1567B9F3000021BCC239403913C54EE01D2E13539E56B0EE1802B7",
				"99a83d5d6471963d",
				"9AD61D7B80F1D832E9DC3F12ECA9CD1595D77617BAB440B34A83A8BECB0DD32E"},
			false},
		{"ecdsaTestCase5",
			fields{AlgoP256K1},
			args{"A15E1788AEB388B31D8C847FD76D84EC30710FEA8E9BCE06B123D3F2F0CF7127",
				"9832832c49754bdeba2d3799cbf6437af28ad9f942d3f313abd320fad0897be6",
				"95423725D8DB01987197778E6E6A9B9D4F3B2771F20CF46F3F1479FDA8016306"},
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyBytes, _ := hex.DecodeString(tt.args.k)
			rand, _ := hex.DecodeString(tt.args.reader)
			hash, _ := hex.DecodeString(tt.args.digest)
			skey := new(ECDSAPrivateKey).FromBytes(keyBytes, AlgoP256K1)
			key := new(ecdsa.PrivateKey)
			key.D = new(big.Int).Set(skey.D)
			key.PublicKey.Curve = skey.Curve
			r, s, _ := ecdsa.Sign(bytes.NewReader(rand), key, hash)
			fmt.Println("sig: ", hex.EncodeToString(r.Bytes())+hex.EncodeToString(s.Bytes()))
			ecdsaKey := &ecdsa.PublicKey{Curve: skey.Curve, X: skey.X, Y: skey.Y}
			gotValid := ecdsa.Verify(ecdsaKey, hash, r, s)
			assert.True(t, gotValid)
		})
	}
}

func TestECDSA_Verify(t *testing.T) {
	type fields struct {
		Opt AlgorithmOption
	}
	type args struct {
		k         string
		signature string
		digest    string
	}
	tests := []struct {
		name      string
		fields    fields
		args      args
		wantValid bool
		wantErr   bool
	}{
		{"ecdsaVerify1",
			fields{AlgoP256K1},
			args{"229B43D5C2376962C9D4A2611707329D9C1C7DDF2A8E45B952C27503B8B579A71B654E80CD2DE184724106E08702680A716D79BC5A770D1808A0B544CF75B150",
				"404A5AB63C044AED06EA5198BB33A32912FC5BC9E7BC404D8FEA8744456E9D7833503CFB2418096C60BA992228B9F6DCED682B4D28A04A90F7AB84040F969882",
				"d856d257f6161c3236357b174560bcf21a00bdfb"},
			false, false},
		{"ecdsaVerify2",
			fields{AlgoP256K1},
			args{"9A64BD19CD93F9D6EC66DAACA1C28EF5001987EE78CF048B93C13BECFF9250AD120E54FA3EDEE1A54FB8498AE14CC9F418780B10A3032378F9A2545E5C7446A7",
				"C629577897E4E2AF4423F0E95BBC4EBAB6F95B9D3599ACD797D11C7E02E35EE536DA1F226CC2FBEA5D267E13EF8958293CC3D48A7E2FBEFFB233376707956153",
				"98de785daacf01567362273f54b1a1044259a9e9"},
			true, false},
		{"ecdsaVerify3",
			fields{AlgoP256K1},
			args{"A99607C5FF6627AB18CC68DE0E1EE80BBED1DD914F9370137AA035DA141295EC65F471D97932C9D0A257858CB4099560B0979F2C4F6C4F9D62F06E31A7597C18",
				"A8EBF6701D333731762E54036103E0CC2F179B704F95F48409C45A737009091972D9A85287DADDAE4E0B92D1D4113EAA7B120CA3F143739BAEC0739386E138BD",
				"e537383a08a421bf1f29"},
			true, false},
		{"ecdsaVerify4",
			fields{AlgoP256K1},
			args{"4FCF89416F8C0C6B7750F29F556D168D5B7F23FB9334327F7E19D6481013C03B3F657F5C776517F02B6128AFC86C848C6C8FFFA0426ED3A11D36FCAE86875BA1",
				"7E4D23C9B474DEC37B7F9C5160F97876BF7B51507F0BA65EF95D930CD8160081E5C6B6907EA12D3B1A42CB426E2E7ED705A0EC55D9E21E92C812D2EDDB54626B",
				"ba5374541c13597bded6880849184a593d69d3d4f0b1cb4d0919cbd6"},
			true,
			false},
		{"ecdsaVerify5",
			fields{AlgoP256K1},
			args{"89F1E9EDF62130509C176635EE182CEEA452472D3CF789CECF8996F52D0BDE3DD045A7DC69B9F8C7CB7411D29A771C9438BAB780B230B56042511F1108E87361",
				"FD911D2AFB0EDC7366B3B9513CB0EF824E50B10E330EDDFAD43BBB0286EE303C14995EBCD23E1B0CBAF98F9A31AB479E02D3978E47B88A6216C88848B28AC703",
				"a66d9e00819d8c1cca5bc0d75e4e05477c1fcbff"},
			true,
			false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sv := &ECDSA{
				Opt: tt.fields.Opt,
			}
			key := make([]byte, 1, 65)
			key[0] = 0x04
			keyBytes, _ := hex.DecodeString(tt.args.k)
			key = append(key, keyBytes...)
			k := new(ECDSAPublicKey).FromBytes(key, sv.Opt)

			sig, _ := hex.DecodeString(tt.args.signature)
			digest, _ := hex.DecodeString(tt.args.digest)
			ecdsaKey := &ecdsa.PublicKey{Curve: k.Curve, X: k.X, Y: k.Y}
			gotValid := ecdsa.Verify(ecdsaKey, digest, new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
			if gotValid != tt.wantValid {
				t.Errorf("Verify() gotValid = %v, want %v", gotValid, tt.wantValid)
			}
		})
	}
}
