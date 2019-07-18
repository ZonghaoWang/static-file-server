package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var publicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ZqzVABBeUkcGUeABmK4qbKsF
X90Q/vpxU0ddg+zi44EAYeMtDyEk0tSEfElyQeRrSBo5AFKSZG6QaJMJeRyW9bWm
ZQDnbyN7U2tHV/Jnddt04Bq2O8C3xcb+7rtllb0Hu5uw8voWqkTVHiKtwYTKQkzN
1aF4aq1jcD6WDHQ9xQIDAQAB
-----END PUBLIC KEY-----
`)
var privateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQC/ZqzVABBeUkcGUeABmK4qbKsFX90Q/vpxU0ddg+zi44EAYeMt
DyEk0tSEfElyQeRrSBo5AFKSZG6QaJMJeRyW9bWmZQDnbyN7U2tHV/Jnddt04Bq2
O8C3xcb+7rtllb0Hu5uw8voWqkTVHiKtwYTKQkzN1aF4aq1jcD6WDHQ9xQIDAQAB
AoGAY81pH6Pp5RTn/g6hTJPNdUe2oZXMEvmxo3f2RXfuBJz2fjmMmMlD0gyxTef0
8EQVlC9DpSda5wTBdkFhMlZZpiJ/WDyhJwAyTH+/arPEQGCYKxYEPro9se3JGkZV
78lo1xoPaDKQZfRIqtYe/ShgWaCEkH2ZpvWk970BgqZHo0ECQQDqQrd1VSkOb0Ps
dOkv2344bm/WxGPw/y6Rp23r+1CQ22HNtoOHT8EePk8iSADy4o2V3PWFg/a2TKAy
a0BD4lVRAkEA0SnAvNMVTdqHeANgdmlMnPVPqdIaHl/ZI71XE8iwTbMZ1dgn1vsv
DyA/YUPhdAe8jQwEE2tzCrsNZ8/3cnpUNQJAFMgyalBRwhwQ1ItSnJJGUk9J0K2/
iAO7Z+SIleTHsvIjbRKB/KEQqtQwRQRKQUHj+aWOine4jVei5pYpL1yG4QJAWQVx
P6yDU7hfkee2BY+5iNArkLaYYTcgHsL2LbhruRYyN76g7jHIDKMH9qjCavTj/hAQ
KAfCVd3YzcdIpNOFxQJACyIQ8zcFtgckVpmdRco1jrPwS3ohm1r/CnqtZX5opyVQ
184BfaBOcCJliNvJMxm/xpKjfrD9iar6rUlQ1v59dA==
-----END RSA PRIVATE KEY-----
`)

// 加密
func RsaEncrypt(origData []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

// 解密
func RsaDecrypt(ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}


func main()  {
	b, _ := RsaEncrypt([]byte("time=234958930&sign=megvii"))
	fmt.Printf("%x\n", b)
	b2, _ := RsaDecrypt(b)
	fmt.Println(string(b2))
}