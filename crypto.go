package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
)

//CheckMAC 检查MAC是否正确
func CheckMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

//Aes256Decrypt aes解密
func Aes256Decrypt(password []byte, encrypted []byte) ([]byte, error) {
	key := sha256.Sum256(password)
	// log.Println("key len:", len(key))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	iv := key[:blockSize]
	// log.Println("iv len:", len(iv))
	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(encrypted))
	// origData := crypted
	blockMode.CryptBlocks(origData, encrypted)
	origData = PKCS5UnPadding(origData)
	// origData = ZeroUnPadding(origData)
	return origData, nil
}

//Aes256Encrypt aes加密
func Aes256Encrypt(password []byte, plain []byte) ([]byte, error) {
	key := sha256.Sum256(password)
	// log.Println("key len:", len(key))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	iv := key[:blockSize]
	// log.Println("iv len:", len(iv))
	blockMode := cipher.NewCBCEncrypter(block, iv)
	origData := PKCS5Padding(plain, blockSize)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//EncryptPrivateKey 加密私钥
func EncryptPrivateKey(pemPath, fileName string, password []byte) error {
	data, err := ioutil.ReadFile(pemPath)
	if err != nil {
		return err
	}
	block2, _ := pem.Decode(data)
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", block2.Bytes, password, x509.PEMCipherAES256)
	if err != nil {
		return err
	}
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}

//DecryptPrivateKey 解密私钥
func DecryptPrivateKey(pemPath string, password []byte) (*rsa.PrivateKey, error) {
	encrypted, err := ioutil.ReadFile(pemPath)
	b, _ := pem.Decode(encrypted)
	clear, err := x509.DecryptPEMBlock(b, password)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(clear) //解析成RSA私钥
}

//ParsePublicKey 从pem文件获取公钥
func RetrievePublicKey(pemPath string) (*rsa.PublicKey, error) {
	data, err := ioutil.ReadFile(pemPath)
	block, _ := pem.Decode(data)
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pubKey.(*rsa.PublicKey), nil
}

//GenRsaKey 生成RSA秘钥
func GenRsaKey(bits int) error {
	// 生成私钥文件
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	file, err = os.Create("public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}
	return nil
}
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize //需要padding的数目
	//只要少于256就能放到一个byte中，默认的blockSize=16(即采用16*8=128, AES-128长的密钥)
	//最少填充1个byte，如果原文刚好是blocksize的整数倍，则再填充一个blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding) //生成填充的文本
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding) //用0去填充
	return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
	return bytes.TrimFunc(origData,
		func(r rune) bool {
			return r == rune(0)
		})
}
