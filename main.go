package main

import (
	"bytes"
	"crypto/des"
	"crypto/cipher"
	"fmt"
	"encoding/base64"
)

/**
补码
 */
func PCKS5Padding(orgData []byte, blockSize int) []byte {
	padding := blockSize - len(orgData)%8
	padtxt := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(orgData, padtxt...)
}

/**
去码
 */
func PCKS5UNPadding(cipherTxt []byte) []byte {
	length := len(cipherTxt)
	unpadding := int(cipherTxt[length-1])
	return cipherTxt[:length-unpadding]
}

/**
DES加密，加密用到补码
 */
func DesEncrypt(orig []byte, key []byte) []byte {
	//首先校验秘钥是否合法
	//DES加密算法，秘钥的长度必须为8bit
	cipherBlock, _ := des.NewCipher(key)
	//补码
	origData := PCKS5Padding(orig, cipherBlock.BlockSize())
	//设置加密方式
	blockMode := cipher.NewCBCEncrypter(cipherBlock, key)
	//加密处理
	crypted := make([]byte, len(origData)) //存放加密后的秘文
	blockMode.CryptBlocks(crypted, origData)
	return crypted
}

/**
DES解密，解密需要用到去码
 */
func DesDecrypt(cipherTxt []byte, key []byte) []byte {
	//校验key的有效性
	cipherBlock, _ := des.NewCipher(key)
	//设置解码方式
	blockmode := cipher.NewCBCDecrypter(cipherBlock, key)
	//创建缓冲，存放解密后的数据
	origData := make([]byte, len(cipherTxt))
	blockmode.CryptBlocks(origData, cipherTxt)
	//去码
	origData = PCKS5UNPadding(origData)
	return origData

}

const cryptKey = "11111111";

func main() {
	//pad := PCKS5Padding([]byte("abcdefg"), 8)
	//fmt.Println(pad)
	//
	//pads := PCKS5UNPadding(pad)
	//fmt.Println(string(pads))

	cipherTxt := DesEncrypt([]byte("test desEncrypt"), []byte(cryptKey))
	fmt.Println(cipherTxt)

	//base64处理秘文
	fmt.Println(base64.StdEncoding.EncodeToString(cipherTxt))

	plainTxt := DesDecrypt(cipherTxt, []byte(cryptKey))
	fmt.Println(string(plainTxt))
	//对称加密中，加密和解密是互逆的
	//DES加密中，秘钥长度必须为8bit
	//3DES加密中，秘钥长度必须为24bit（DES加密，解密，加密）
	//AES加密中，秘钥长度必须为16或24或32bit
}
