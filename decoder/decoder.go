package decoder

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

type Decoder interface {
	Decode(iv string, data []byte) (string, error)
}

type decoder struct {
	AESPassphrase string
}

// NewDecoder(AESPassphrase string) It creates new object for decoder and returns object
func NewDecoder(AESPassphrase string) Decoder {
	return &decoder{
		AESPassphrase: AESPassphrase,
	}
}

// Decode(iv string, data []byte) (string, error) It will decode data prvided by grpc and returns decoded string, error
// input is iv in string and data in bytes
func (d *decoder) Decode(iv string, data []byte) (string, error) {
	pass, err := hex.DecodeString(d.AESPassphrase)
	if err != nil {
		return "", errors.New("decoding key is not valid")
	}

	ivBytes, err := hex.DecodeString(iv)
	if err != nil {
		return "", errors.New("iv is not valid")
	}

	content, err := decompress(data)
	if err != nil {
		return "", err
	}
	encryptedData, err := base64.StdEncoding.DecodeString(string(content))
	if err != nil {
		return "", err
	}
	passphrase := []byte(pass)
	decryptedText := aesDecrypt(ivBytes, encryptedData, []byte(passphrase))
	return string(decryptedText), nil

}

func decompress(data []byte) ([]byte, error) {
	datainbytes := bytes.NewReader(data)
	reader, err := gzip.NewReader(datainbytes)
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	decompressedData, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return decompressedData, nil
}

func aesDecrypt(iv, crypt, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("key error1", err)
	}
	if len(crypt) == 0 {
		fmt.Println("plain content empty")
	}
	ecb := cipher.NewCBCDecrypter(block, []byte(iv))
	decrypted := make([]byte, len(crypt))
	ecb.CryptBlocks(decrypted, crypt)
	return pKCS5Trimming(decrypted)
}

func pKCS5Trimming(encrypt []byte) []byte {
	padding := encrypt[len(encrypt)-1]
	return encrypt[:len(encrypt)-int(padding)]
}
