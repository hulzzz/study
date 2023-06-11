package util

import (
	"bytes"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/blowfish"
)

func PaddingPKS5(data []byte, blocksize int) []byte {
	padding := blocksize - len(data)%blocksize
	paddText := bytes.Repeat([]byte{0}, padding)
	return append(data, paddText...)
}
func UnPaddingPKS5(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte{0}, []byte{})
}
func Encrypt(data, key []byte) (string, error) {
	cipher, err := blowfish.NewCipher(key)
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return "", errors.New("data is empty")
	}
	paddText := PaddingPKS5(data, cipher.BlockSize())
	result := make([]byte, 0, len(paddText))
	crypted := make([]byte, cipher.BlockSize())
	for len(paddText) > 0 {
		cipher.Encrypt(crypted, paddText[:cipher.BlockSize()])
		paddText = paddText[cipher.BlockSize():]
		result = append(result, crypted...)
	}
	str := base64.StdEncoding.EncodeToString(result)
	return str, nil
}
func Decrypt(data, key []byte) (string, error) {
	cipher, err := blowfish.NewCipher(key)
	if err != nil {
		return "", err
	}
	data, err = base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return "", err
	}
	crypted := make([]byte, cipher.BlockSize())
	result := make([]byte, 0, len(data))
	for len(data) > 0 {
		cipher.Decrypt(crypted, data[:cipher.BlockSize()])
		data = data[cipher.BlockSize():]
		result = append(result, crypted...)
	}
	result = UnPaddingPKS5(result)
	return string(result), nil
}
