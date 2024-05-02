package main

import (
	"fmt"

	"github.com/tech-thinker/grpc-decoder/decoder"
)

func main() {
	iv := ""             // It should be iv, recived in browser network tab
	data := []byte{}     // It should be bytes that got from response of Network Tab in Browser
	aes_passphrase := "" // It will be aes passphrase for decryption
	decoder := decoder.NewDecoder(aes_passphrase)
	decryptedText, err := decoder.Decode(iv, data)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(decryptedText)
}
