MIT License

Copyright (c) 2025 Elliot Michael Keavney

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

package aestext

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
)

func EncText(dataToEncrypt string, encryptionKey string) string {

	data := dataToEncrypt
	dataByte := []byte(data)
	aesKey := encryptionKey

	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		log.Fatal("error creating aes block cipher\n", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("error setting Galois/Counter Mode (GCM)\n", err)
	}

	numberOnce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, numberOnce); err != nil {
		log.Fatal("error generating the number once value\n", err)
	}

	cipherText := gcm.Seal(numberOnce, numberOnce, dataByte, nil)
	encryptedString := hex.EncodeToString(cipherText)

	return encryptedString
}

func DecText(dataToDecrypt string, decryptionKey string) string {

	encryptedString, err := hex.DecodeString(dataToDecrypt)
	if err != nil {
		log.Fatal("error decoding string\n", err)
	}

	aesKey := decryptionKey

	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		log.Fatal("error creating aes block cipher\n", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("error setting Galois/Counter Mode (GCM)\n", err)
	}

	numberOnceSize := gcm.NonceSize()
	numberOnce := encryptedString[:numberOnceSize]
	ciphertext := encryptedString[numberOnceSize:]

	decryptedString, err := gcm.Open(nil, []byte(numberOnce), []byte(ciphertext), nil)
	if err != nil {
		log.Fatal("error decrypting\n", err)
	}

	return string(decryptedString)
}
