package genrsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/rand"
	"fmt"
	"os"
)

func Key() (crypto.PrivateKey, crypto.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	publicKey := &privateKey.PublicKey

	return privateKey, publicKey
}