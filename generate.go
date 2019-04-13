package genrsa

import (
	"crypto/rsa"
	"crypto/rand"
	"fmt"
	"time"
	"math/big"
	"os"
	"encoding/pem"
	"crypto/x509"
	"io/ioutil"
)

const blockType = "RSA PRIVATE KEY"
const publicBlockType = "RSA PUBLIC KEY"

func Key(byteCount int) (*rsa.PrivateKey, *rsa.PublicKey) {
	fakewait(399)
	privateKey, err := rsa.GenerateKey(rand.Reader, byteCount)
	checkErr(err)
	fakewait(399)
	publicKey := &privateKey.PublicKey

	return privateKey, publicKey
}

func MakePrivatePublicFilePair(privateFile *os.File, publicFile *os.File, byteCount int) {
	private,public := Key(byteCount)
	writePrivate(privateFile, private)
	writePublic(publicFile, public)
}

func MakePrivateFile(file *os.File, byteCount int) {
	private,_ := Key(byteCount)
	writePrivate(file, private)
}

func writePrivate(file *os.File, privateKey *rsa.PrivateKey) {
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type: blockType,
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})
	file.Write(pemdata)
}

func writePublic(file *os.File, publicKey *rsa.PublicKey) {
	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type: publicBlockType,
			Bytes: x509.MarshalPKCS1PublicKey(publicKey),
		})
	file.Write(pemdata)
}

func PrivateKeysFromFile(file *os.File) []*rsa.PrivateKey {
	privateBytes,err := ioutil.ReadAll(file)
	checkErr(err)
	var keys []*rsa.PrivateKey = nil
	block, privateBytes := pem.Decode(privateBytes)
	for ; block != nil && block.Type == blockType; block, privateBytes = pem.Decode(privateBytes) {
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err == nil {
			keys = append(keys, privateKey)
		}
	}

	return keys
}

func PublicKeysFromFile(file *os.File) []*rsa.PublicKey {
	publicBytes,err := ioutil.ReadAll(file)
	checkErr(err)
	var keys []*rsa.PublicKey = nil
	block, publicBytes := pem.Decode(publicBytes)
	for ; block != nil && block.Type == publicBlockType; block, publicBytes = pem.Decode(publicBytes) {
		publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err == nil {
			keys=append(keys, publicKey)
		}
	}
	return keys
}

func PublicKeysFromPrivateFiles(file *os.File) []*rsa.PublicKey {
	privateKeys := PrivateKeysFromFile(file)
	var publicKeys []*rsa.PublicKey = nil
	for _,key := range privateKeys {
		publicKeys = append(publicKeys, &rsa.PublicKey{N: key.PublicKey.N, E: key.PublicKey.E})
	}
	return publicKeys
}

func checkErr(err error) {
	if err != nil {
		fmt.Println(err.Error())
		panic(err)
	}
}

func fakewait(fakemills int64) {
	bigNum, err := rand.Int(rand.Reader, big.NewInt(fakemills))
	checkErr(err)
	<-time.After(time.Duration(bigNum.Int64()) * time.Millisecond)
}