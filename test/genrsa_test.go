package genrsa_test

import (
	"testing"
	"github.com/Yomiji/genrsa"
	"os"
	bytes2 "bytes"
)

const (
	testByteCount = 2048
	privPerm = 0600
	pubPerm = 0644
)

func TestKey(t *testing.T) {
	defer func() {
		if err := recover(); err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
	}()
	privateKey, publicKey := genrsa.Key(testByteCount)
	if privateKey == nil || publicKey == nil {
		t.Fatalf("Unexpected key nil exception private:%v, public:%v", privateKey, publicKey)
	}
}

func TestMakePrivateFile(t *testing.T) {
	defer func() {
		if err := recover(); err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
	}()
	testStr := "-----BEGIN RSA PRIVATE KEY-----"
	testLen := len(testStr)
	file,err := os.OpenFile("testPriv", os.O_CREATE | os.O_TRUNC | os.O_WRONLY, privPerm)
	checkErr(err, t)
	genrsa.MakePrivateFile(file, testByteCount)
	err = file.Close()
	checkErr(err, t)
	file,err = os.Open("testPriv")
	bytes := make([]byte, testLen)
	n,err := file.Read(bytes)
	checkErr(err, t)
	checkBytes := bytes2.Compare(bytes[0:testLen], []byte(testStr))
	if n != testLen || checkBytes != 0 {
		t.Fatal("Failed to read from test file")
	}
	file.Close()
}

func TestPrivateKeysFromFile(t *testing.T) {
	defer func() {
		if err := recover(); err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
	}()
	file,err := os.OpenFile("testPriv", os.O_CREATE | os.O_APPEND | os.O_TRUNC | os.O_RDWR, privPerm)
	checkErr(err, t)
	genrsa.MakePrivateFile(file, testByteCount)
	genrsa.MakePrivateFile(file, testByteCount)
	err = file.Close()
	checkErr(err, t)
	file,err = os.Open("testPriv")
	pkeys := genrsa.PrivateKeysFromFile(file)
	if len(pkeys) < 2 {
		t.Fatal("Failed to read private keys from file")
	}
	file.Close()
}

func TestPublicKeysFromPrivateFiles(t *testing.T) {
	defer func() {
		if err := recover(); err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
	}()
	file,err := os.OpenFile("testPriv", os.O_CREATE | os.O_APPEND | os.O_TRUNC | os.O_RDWR, privPerm)
	checkErr(err, t)
	genrsa.MakePrivateFile(file, testByteCount)
	genrsa.MakePrivateFile(file, testByteCount)
	err = file.Close()
	checkErr(err, t)
	file,err = os.Open("testPriv")
	pkeys := genrsa.PublicKeysFromPrivateFiles(file)
	if len(pkeys) < 2 {
		t.Fatal("Failed to read public keys from file")
	}
	file.Close()
}

func TestMakePrivatePublicFilePair(t *testing.T) {
	defer func() {
		if err := recover(); err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
	}()
	privateTestStr := "-----BEGIN RSA PRIVATE KEY-----"
	privateTestLen := len(privateTestStr)
	publicTestStr := "-----BEGIN RSA PUBLIC KEY-----"
	publicTestLen := len(publicTestStr)
	privateFile,err := os.OpenFile("testPriv", os.O_CREATE | os.O_TRUNC | os.O_WRONLY, privPerm)
	checkErr(err, t)
	publicFile,err := os.OpenFile("testPub", os.O_CREATE | os.O_TRUNC | os.O_WRONLY, pubPerm)
	checkErr(err, t)
	genrsa.MakePrivatePublicFilePair(privateFile, publicFile, testByteCount)
	err = privateFile.Close()
	checkErr(err, t)
	err = publicFile.Close()
	checkErr(err, t)
	file, err := os.Open("testPriv")
	bytes := make([]byte, privateTestLen)
	n,err := file.Read(bytes)
	checkBytes := bytes2.Compare(bytes[0:privateTestLen], []byte(privateTestStr))
	if n != privateTestLen || checkBytes != 0 {
		t.Fatal("Failed to read from private test file")
	}
	file.Close()
	file, err = os.Open("testPub")
	bytes = make([]byte, publicTestLen)
	n,err = file.Read(bytes)
	checkBytes = bytes2.Compare(bytes[0:publicTestLen], []byte(publicTestStr))
	if n != publicTestLen || checkBytes != 0 {
		t.Fatal("Failed to read from public test file")
	}
	file.Close()
}

func TestPublicKeysFromFile(t *testing.T) {
	defer func() {
		if err := recover(); err != nil {
			t.Fatalf("Unexpected error: %s", err)
		}
	}()
	privateFile,err := os.OpenFile("testPriv", os.O_CREATE | os.O_APPEND | os.O_TRUNC | os.O_RDWR, privPerm)
	checkErr(err, t)
	publicFile,err := os.OpenFile("testPub", os.O_CREATE | os.O_APPEND | os.O_TRUNC | os.O_RDWR, privPerm)
	checkErr(err, t)
	genrsa.MakePrivatePublicFilePair(privateFile, publicFile, testByteCount)
	genrsa.MakePrivatePublicFilePair(privateFile, publicFile, testByteCount)
	err = privateFile.Close()
	checkErr(err, t)
	err = publicFile.Close()
	checkErr(err, t)
	publicFile,err = os.Open("testPub")
	pkeys := genrsa.PublicKeysFromFile(publicFile)
	if len(pkeys) < 2 {
		t.Fatal("Failed to read private keys from file")
	}
	publicFile.Close()
}

func checkErr(err error, t *testing.T) {
	if err != nil {
		t.Fatalf("Unexpected error: %s", err)
	}
}