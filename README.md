# genrsa
#### Golang functions to generate rsa private and public keys in memory and files

### dependency

```bash
dep ensure -add "github.com/Yomiji/genrsa"
```

### useage

```go
func TestKey(t *testing.T) {

	privateKey, publicKey := genrsa.MakeKeys(testByteCount)
	
	// do something with keys
}

func TestMakePrivatePublicFilePair(t *testing.T) {
		
	privateFile,err := os.OpenFile("testPriv", os.O_CREATE | os.O_TRUNC | os.O_WRONLY, privPerm)
	checkTheErr(err)
	
	publicFile,err := os.OpenFile("testPub", os.O_CREATE | os.O_TRUNC | os.O_WRONLY, pubPerm)
	checkTheErr(err)
	
	genrsa.MakePrivatePublicFilePair(privateFile, publicFile, testByteCount)
	
	privateFile.Close()
	publicFile.Close()
	
	// do something with files
}
```