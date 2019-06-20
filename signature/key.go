package signage

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// GetPrivateKey looks for an exsisting key from file, if none generates one based on byte size given.
func GetPrivateKey(bitSize int) *rsa.PrivateKey {
	filePath := "private.pem"

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		privateKey, err := GeneratePrivateKey(bitSize)
		if err != nil {
			fmt.Printf("could not generate private key, %v", err)
		}

		EncodePrivateKeyToPEM(filePath, privateKey)
		return privateKey
	}
	return DecodePrivateKeyFromFile(filePath)

}

// GeneratePrivateKey generates a private RSA key given the byte size.
func GeneratePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// EncodePrivateKeyToPEM saves encoded RSA key in PEM format to the file specified.
func EncodePrivateKeyToPEM(fileName string, key *rsa.PrivateKey) {
	pemFile, err := os.Create(fileName)
	if err != nil {
		log.Fatalf("could not create file, %s %v", fileName, err)
	}
	defer pemFile.Close()

	privateKey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(pemFile, privateKey)
	if err != nil {
		fmt.Printf("could not write key to file %s %v", fileName, err)
	}
}

// DecodePrivateKeyFromFile reads RSA key from file and parses key.
func DecodePrivateKeyFromFile(fileName string) *rsa.PrivateKey {
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		log.Fatalf("could not read file from %s %v", fileName, err)
	}

	data, _ := pem.Decode(file)
	privateKey, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		log.Fatalf("could not parse key from file %v", err)
	}

	return privateKey
}
