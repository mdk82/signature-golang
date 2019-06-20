package signage

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
)

// Signature json format tags
type Signature struct {
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Pubkey    string `json:"pubkey"`
}

// GetSignature returns a signature of a SHA256 hash of the input email and the RSA keypair.
func GetSignature(input string, privateKey *rsa.PrivateKey) Signature {
	hash := crypto.SHA256.New()
	hash.Write([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash.Sum(nil))
	if err != nil {
		log.Fatalf("Not able to create signature %v", err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&privateKey.PublicKey),
	})

	return Signature{
		Message:   input,
		Signature: base64.StdEncoding.EncodeToString(signature),
		Pubkey:    string(pemBytes),
	}
}
