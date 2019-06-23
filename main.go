package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	signage "github.com/mdk82/signature-golang/signature"
	validate "github.com/mdk82/signature-golang/validation"
)

func main() {

	if len(os.Args) < 2 {
		log.Fatalln(`Program requires at least one argument "Email Address", please try again`)
	}

	email := os.Args[1]

	err := validate.Validate(email)
	if err != nil {
		fmt.Println("Error:", err)
		log.Fatal()
	}

	key := signage.GetPrivateKey(2048)

	sigCreated := signage.GetSignature(email, key)

	signature, err := json.Marshal(sigCreated)
	if err != nil {
		log.Fatalf("Could not marshal JSON of signature %v", err)
	}

	fmt.Println(string(signature))

}
