package main

import (
	"encoding/base32"
	"encoding/base64"
	"fmt"

	"github.com/demonshreder/monocypher-go/monocypher"
)

func main() {
	message := []byte("Hello this is Gopher army, we are gonna rule this world ")
	secretKey := []byte("Gophers are such a fun thing. Hehehehehe")
	// publicKey := []byte("Hacking Hacking guys this is so much fun")
	// a := make([]byte, 32)
	// rand.Read(a)
	// b := make([]byte, 32)
	// rand.Read(b)
	// signature := monocypher.Sign(message, publicKey, secretKey)

	signature, pubkey := monocypher.Sign(message, secretKey)
	// signature2 := Sign(message, []byte{}, secretKey)
	// fmt.Println(signature)
	// fmt.Println(base64.StdEncoding.EncodeToString(signature))
	// msg := []byte("hahahahah")
	result := monocypher.CheckSign(message, pubkey, signature)
	fmt.Println(result)
	fmt.Println(base32.StdEncoding.EncodeToString(pubkey))
	fmt.Println(base64.StdEncoding.EncodeToString(signature))
}
