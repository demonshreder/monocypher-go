package main

import (
	"fmt"

	"github.com/demonshreder/monocypher-go/monocypher"
)

func main() {
	key := "OMG kamal is here again touche. Such a sexy guy"
	nonce := "This is kamal too, kek guys, hahahahahaha"
	plain := "Hello this is Kamal"
	mac, cipher := monocypher.Lock(plain, nonce, key)
	// fmt.Println(len(mac), len(cipher), len("Hello this is Kamal"))
	decipher := monocypher.Unlock(mac, cipher, nonce, key)
	fmt.Println(len([]byte(key[:32])), []byte(key[:32]))
	fmt.Println(len(plain), plain, len(decipher), string(decipher))
}
