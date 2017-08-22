package main

import "fmt"
import "github.com/demonshreder/monocypher-go/monocypher"

func main() {
	key := []byte("OMG kamal is here again touche. Such a sexy guy")
	nonce := []byte("This is kamal too, kek guys, hahahahahaha")
	plain := []byte("Hello this is Kamal")
	ad := []byte("")
	mac, cipher, add := monocypher.AeadLock(plain, nonce, key, ad)
	// fmt.Println(len(mac), len(cipher), len("Hello this is Kamal"))
	decipher := monocypher.AeadUnlock(mac, cipher, nonce, key, add)
	// fmt.Println(len([]byte(key[:32])), []byte(key[:32]))
	fmt.Println(len(plain), plain, len(decipher), string(decipher))
}
