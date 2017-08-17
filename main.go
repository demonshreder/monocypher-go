package main

import (
	"fmt"

	"github.com/demonshreder/monocypher-go/monocypher"
)

func main() {
	mac, cipher := monocypher.Lock("Hello this is Kamal", "This is kamal too, kek guys, hahahahahaha", "OMG kamal is here again touche. Such a sexy guy")
	fmt.Println(mac, cipher)
	// fmt.Println("sexy")
}
