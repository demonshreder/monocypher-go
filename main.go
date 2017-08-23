package main

import "crypto/rand"
import "fmt"

func main() {
	a := make([]byte, 24)
	rand.Read(a)
	fmt.Println(a)
}
