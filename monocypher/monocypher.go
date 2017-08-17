package monocypher

// #include "monocypher.h"
// #include "sha512.h"
// #include <stdio.h>
// #include <stdlib.h>
import "C"
import "fmt"
import "unsafe"

// func main() {
// 	cs := C.CString("cool")
// 	defer C.free(unsafe.Pointer(cs))
// }

//Cool is cooler than the coolest
func Cool() {
	fmt.Println("standard shit, move on")
}

// Lock is authenticated encryption using XChacha20 & Poly1305
func Lock(plaintext, nonce, key string) (mac, ciphertext []byte) {
	// func Lock(plaintext, nonce, key string) (mac, ciphertext string) {
	// void crypto_lock(uint8_t        mac[16],
	// uint8_t       *ciphertext,
	// const uint8_t  key[32],
	// const uint8_t  nonce[24],
	// const uint8_t *plaintext, size_t text_size);

	// var pPlain *C.uint8_t
	// Gplain := []uint8(plaintext)
	Csize := (C.size_t)(len(plaintext))
	Cplain := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(plaintext))))
	defer C.free(unsafe.Pointer(Cplain))
	Ckey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(key[:32]))))
	defer C.free(unsafe.Pointer(Ckey))
	Cnonce := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(nonce[:24]))))
	defer C.free(unsafe.Pointer(Cnonce))
	Cmac := (*C.uint8_t)(unsafe.Pointer(C.calloc(16, 8)))
	defer C.free(unsafe.Pointer(Cmac))
	Ccipher := (*C.uint8_t)(unsafe.Pointer(C.calloc(Csize, 8)))
	defer C.free(unsafe.Pointer(Ccipher))

	// defer C.free(Csize)
	// var Ccipher *C.uint8_t
	// Ccipher := make([]*C.uint8_t, Gsize)
	C.crypto_lock(Cmac, Ccipher, Ckey, Cnonce, Cplain, Csize)
	var Ncipher []byte = C.GoBytes(unsafe.Pointer(&Ccipher), C.int(Csize))
	var Nmac []byte = C.GoBytes(unsafe.Pointer(&mac), C.int(Csize))
	// var Pcipher *byte = Ncipher
	fmt.Println(Ncipher, Nmac)
	// return string(Nmac), string(Ncipher)
	// var Ncipher *byte = unsafe.Pointer(&Ccipher)
	// var Nmac *byte = unsafe.Pointer(&mac)
	return Nmac, Ncipher
}

func Unlock() {
	// int crypto_unlock(uint8_t       *plaintext,
	// const uint8_t  key[32],
	// const uint8_t  nonce[24],
	// const uint8_t  mac[16],
	// const uint8_t *ciphertext, size_t text_size);
}

func Crypto_aead_lock() {
	// void crypto_aead_lock(uint8_t        mac[16],
	// uint8_t       *ciphertext,
	// const uint8_t  key[32],
	// const uint8_t  nonce[24],
	// const uint8_t *ad       , size_t ad_size,
	// const uint8_t *plaintext, size_t text_size);
}

func Crypto_aead_unlock() {
	// int crypto_aead_unlock(uint8_t       *plaintext,
	// const uint8_t  key[32],
	// const uint8_t  nonce[24],
	// const uint8_t  mac[16],
	// const uint8_t *ad        , size_t ad_size,
	// const uint8_t *ciphertext, size_t text_size);
}

func Crypto_key_exchange() {
	// int crypto_key_exchange(uint8_t       shared_key      [32],
	// const uint8_t your_secret_key [32],
	// const uint8_t their_public_key[32]);
}
func Crypto_x25519_public_key() {
	// void crypto_x25519_public_key(uint8_t       public_key[32],
	// const uint8_t secret_key[32]);

}

func Crypto_x25519() {
	// int  crypto_x25519(uint8_t       shared_secret   [32],
	// const uint8_t your_secret_key [32],
	// const uint8_t their_public_key[32]);
}

func Crypto_sign_public_key() {
	// void crypto_sign_public_key(uint8_t        public_key[32],
	// const uint8_t  secret_key[32]);

}

func Crypto_sign() {
	// void crypto_sign(uint8_t        signature[64],
	// const uint8_t  secret_key[32],
	// const uint8_t  public_key[32], // optional, may be null
	// const uint8_t *message, size_t message_size);
}

func Crypto_check() {
	// int crypto_check(const uint8_t  signature[64],
	// const uint8_t  public_key[32],
	// const uint8_t *message, size_t message_size);
}
func Crypto_blake2b_general() {

	// void crypto_blake2b_general(uint8_t       *digest, size_t digest_size,
	// const uint8_t *key   , size_t key_size,
	// const uint8_t *in    , size_t in_size);
}
func Crypto_blake2b() {
	// void crypto_blake2b(uint8_t digest[64], const uint8_t *in, size_t in_size);
}

func Crypto_blake2b_general_init() {
	// void crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t digest_size,
	// const uint8_t      *key, size_t key_size);

}
func Crypto_blake2b_init() {
	// void crypto_blake2b_init(crypto_blake2b_ctx *ctx);
}

func Crypto_blake2b_update() {
	// void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
	// const uint8_t      *in, size_t in_size);
}

func Crypto_blake2b_final() {
	// void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *digest);
}
func Crypto_argon2i() {
	// void crypto_argon2i(uint8_t       *tag,       uint32_t tag_size,
	// void          *work_area, uint32_t nb_blocks,
	// uint32_t       nb_iterations,
	// const uint8_t *password,  uint32_t password_size,
	// const uint8_t *salt,      uint32_t salt_size,
	// const uint8_t *key,       uint32_t key_size,
	// const uint8_t *ad,        uint32_t ad_size);
}
func Crypto_memcmp() {
	// int crypto_memcmp (const uint8_t *p1, const uint8_t *p2, size_t n);
}
func Crypto_zerocmp() {
	// int crypto_zerocmp(const uint8_t *p , size_t n);
}
func Crypto_chacha20_H() {
	// void crypto_chacha20_H(uint8_t       out[32],
	// const uint8_t key[32],
	// const uint8_t in [16]);
}

func Crypto_chacha20_init() {
	// void crypto_chacha20_init(crypto_chacha_ctx *ctx,
	// const uint8_t      key[32],
	// const uint8_t      nonce[8]);
}
func Crypto_chacha20_Xinit() {
	// void crypto_chacha20_Xinit(crypto_chacha_ctx *ctx,
	// const uint8_t      key[32],
	// const uint8_t      nonce[24]);
}
func crypto_chacha20_encrypt() {
	// void crypto_chacha20_encrypt(crypto_chacha_ctx *ctx,
	// uint8_t           *cipher_text,
	// const uint8_t     *plain_text,
	// size_t             message_size);
}
func Crypto_chacha20_stream() {
	// void crypto_chacha20_stream(crypto_chacha_ctx *ctx,
	// uint8_t           *cipher_text,
	// size_t             message_size);
}
func Crypto_chacha20_set_ctr() {
	// void crypto_chacha20_set_ctr(crypto_chacha_ctx *ctx, uint64_t ctr);
}
func Crypto_poly1305_auth() {
	// void crypto_poly1305_auth(uint8_t        mac[16],
	// const uint8_t *m,
	// size_t         msg_size,
	// const uint8_t  key[32]);

}
func Crypto_poly1305_init() {
	// void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32]);
}
func Crypto_poly1305_update() {
	// void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
	// const uint8_t *m, size_t bytes);
}
func Crypto_poly1305_final() {
	// void crypto_poly1305_final(crypto_poly1305_ctx *ctx, uint8_t mac[16]);
}
