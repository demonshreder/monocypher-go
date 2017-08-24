package monocypher

// #include "monocypher.h"
// #include "sha512.h"
// #include <stdio.h>
// #include <stdlib.h>
import "C"

import "unsafe"

// Lock is authenticated encryption using XChacha20 & Poly1305.
// Lock takes plaintext, [24]nonce and [32]key, returns the [16]mac and the
// ciphertext.
func Lock(plaintext, nonce, key []byte) (mac, ciphertext []byte) {
	// func Lock(plaintext, nonce, key string) (mac, ciphertext string) {
	// void crypto_lock(uint8_t        mac[16],
	// uint8_t       *ciphertext,
	// const uint8_t  key[32],
	// const uint8_t  nonce[24],
	// const uint8_t *plaintext, size_t text_size);

	CSize := (C.size_t)(len(plaintext))
	CPlain := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(plaintext))))
	defer C.free(unsafe.Pointer(CPlain))
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(key[:32]))))
	defer C.free(unsafe.Pointer(CKey))
	CNonce := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(nonce[:24]))))
	defer C.free(unsafe.Pointer(CNonce))
	CMac := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, 16))))
	defer C.free(unsafe.Pointer(CMac))
	CCipher := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, len(plaintext)))))
	defer C.free(unsafe.Pointer(CCipher))
	//	C Method call
	C.crypto_lock(CMac, CCipher, CKey, CNonce, CPlain, CSize)
	// Converting CTypes back to Go
	var GCipher []byte = C.GoBytes(unsafe.Pointer(CCipher), C.int(len(plaintext)))
	var GMac []byte = C.GoBytes(unsafe.Pointer(CMac), C.int(16))
	return GMac, GCipher
}

// Unlock decrypts the ciphertext from Lock(). It first checks the integrity
// using mac, then uses the same [24]nonce and [32]key to decrypt the cipher
// and returns the plaintext in bytes.
func Unlock(ciphertext, nonce, key, mac []byte) (plaintext []byte) {
	// int crypto_unlock(uint8_t       *plaintext,
	// const uint8_t  key[32],
	// const uint8_t  nonce[24],
	// const uint8_t  mac[16],
	// const uint8_t *ciphertext, size_t text_size);

	CSize := (C.size_t)(len(ciphertext))
	CCipher := (*C.uint8_t)(unsafe.Pointer(C.CBytes(ciphertext)))
	defer C.free(unsafe.Pointer(CCipher))

	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(key[:32]))))
	defer C.free(unsafe.Pointer(CKey))
	CNonce := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(nonce[:24]))))
	defer C.free(unsafe.Pointer(CNonce))
	CMac := (*C.uint8_t)(unsafe.Pointer(C.CBytes(mac)))
	defer C.free(unsafe.Pointer(CMac))
	CPlain := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, len(ciphertext)))))
	defer C.free(unsafe.Pointer(CPlain))
	//	C Method call
	C.crypto_unlock(CPlain, CKey, CNonce, CMac, CCipher, CSize)
	var GPlain []byte = C.GoBytes(unsafe.Pointer(CPlain), C.int(len(ciphertext)))
	// return Nmac, Ncipher

	return GPlain
}

// AeadLock is the same as Lock() but allows some additional data to be signed
// though not encrypted with the rest. AeadLock returns mac, ciphertext and the
// authenticated text.
func AeadLock(plaintext, nonce, key, addData []byte) (mac, ciphertext, data []byte) {
	// void crypto_aead_lock(uint8_t        mac[16],
	// uint8_t       *ciphertext,
	// const uint8_t  key[32],
	// const uint8_t  nonce[24],
	// const uint8_t *ad       , size_t ad_size,
	// const uint8_t *plaintext, size_t text_size);

	CAdDataSize := (C.size_t)(len(addData))
	CAdData := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(addData))))
	defer C.free(unsafe.Pointer(CAdData))
	CTextSize := (C.size_t)(len(plaintext))
	CPlain := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(plaintext))))
	defer C.free(unsafe.Pointer(CPlain))
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(key[:32]))))
	defer C.free(unsafe.Pointer(CKey))
	CNonce := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(nonce[:24]))))
	defer C.free(unsafe.Pointer(CNonce))
	CMac := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, 16))))
	defer C.free(unsafe.Pointer(CMac))
	CCipher := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, len(plaintext)))))
	defer C.free(unsafe.Pointer(CCipher))
	//	C Method call
	C.crypto_aead_lock(CMac, CCipher, CKey, CNonce, CAdData, CAdDataSize, CPlain, CTextSize)
	// Converting CTypes back to Go
	var GCipherText []byte = C.GoBytes(unsafe.Pointer(CCipher), C.int(len(plaintext)))
	var GMac []byte = C.GoBytes(unsafe.Pointer(CMac), C.int(16))
	var GAdData []byte = C.GoBytes(unsafe.Pointer(CAdData), C.int(CAdDataSize))
	return GMac, GCipherText, GAdData
}

// AeadUnlock is the same as Unlock(), but checks authenticated
// data and returns the deciphered plaintext.
func AeadUnlock(ciphertext, nonce, key, mac, addData []byte) (plaintext []byte) {
	// int crypto_aead_unlock(uint8_t       *plaintext,
	// const uint8_t  key[32],
	// const uint8_t  nonce[24],
	// const uint8_t  mac[16],
	// const uint8_t *ad        , size_t ad_size,
	// const uint8_t *ciphertext, size_t text_size);

	CAdDataSize := (C.size_t)(len(addData))
	CAdData := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(addData))))
	defer C.free(unsafe.Pointer(CAdData))
	CCipherSize := (C.size_t)(len(ciphertext))
	CCipherText := (*C.uint8_t)(unsafe.Pointer(C.CBytes(ciphertext)))
	defer C.free(unsafe.Pointer(CCipherText))
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(key[:32]))))
	defer C.free(unsafe.Pointer(CKey))
	CNonce := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(nonce[:24]))))
	defer C.free(unsafe.Pointer(CNonce))
	CMac := (*C.uint8_t)(unsafe.Pointer(C.CBytes(mac)))
	defer C.free(unsafe.Pointer(CMac))
	CPlainText := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, len(ciphertext)))))
	defer C.free(unsafe.Pointer(CPlainText))
	//	C Method call
	C.crypto_aead_unlock(CPlainText, CKey, CNonce, CMac, CAdData, CAdDataSize, CCipherText, CCipherSize)
	// Converting CTypes back to Go
	var GPlainText []byte = C.GoBytes(unsafe.Pointer(CPlainText), C.int(len(ciphertext)))
	// return Nmac, Ncipher

	return GPlainText
}

// SignPublicKey is blake2b based curve25519 public key generator
// meant for signing messages alone.
func GenPublicKey(secretKey []byte) (publicKey []byte) {
	// void crypto_sign_public_key(uint8_t        public_key[32],
	// const uint8_t  secret_key[32]);

	CSecKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(secretKey[:32]))))
	defer C.free(unsafe.Pointer(CSecKey))
	CPubKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, 32))))
	defer C.free(unsafe.Pointer(CPubKey))
	//	C Method call
	C.crypto_sign_public_key(CPubKey, CSecKey)
	// Converting CTypes back to Go
	var GPubKey []byte = C.GoBytes(unsafe.Pointer(CPubKey), C.int(32))
	return GPubKey
}

// Sign signs a message with your secret key. The generated curve225519
// public key along with the signature is returned.
func SignMessage(message, secretKey []byte) (signature, publicKey []byte) {
	// void crypto_sign(uint8_t        signature[64],
	// const uint8_t  secret_key[32],
	// const uint8_t  public_key[32], // optional, may be null
	// const uint8_t *message, size_t message_size);

	CSign := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, 64))))
	defer C.free(unsafe.Pointer(CSign))
	CSize := (C.size_t)(len(message))
	CMessage := (*C.uint8_t)(unsafe.Pointer(C.CBytes(message)))
	defer C.free(unsafe.Pointer(CMessage))
	CPubKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, 32))))
	defer C.free(unsafe.Pointer(CPubKey))
	CSecKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(secretKey[:32]))))
	defer C.free(unsafe.Pointer(CSecKey))
	//	C Method call
	C.crypto_sign_public_key(CPubKey, CSecKey)
	C.crypto_sign(CSign, CSecKey, CPubKey, CMessage, CSize)
	// Converting CTypes back to Go
	var GSign []byte = C.GoBytes(unsafe.Pointer(CSign), C.int(64))
	var GPubKey []byte = C.GoBytes(unsafe.Pointer(CPubKey), C.int(32))
	return GSign, GPubKey
}

// CheckSign checks the message and its corresponding public key and signature
// for validity.
func CheckMessageSignature(message, publicKey, signature []byte) (result bool) {
	// int crypto_check(const uint8_t  signature[64],
	// const uint8_t  public_key[32],
	// const uint8_t *message, size_t message_size);

	CSign := (*C.uint8_t)(C.CBytes(signature))
	CSize := (C.size_t)(len(message))
	CMessage := (*C.uint8_t)(unsafe.Pointer(C.CBytes(message)))
	defer C.free(unsafe.Pointer(CMessage))
	CPubKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(publicKey[:32]))))
	defer C.free(unsafe.Pointer(CPubKey))
	CResult := C.int(0)
	//	C Method call
	CResult = C.crypto_check(CSign, CPubKey, CMessage, CSize)
	// Converting CTypes back to Go
	var GResult []byte = C.GoBytes(unsafe.Pointer(&CResult), C.int(1))
	// Original output from C if wrong is -1 which is impossible with
	// byte being uint8 so hacks.
	if int(GResult[0]) == 0 {
		return true
	}
	return false
}


// KeyExchange computes a shared key with your secret key & their public key, for the Lock() function above.
// It performs X25519 key exchange and hashes the key with HChacha20 to get a fairly random shared key.
func KeyExchange(secretKey, theirPublicKey []byte)(sharedKey []byte, validity bool) {
	// int crypto_key_exchange(uint8_t       shared_key      [32],
	// const uint8_t your_secret_key [32],
	// const uint8_t their_public_key[32]);
  
  	CSharedKey := (*C.uint8_t)(C.CBytes(make([]uint8,32))
  	CSecretKey := (*C.uint8_t)(C.CBytes(secretKey))
  	CTheirPublicKey := (*C.uint8_t)(C.CBytes(theirPublicKey))
  
 	CResult := C.int(0)
  	// C Method call
 	CResult = C.crypto_key_exchange(CSharedKey, CSecretKey, CTheirPublicKey)
 	// Converting CTypes back to Go
	var GResult []byte = C.GoBytes(unsafe.Pointer(&CResult), C.int(1))
  	if int(GResult[0]) == 0 {
		return true
	}
	return false
  	return true, GSharedKey
}


func crypto_x25519_public_key() {
	// void crypto_x25519_public_key(uint8_t       public_key[32],
	// const uint8_t secret_key[32]);

}

func crypto_x25519() {
	// int  crypto_x25519(uint8_t       shared_secret   [32],
	// const uint8_t your_secret_key [32],
	// const uint8_t their_public_key[32]);
}

func crypto_blake2b_general() {

	// void crypto_blake2b_general(uint8_t       *digest, size_t digest_size,
	// const uint8_t *key   , size_t key_size,
	// const uint8_t *in    , size_t in_size);
}
func crypto_blake2b() {
	// void crypto_blake2b(uint8_t digest[64], const uint8_t *in, size_t in_size);
}

func crypto_blake2b_general_init() {
	// void crypto_blake2b_general_init(crypto_blake2b_ctx *ctx, size_t digest_size,
	// const uint8_t      *key, size_t key_size);

}
func crypto_blake2b_init() {
	// void crypto_blake2b_init(crypto_blake2b_ctx *ctx);
}

func crypto_blake2b_update() {
	// void crypto_blake2b_update(crypto_blake2b_ctx *ctx,
	// const uint8_t      *in, size_t in_size);
}

func crypto_blake2b_final() {
	// void crypto_blake2b_final(crypto_blake2b_ctx *ctx, uint8_t *digest);
}

func crypto_chacha20_H() {
	// void crypto_chacha20_H(uint8_t       out[32],
	// const uint8_t key[32],
	// const uint8_t in [16]);
}

func crypto_chacha20_init() {
	// void crypto_chacha20_init(crypto_chacha_ctx *ctx,
	// const uint8_t      key[32],
	// const uint8_t      nonce[8]);
}
func crypto_chacha20_Xinit() {
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
func crypto_chacha20_stream() {
	// void crypto_chacha20_stream(crypto_chacha_ctx *ctx,
	// uint8_t           *cipher_text,
	// size_t             message_size);
}
func crypto_chacha20_set_ctr() {
	// void crypto_chacha20_set_ctr(crypto_chacha_ctx *ctx, uint64_t ctr);
}
func crypto_poly1305_auth() {
	// void crypto_poly1305_auth(uint8_t        mac[16],
	// const uint8_t *m,
	// size_t         msg_size,
	// const uint8_t  key[32]);

}
func crypto_poly1305_init() {
	// void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const uint8_t key[32]);
}
func crypto_poly1305_update() {
	// void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
	// const uint8_t *m, size_t bytes);
}
func crypto_poly1305_final() {
	// void crypto_poly1305_final(crypto_poly1305_ctx *ctx, uint8_t mac[16]);
}
func crypto_argon2i() {
	// void crypto_argon2i(uint8_t       *tag,       uint32_t tag_size,
	// void          *work_area, uint32_t nb_blocks,
	// uint32_t       nb_iterations,
	// const uint8_t *password,  uint32_t password_size,
	// const uint8_t *salt,      uint32_t salt_size,
	// const uint8_t *key,       uint32_t key_size,
	// const uint8_t *ad,        uint32_t ad_size);
}
