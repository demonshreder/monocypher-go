#include "monocypher/monocypher.h"
#include "monocypher/sha512.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void main(){
    // void crypto_lock(uint8_t        mac[16],
	// uint8_t       *ciphertext,
	// const uint8_t  key[32],
	// const uint8_t  nonce[24],
	// const uint8_t *plaintext, size_t text_size);
    uint8_t mac[16];
    const uint8_t key[32] = "This is one of the best thingsin";
    const uint8_t nonce[24] = "I am sexy and I know its";
    const uint8_t *plaintext = "I am sexy and I know it very well.";
    size_t text_size = strlen(plaintext);
    uint8_t *ciphertext = calloc(strlen(plaintext),sizeof(uint8_t));
    crypto_lock(mac,ciphertext,key,nonce,plaintext,text_size);
    // int crypto_unlock(uint8_t       *plaintext,
	// const uint8_t  key[32],
	// const uint8_t  nonce[24],
	// const uint8_t  mac[16],
    // const uint8_t *ciphertext, size_t text_size);
    uint8_t *plaintext2 = calloc(strlen(ciphertext),sizeof(uint8_t));
    crypto_unlock(plaintext2,key,nonce,mac,ciphertext,text_size);
    printf(plaintext,"\n");
    printf(plaintext2);

}