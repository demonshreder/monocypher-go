#include "monocypher/monocypher.h"
#include "monocypher/sha512.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void main(){
    // void crypto_sign(uint8_t        signature[64],
	// const uint8_t  secret_key[32],
	// const uint8_t  public_key[32], // optional, may be null
	// const uint8_t *message, size_t message_size);
    
    // int crypto_check(const uint8_t  signature[64],
    // const uint8_t  public_key[32],
    // const uint8_t *message, size_t message_size);


    uint8_t signature[64];
    const uint8_t secret_key[32] = "GophersaresuchafunthingHeHeHeHeH";
    // const uint8_t pub_key[32] = "HackingHackingguysthisissomuchfu";
    uint8_t pub_key[32];
    const uint8_t *plaintext = "HellothisisGopherarmyawearegonnarulethisworld";
    size_t text_size = strlen(plaintext);
    crypto_sign_public_key(pub_key,secret_key);
    crypto_sign(signature,secret_key,pub_key,plaintext,text_size);
    int a = crypto_check(signature, pub_key,plaintext,text_size);
    printf("Result: %d\n",a); // Output is always -1
    
    

}