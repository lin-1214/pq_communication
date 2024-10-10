#ifndef INDCCA_H
#define INDCCA_H

#include <oqs/oqs.h>

// https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption#Authenticated_Decryption_using_GCM_mode
void print_data(OQS_KEM* kem,
                unsigned char* m,
                int len_m,
                unsigned char* pk,
                unsigned char* ciphertext_kem,
                unsigned char* ciphertext_dem,
                unsigned char* tag,
                unsigned char* iv,
                unsigned char* coins);

int pke_keypair(OQS_KEM* kem, unsigned char* pk, unsigned char* sk);

int pke_enc(OQS_KEM* kem,
            unsigned char* m,
            int len_m,
            unsigned char* pk,
            unsigned char* ciphertext_kem,
            unsigned char* ciphertext_dem,
            unsigned char* tag,
            unsigned char* iv,
            unsigned char* coins);

int pke_dec(OQS_KEM* kem,
            unsigned char* sk,
            unsigned char* ciphertext_kem,
            unsigned char* ciphertext_dem,
            int ciphertext_dem_len,
            unsigned char* tag,
            unsigned char* iv,
            unsigned char* m);

#endif
