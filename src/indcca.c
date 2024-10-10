#include <string.h>

#include "indcca.h"
#include "aes256gcm.h"
#include "utils.h"

void print_data(OQS_KEM* kem,
                unsigned char* m,
                int len_m,
                unsigned char* pk,
                unsigned char* ciphertext_kem,
                unsigned char* ciphertext_dem,
                unsigned char* tag,
                unsigned char* iv,
                unsigned char* coins) {

  printf("Ciphertext KEM: ");
  print_hex(ciphertext_kem, kem->length_ciphertext);

  printf("Ciphertext DEM: ");
  print_hex(ciphertext_dem, 32);

  printf("Tag: ");
  print_hex(tag, AES_256_GCM_TAG_LENGTH);

  printf("IV: ");
  print_hex(iv, AES_256_IVEC_LENGTH);

  printf("\tcoins: ");
  print_hex(coins, 32);

  printf("\tpk: ");
  print_hex_short(pk, kem->length_public_key, 10);

  print_hex(m, len_m);
}

int pke_keypair(OQS_KEM* kem, unsigned char* pk, unsigned char* sk) {
  return OQS_KEM_keypair(kem, pk, sk);
}

int pke_enc(OQS_KEM* kem,
            unsigned char* m,
            int len_m,
            unsigned char* pk,
            unsigned char* ciphertext_kem,
            unsigned char* ciphertext_dem,
            unsigned char* tag,
            unsigned char* iv,
            unsigned char* coins) {

  unsigned char K[kem->length_shared_secret];

  unsigned char* aad = (unsigned char*) "";

  OQS_KEM_encaps(kem, ciphertext_kem, K, pk, coins);

  int ret = gcm_encrypt(m, len_m,
                        aad, strlen((char*) aad),
                        K,
                        iv, AES_256_IVEC_LENGTH,
                        ciphertext_dem,
                        tag);

  return ret;

}

int pke_dec(OQS_KEM* kem,
            unsigned char* sk,
            unsigned char* ciphertext_kem,
            unsigned char* ciphertext_dem,
            int ciphertext_dem_len,
            unsigned char* tag,
            unsigned char* iv,
            unsigned char* m) {

  unsigned char K[kem->length_shared_secret];

  unsigned char* aad = (unsigned char*) "";

  OQS_KEM_decaps(kem, K, ciphertext_kem, sk);

  int ret = gcm_decrypt(ciphertext_dem, ciphertext_dem_len,
                        aad, 0,
                        tag,
                        K,
                        iv, AES_256_IVEC_LENGTH,
                        m);

  return ret;
}
