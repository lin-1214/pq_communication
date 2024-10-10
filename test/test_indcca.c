#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../src/utils.h"
#include "../src/aes256gcm.h"
#include "../src/indcca.h"

#define NUM_ALGOS 3

int main(void) {

  char algos[NUM_ALGOS][OQS_KEM_algs_length] = {
    // OQS_KEM_alg_classic_mceliece_6688128,
    // OQS_KEM_alg_ntru_hps4096821,
    // OQS_KEM_alg_saber_firesaber,
    OQS_KEM_alg_kyber_1024,
    OQS_KEM_alg_kyber_768,
    OQS_KEM_alg_kyber_512
  };

  for (int i = 0; i < NUM_ALGOS; i++) {
    OQS_KEM *kem = OQS_KEM_new(algos[i]);
    if(kem == NULL) exit(EXIT_FAILURE);
    printf("[--] Setting %s...\n", algos[i]);
    printf("[--] Public key bytes: %zu\n[--] Ciphertext bytes: %zu\n[--] Secret key bytes: %zu\n[--] Shared secret key bytes: %zu\n[--] NIST level: %d\n[--] IND-CCA: %s\n", kem->length_public_key, kem->length_ciphertext, kem->length_secret_key, kem->length_shared_secret, kem->claimed_nist_level, kem->ind_cca ? "Y" : "N");

    uint8_t *pk = malloc(kem->length_public_key);
    uint8_t *sk = malloc(kem->length_secret_key);
    uint8_t *coins = malloc(kem->length_secret_key);
    uint8_t *iv = malloc(AES_256_IVEC_LENGTH);
    uint8_t *tag = malloc(AES_256_GCM_TAG_LENGTH);
    uint8_t *ciphertext_kem = malloc(kem->length_ciphertext);
    uint8_t *ciphertext_dem = malloc(2000);

    pke_keypair(kem, pk, sk);

    OQS_randombytes(coins, kem->length_secret_key);

    OQS_randombytes(iv, AES_256_IVEC_LENGTH);

    printf("iv to function: ");
    print_hex(iv, AES_256_IVEC_LENGTH);

    unsigned char* m = (unsigned char *) "The quick brown fox jumps over the lazy dog";

    printf("\tplaintext: %s\n", m);

    for (int j = 0; j < 5; j++) {

      printf("Encryption\n");
      size_t len_m = strlen((char*) m);
      int ciphertext_dem_len = pke_enc(kem, m, len_m,  pk, ciphertext_kem,
                                       ciphertext_dem, tag, iv, coins);

      if (ciphertext_dem_len == -1) {
        printf("Error!\n");
        return 1;
      }

      unsigned char m_dec[2000];

      int ret = pke_dec(kem, sk, ciphertext_kem,
                  ciphertext_dem,
                  ciphertext_dem_len,
                  tag,
                  iv,
                  m_dec);

      if (ret == -1) {
        printf("Error!\n");
        return 1;
      }

      m_dec[ret] = '\0';
      printf("Plaintext: %s\n", m_dec);
    }


    // Delete secrets and free
    OQS_MEM_secure_free(sk, kem->length_secret_key);
    OQS_MEM_secure_free(iv, AES_256_IVEC_LENGTH);
    OQS_MEM_secure_free(tag, AES_256_GCM_TAG_LENGTH);
    OQS_MEM_secure_free(coins, kem->length_secret_key);

    // Free
    OQS_MEM_insecure_free(ciphertext_kem);
    OQS_MEM_insecure_free(ciphertext_dem);
    OQS_MEM_insecure_free(pk);
    OQS_KEM_free(kem);

   printf("----------------------------------------------------------------------------------------\n");

  }
  return OQS_SUCCESS;
}
