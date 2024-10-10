#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../src/utils.h"
#include "../src/aes256gcm.h"
#include "../src/indcca.h"
#include "../src/commitment.h"

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
    uint8_t *coins2 = malloc(kem->length_secret_key);
    uint8_t *m = malloc(1000);
    uint8_t *m2 = malloc(1000);

    pke_keypair(kem, pk, sk);

    const int COMMITMENTCOINSBYTES = AES_256_IVEC_LENGTH + kem->length_shared_secret;

    OQS_randombytes(coins, COMMITMENTCOINSBYTES);
    printf("coins: ");
    print_hex(coins, COMMITMENTCOINSBYTES);

    OQS_randombytes(m, 100);

    printf("m: ");
    print_hex(m, 1000);

    Commitment* commitment = malloc(sizeof(Commitment));
    init_commitment(kem, commitment);
    Commitment* commitment2 = malloc(sizeof(Commitment));
    init_commitment(kem, commitment2);

    const int DEM_LEN = commitment->kem->length_shared_secret + sizeof(int);
    commit(pk, m, DEM_LEN, coins, commitment);

    print_commitment(commitment);
    printf(".............................................................\n");

    int equal = check_commitment(pk, m, coins, commitment);

    if (equal == 0) {
      printf("Commitments are equal!\n");
    } else {
      printf("Commitments are NOT equal!\n");
    }

    memcpy(coins2, coins, COMMITMENTCOINSBYTES);
    memcpy(m2, m, 1000);

    int equal1 = check_commitment(pk, m2, coins2, commitment);

    if (equal1 == 0) {
      printf("Commitments are equal!\n");
    } else {
      printf("Commitments are NOT equal!\n");
    }

    free_commitment(commitment);
    free_commitment(commitment2);

    // Delete secrets and free
    OQS_MEM_secure_free(sk, kem->length_secret_key);
    OQS_MEM_secure_free(coins, kem->length_secret_key);
    OQS_MEM_secure_free(coins2, kem->length_secret_key);

    // Free
    OQS_MEM_insecure_free(pk);
    OQS_KEM_free(kem);

    printf("----------------------------------------------------------------------------------------\n");

  }
  return OQS_SUCCESS;
}
