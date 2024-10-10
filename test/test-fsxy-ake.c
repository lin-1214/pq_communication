#include "../src/fsxy-ake.h"

#define NUM_ALGOS 6

int main(void) {

  char algos[NUM_ALGOS][OQS_KEM_algs_length] = {
    // OQS_KEM_alg_classic_mceliece_6688128,
    OQS_KEM_alg_ntru_hps4096821,
    OQS_KEM_alg_saber_firesaber,
    OQS_KEM_alg_kyber_1024,
    OQS_KEM_alg_kyber_768,
    OQS_KEM_alg_kyber_512,
    OQS_KEM_alg_classic_mceliece_348864
  };

  for (int i = 0; i < NUM_ALGOS; i++) {
    clock_t begin_init = times(NULL);
    OQS_KEM *kem = OQS_KEM_new(algos[i]);
    if(kem == NULL) exit(EXIT_FAILURE);
    printf("[--] Setting %s...\n", algos[i]);
    printf("[--] Public key bytes: %zu\n[--] Ciphertext bytes: %zu\n[--] Secret key bytes: %zu\n[--] Shared secret key bytes: %zu\n[--] NIST level: %d\n[--] IND-CCA: %s\n", kem->length_public_key, kem->length_ciphertext, kem->length_secret_key, kem->length_shared_secret, kem->claimed_nist_level, kem->ind_cca ? "Y" : "N");
    clock_t end_init = times(NULL);

    // Static keys for U_A
    uint8_t *ekA1 = malloc(kem->length_public_key);
    uint8_t *dkA1 = malloc(kem->length_secret_key);
    OQS_KEM_keypair(kem, ekA1, dkA1);

    printf("\n[U_A] Generating static keys...\n");
    printf("[U_A] ekA1: ");
    print_hex_short(ekA1, kem->length_public_key, MAX);
    printf("[U_A] dkA1: ");
    print_hex_short(dkA1, kem->length_secret_key, MAX);

    // Static keys for U_B
    uint8_t *ekB1 = malloc(kem->length_public_key);
    uint8_t *dkB1 = malloc(kem->length_secret_key);
    OQS_KEM_keypair(kem, ekB1, dkB1);

    printf("\n[U_B] Generating static keys...\n");
    printf("[U_B] ekB1: ");
    print_hex_short(ekB1, kem->length_public_key, MAX);
    printf("[U_B] dkB1: ");
    print_hex_short(dkB1, kem->length_secret_key, MAX);

    clock_t end_static_keys = times(NULL);

    // -----------------------------------------------
    // Init key exchange
    printf("\n[--] Init key exchange...\n");
    uint8_t *cA1 = malloc(kem->length_ciphertext);
    uint8_t *kA1 = malloc(kem->length_shared_secret);
    uint8_t *ekA2 = malloc(kem->length_public_key);
    uint8_t *dkA2 = malloc(kem->length_secret_key);
    ake_init(kem, dkA1, ekB1, cA1, kA1, ekA2, dkA2);
    printf("[U_A] kA1: ");
    print_hex_short(kA1, kem->length_shared_secret, MAX);

    clock_t end_alg_init = times(NULL);
    // -----------------------------------------------
    // AlgB
    uint8_t *cB1 = malloc(kem->length_ciphertext);
    uint8_t *kB1 = malloc(kem->length_shared_secret);
    uint8_t *cB2 = malloc(kem->length_ciphertext);
    uint8_t *kB2 = malloc(kem->length_shared_secret);
    uint8_t *skB = malloc(kem->length_shared_secret);
    uint8_t *kA1_prime = malloc(kem->length_shared_secret);

    ake_algB(kem, ekA1, ekA2, dkB1, kB1, kB2, cA1, cB1, cB2, kA1_prime, ekB1, skB);
    printf("[U_B] kA1: ");
    print_hex_short(kA1_prime, kem->length_shared_secret, MAX);

    clock_t end_algB = times(NULL);

    // -----------------------------------------------
    // AlgA
    uint8_t *skA = malloc(kem->length_shared_secret);
    ake_algA(kem, cB1, cB2, dkA1, dkA2, kA1, ekA1, ekB1, ekA2, cA1, skA);

    clock_t end_algA = times(NULL);

    printf("\n[U_A] skA: ");
    print_hex(skA, kem->length_shared_secret);

    printf("[U_B] skB: ");
    print_hex(skB, kem->length_shared_secret);

    if(memcmp(skA, skB, kem->length_shared_secret) != 0){
      printf("[--] Key exchange error!\n");
      return OQS_ERROR;
    }

    printf("[--] Key exchange successful!\n");

    // Delete secrets and free
    OQS_MEM_secure_free(dkA1, kem->length_secret_key);
    OQS_MEM_secure_free(dkA2, kem->length_secret_key);
    OQS_MEM_secure_free(dkB1, kem->length_secret_key);
    OQS_MEM_secure_free(kA1, kem->length_shared_secret);
    OQS_MEM_secure_free(kB1, kem->length_shared_secret);
    OQS_MEM_secure_free(kB2, kem->length_shared_secret);
    OQS_MEM_secure_free(kA1_prime, kem->length_shared_secret);
    OQS_MEM_secure_free(skA, kem->length_shared_secret);
    OQS_MEM_secure_free(skB, kem->length_shared_secret);

    // Free
    OQS_MEM_insecure_free(ekA1);
    OQS_MEM_insecure_free(ekA2);
    OQS_MEM_insecure_free(ekB1);
    OQS_MEM_insecure_free(cA1);
    OQS_MEM_insecure_free(cB1);
    OQS_MEM_insecure_free(cB2);
    OQS_KEM_free(kem);

    clock_t end_total = times(NULL);

    ake_print_stats(begin_init,
                    end_init,
                    end_static_keys,
                    end_alg_init,
                    end_algB,
                    end_algA,
                    end_total);
   printf("----------------------------------------------------------------------------------------\n");

  }
  return OQS_SUCCESS;
}
