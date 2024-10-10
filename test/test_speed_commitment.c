#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#include "../src/utils.h"
#include "../src/aes256gcm.h"
#include "../src/indcca.h"
#include "../src/commitment.h"

#include "ds_benchmark.h"
#include "system_info.h"

int is_mceliece(OQS_KEM* kem);

int is_mceliece(OQS_KEM* kem) {
  return strstr(kem->method_name, "McEliece") != NULL ? 1 : 0;
}

int main(void) {

  uint8_t *pk = NULL;
  uint8_t *sk = NULL;
  uint8_t *coins = NULL;
  uint8_t *m = NULL;

  int ITERATIONS = 10000;

  printf("Speed test\n");
  printf("==========\n");

  print_system_info();

  PRINT_TIMER_HEADER
  for (int alg = 0; alg < OQS_KEM_alg_count(); alg++) {
    if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_identifier(alg))){

      const char* KEM = OQS_KEM_alg_identifier(alg);
      OQS_KEM *kem = OQS_KEM_new(KEM);
      if(kem == NULL) exit(EXIT_FAILURE);

      printf("%-30s | %10s | %14s | %15s | %10s | %25s | %10s\n", kem->method_name, "", "", "", "", "", "");

      pk = malloc(kem->length_public_key);
      sk = malloc(kem->length_secret_key);
      coins = malloc(kem->length_secret_key);
      m = malloc(1000);

      if ((pk == NULL) ||
          (sk == NULL) ||
          (coins == NULL) ||
          (m == NULL)) {
        fprintf(stderr, "ERROR: malloc failed\n");
    		exit(EXIT_FAILURE);
      }

      pke_keypair(kem, pk, sk);

      const int COMMITMENTCOINSBYTES = AES_256_IVEC_LENGTH + kem->length_shared_secret;

      OQS_randombytes(coins, COMMITMENTCOINSBYTES);
      OQS_randombytes(m, 100);

      Commitment* commitment = malloc(sizeof(Commitment));
      TIME_OPERATION_ITERATIONS(
        init_commitment(kem, commitment),
        "init",
        ITERATIONS
      )

      const int DEM_LEN = commitment->kem->length_shared_secret + sizeof(int);
      TIME_OPERATION_ITERATIONS(
        commit(pk, m, DEM_LEN, coins, commitment),
        "commit",
        ITERATIONS
      )

      TIME_OPERATION_ITERATIONS(
        check_commitment(pk, m, coins, commitment),
        "check",
        ITERATIONS
      )

      free_commitment(commitment);

      // Delete secrets and free
      OQS_MEM_secure_free(sk, kem->length_secret_key);
      OQS_MEM_secure_free(coins, kem->length_secret_key);

      // Free
      OQS_MEM_insecure_free(pk);
      OQS_KEM_free(kem);
    }
  }
  PRINT_TIMER_FOOTER

  return OQS_SUCCESS;
}
