#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <oqs/oqs.h>

#if defined(USE_RASPBERRY_PI)
#define _RASPBERRY_PI
#endif
#if defined(OQS_SPEED_USE_ARM_PMU)
#define SPEED_USE_ARM_PMU
#endif
#include "ds_benchmark.h"
#include "system_info.h"

#include "../src/gake.h"

int main(int argc, char** argv){

  if(argc < 3){
    printf("You must provide the number of parties and a valid KEM!\n");
    return 1;
  }

  int NUM_PARTIES = atoi(argv[1]);
  char* KEM = argv[2];
  int ITERATIONS = 1;

  if(!OQS_KEM_alg_is_enabled(KEM)) {
    printf("%s is not enabled or does not exist!\n", KEM);
    printf("Available KEM are: \n");
    for (int i = 0; i < OQS_KEM_alg_count(); i++) {
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_identifier(i)))
        printf("%s\n", OQS_KEM_alg_identifier(i));
    }
    return 1;
  }

  printf("Speed test for N=%d\n", NUM_PARTIES);
  printf("==========\n");

  print_system_info();

  PRINT_TIMER_HEADER

  Party *pointer_to_parties;

  OQS_KEM *kem = OQS_KEM_new(KEM);
  if(kem == NULL) exit(EXIT_FAILURE);

  pointer_to_parties = malloc(sizeof(Party) * NUM_PARTIES);

  printf("%-30s | %10s | %14s | %15s | %10s | %25s | %10s\n", kem->method_name, "", "", "", "", "", "");

  TIME_OPERATION_ITERATIONS(
    init_parties(kem, pointer_to_parties, NUM_PARTIES),
    "init",
    ITERATIONS
  )

  // Round 1-2
  TIME_OPERATION_ITERATIONS(
    compute_left_right_keys(kem, pointer_to_parties, NUM_PARTIES),
    "round12",
    ITERATIONS
  )

  // Round 3
  TIME_OPERATION_ITERATIONS(
    compute_xs_commitments(kem, pointer_to_parties, NUM_PARTIES, kem->length_shared_secret),
    "round3",
    ITERATIONS
  )

  // Round 4
  TIME_OPERATION_ITERATIONS(
    for (int k = 0; k < NUM_PARTIES; k++) {

      int res = check_xs(kem, pointer_to_parties, k, NUM_PARTIES, kem->length_shared_secret); // Check Xi
      int result = check_commitments(pointer_to_parties, k, NUM_PARTIES, kem->length_shared_secret); // Check commitments

      if (res == 0) {
      } else {
        pointer_to_parties[k].acc = 0;
        pointer_to_parties[k].term = 1;
        return 1;
      }

      if (result == 0) {
      } else {
        pointer_to_parties[k].acc = 0;
        pointer_to_parties[k].term = 1;
        return 1;
      }
    }

    // Master Key
    compute_masterkey(kem, pointer_to_parties, NUM_PARTIES, kem->length_shared_secret);

    // Compute session key and session identifier
    compute_sk_sid(kem, pointer_to_parties, NUM_PARTIES, kem->length_shared_secret),
    "round4",
    ITERATIONS
  )

  // Free resources
  free_parties(pointer_to_parties, NUM_PARTIES);
  OQS_KEM_free(kem);

  PRINT_TIMER_FOOTER

  return 0;
}
