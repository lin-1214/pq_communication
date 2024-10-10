#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "../src/gake.h"

int main(int argc, char** argv){

  if(argc < 3){
    printf("You must provide the number of parties and KEM name!\n");
    return 1;
  }

  uint8_t verbose = 0;

  if (argc == 4) {
    verbose = 1;
  }

  int NUM_PARTIES = atoi(argv[1]);
  char* KEM = argv[2];
  int SHOW = 10;

  if(!OQS_KEM_alg_is_enabled(KEM)) {
    printf("%s is not enabled or does not exist!\n", KEM);
    printf("Available KEM are: \n");
    for (int i = 0; i < OQS_KEM_alg_count(); i++) {
      if(OQS_KEM_alg_is_enabled(OQS_KEM_alg_identifier(i)))
        printf("%s\n", OQS_KEM_alg_identifier(i));
    }
    return 1;
  }

  clock_t begin_total = clock();

  Party *pointer_to_parties;

  OQS_KEM *kem = OQS_KEM_new(KEM);
  if(kem == NULL) exit(EXIT_FAILURE);

  pointer_to_parties = malloc(sizeof(Party) * NUM_PARTIES);

  init_parties(kem, pointer_to_parties, NUM_PARTIES);

  if (verbose == 1) {
    print_parties(kem, pointer_to_parties, NUM_PARTIES, SHOW);
  }

  clock_t end_init = clock();

  // Round 1-2
  printf("Round 1-2\n");
  compute_left_right_keys(kem, pointer_to_parties, NUM_PARTIES);

  if (verbose == 1) {
    print_parties(kem, pointer_to_parties, NUM_PARTIES, SHOW);
  }
  clock_t end_12 = clock();

  // Round 3
  printf("Round 3\n");
  compute_xs_commitments(kem, pointer_to_parties, NUM_PARTIES, kem->length_shared_secret);

  if (verbose == 1) {
    print_parties(kem, pointer_to_parties, NUM_PARTIES, SHOW);
  }
  clock_t end_3 = clock();

  // Round 4
  // printf("Round 4\n");
  for (int i = 0; i < NUM_PARTIES; i++) {

    int res = check_xs(kem, pointer_to_parties, i, NUM_PARTIES, kem->length_shared_secret); // Check Xi
    int result = check_commitments(pointer_to_parties, i, NUM_PARTIES, kem->length_shared_secret); // Check commitments

    if (verbose == 1) {
      printf("\tParty %d\n", i);
    }

    if (res == 0) {
      if (verbose == 1) {
        printf("\t\tXi are zero!\n");
      }
    } else {
      if (verbose == 1) {
        printf("\t\tXi are not zero!\n");
      }
      pointer_to_parties[i].acc = 0;
      pointer_to_parties[i].term = 1;
      return 1;
    }

    if (result == 0) {
      if (verbose == 1) {
        printf("\t\tCommitments are correct!\n");
      }
    } else {
      if (verbose == 1) {
        printf("\t\tCommitments are not correct!\n");
      }
      pointer_to_parties[i].acc = 0;
      pointer_to_parties[i].term = 1;
      return 1;
    }
  }

  // Master Key
  compute_masterkey(kem, pointer_to_parties, NUM_PARTIES, kem->length_shared_secret);

  // Compute session key and session identifier
  compute_sk_sid(kem, pointer_to_parties, NUM_PARTIES, kem->length_shared_secret);

  if (verbose) {
    print_parties(kem, pointer_to_parties, NUM_PARTIES, SHOW);
  }

  // Check all keys are correct
  int res = check_all_keys(pointer_to_parties, NUM_PARTIES, kem->length_shared_secret);

  if (res == 0) {
    printf("All keys are equal!\n");

    printf("Session key: ");
    print_sk(pointer_to_parties[0].sk, kem->length_shared_secret);

    printf("Session id:  ");
    print_sk(pointer_to_parties[0].sid, kem->length_shared_secret);
  } else {
    printf("All keys are NOT equal!\n");
  }
  //

  // Free resources
  free_parties(pointer_to_parties, NUM_PARTIES);
  OQS_KEM_free(kem);

  clock_t end_4 = clock();

  print_stats(end_init, end_12, end_3, end_4, begin_total);
  return 0;
}
