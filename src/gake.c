#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "gake.h"
#include "fsxy-ake.h"
#include "commitment.h"

void print_sk(uint8_t *key, size_t length) {
  for(size_t j = 0; j < length; j++){
    printf("%02x", key[j]);
  }
  printf("\n");
}

void xor_keys(uint8_t *x_a, uint8_t *x_b, uint8_t *x_out, size_t length){

  for (size_t j = 0; j < length; j++) {
    x_out[j] = x_a[j] ^ x_b[j];
  }
}

int check_keys(uint8_t *ka, uint8_t *kb, uint8_t *zero, size_t length) {
  if(memcmp(ka, kb, length) != 0){
    return 1;
  }

  if(!memcmp(ka, zero, length)){
    return 2;
  }

  return 0;
}

void two_ake(OQS_KEM* kem, uint8_t *ekA1, uint8_t *ekB1, uint8_t *dkA1, uint8_t *dkB1, uint8_t *skA, uint8_t *skB){

  uint8_t *cA1 = malloc(kem->length_ciphertext);
  uint8_t *kA1 = malloc(kem->length_shared_secret);
  uint8_t *ekA2 = malloc(kem->length_public_key);
  uint8_t *dkA2 = malloc(kem->length_secret_key);
  uint8_t *cB1 = malloc(kem->length_ciphertext);
  uint8_t *kB1 = malloc(kem->length_shared_secret);
  uint8_t *cB2 = malloc(kem->length_ciphertext);
  uint8_t *kB2 = malloc(kem->length_shared_secret);
  uint8_t *kA1_prime = malloc(kem->length_shared_secret);

  ake_init(kem, dkA1, ekB1, cA1, kA1, ekA2, dkA2);
  ake_algB(kem, ekA1, ekA2, dkB1, kB1, kB2, cA1, cB1, cB2, kA1_prime, ekB1, skB);
  ake_algA(kem, cB1, cB2, dkA1, dkA2, kA1, ekA1, ekB1, ekA2, cA1, skA);

  // Delete secrets and free
  OQS_MEM_secure_free(dkA2, kem->length_secret_key);
  OQS_MEM_secure_free(kA1, kem->length_shared_secret);
  OQS_MEM_secure_free(kB1, kem->length_shared_secret);
  OQS_MEM_secure_free(kB2, kem->length_shared_secret);
  OQS_MEM_secure_free(kA1_prime, kem->length_shared_secret);

  // Free
  OQS_MEM_insecure_free(cA1);
  OQS_MEM_insecure_free(cB1);
  OQS_MEM_insecure_free(cB2);
  OQS_MEM_insecure_free(ekA2);

}

void concat_masterkey(MasterKey* mk, Pid* pids, int num_parties, uint8_t *concat_mk, size_t length) {
  for (int i = 0; i < num_parties; i++) {
    memcpy(concat_mk + i*length, mk[i], length);
  }

  for (int j = 0; j < num_parties; j++) {
    memcpy(concat_mk + num_parties*length + PID_LENGTH*j, pids[j], PID_LENGTH);
  }
}

void print_party(OQS_KEM* kem, Party* parties, int i, int num_parties, int show) {
  printf("Party %d\n", i);

  printf("\tPublic key:  ");
  print_hex_short(parties[i].public_key, kem->length_public_key, show);

  printf("\tSecret key:  ");
  print_hex_short(parties[i].secret_key, kem->length_secret_key, show);

  printf("\tLeft key:    ");
  print_hex_short(parties[i].key_left, kem->length_shared_secret, show);

  printf("\tRight key:   ");
  print_hex_short(parties[i].key_right, kem->length_shared_secret, show);

  printf("\tSession id:  ");
  print_hex_short(parties[i].sid, kem->length_shared_secret, show);

  printf("\tSession key: ");
  print_hex_short(parties[i].sk, kem->length_shared_secret, show);

  printf("\tX: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tX%d: ", j);
    print_hex_short(parties[i].xs[j], kem->length_shared_secret, show);
  }

  const int COMMITMENTCOINSBYTES = AES_256_IVEC_LENGTH + kem->length_coins;

  printf("\tCoins: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tr%d: ", j);
    print_hex_short(parties[i].coins[j], COMMITMENTCOINSBYTES, show);
  }

  printf("\tCommitments:\n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tc%d: ", j);
    print_commitment(&parties[i].commitments[j]);
  }

  printf("\tMaster Key: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tk%d: ", j);
    print_hex_short(parties[i].masterkey[j], kem->length_shared_secret, show);
  }

  printf("\tPids: \n");
  for (int j = 0; j < num_parties; j++) {
    printf("\t\tpid%d: %s\n", j, (char*) parties[i].pids[j]);
  }

  printf("\tAccepted:   %d\n", parties[i].acc);
  printf("\tTerminated: %d\n", parties[i].term);
}

void init_parties(OQS_KEM* kem, Party* parties, int num_parties) {
  for (int i = 0; i < num_parties; i++) {
    parties[i].commitments = malloc(sizeof(Commitment) * num_parties);
    parties[i].masterkey = malloc(sizeof(MasterKey) * num_parties);
    parties[i].pids = malloc(sizeof(Pid) * num_parties);
    parties[i].coins = malloc(sizeof(Coins) * num_parties);
    parties[i].xs = malloc(sizeof(X) * num_parties);
    for (int j = 0; j < num_parties; j++) {
      char pid[PID_LENGTH];
      sprintf(pid, "%s %d", "Party", j);
      memcpy(parties[i].pids[j], pid, PID_LENGTH);
    }

    // const int DEM_LEN = kem->length_shared_secret + sizeof(int);
    const int COMMITMENTCOINSBYTES = AES_256_IVEC_LENGTH + kem->length_coins;

    for (int j = 0; j < num_parties; j++) {
      init_commitment(kem, &parties[i].commitments[j]);
      parties[i].coins[j] = malloc(COMMITMENTCOINSBYTES);
      init_to_zero(parties[i].coins[j], COMMITMENTCOINSBYTES);
      parties[i].masterkey[j] = malloc(kem->length_shared_secret);
      init_to_zero(parties[i].masterkey[j], kem->length_shared_secret);
      parties[i].xs[j] = malloc(kem->length_shared_secret);
      init_to_zero(parties[i].xs[j], kem->length_shared_secret);
    }

    parties[i].sid = malloc(kem->length_shared_secret);
    parties[i].sk  = malloc(kem->length_shared_secret);
    parties[i].key_left = malloc(kem->length_shared_secret);
    parties[i].key_right = malloc(kem->length_shared_secret);
    init_to_zero(parties[i].sid, kem->length_shared_secret);
    init_to_zero(parties[i].sk, kem->length_shared_secret);
    init_to_zero(parties[i].key_left, kem->length_shared_secret);
    init_to_zero(parties[i].key_right, kem->length_shared_secret);

    parties[i].public_key = malloc(kem->length_public_key);
    parties[i].secret_key  = malloc(kem->length_secret_key);
    init_to_zero(parties[i].public_key, kem->length_public_key);
    init_to_zero(parties[i].secret_key, kem->length_secret_key);

    OQS_KEM_keypair(kem,
                    parties[i].public_key,
                    parties[i].secret_key);

    parties[i].acc = 0;
    parties[i].term = 0;

  }
}

void print_parties(OQS_KEM* kem, Party* parties, int num_parties, int show) {
  for (int i = 0; i < num_parties; i++) {
    print_party(kem, parties, i, num_parties, show);
  }
}

void free_parties(Party* parties, int num_parties) {
  for (int i = 0; i < num_parties; i++) {
    for (int j = 0; j < num_parties; j++) {
      free(parties[i].coins[j]);
      free(parties[i].masterkey[j]);
      free(parties[i].xs[j]);
      // free_commitment(&parties[i].commitments[j]);
    }
    // free(parties[i].commitments);
    free(parties[i].masterkey);
    free(parties[i].pids);
    free(parties[i].coins);
    free(parties[i].xs);
    free(parties[i].sid);
    free(parties[i].sk);
    free(parties[i].key_left);
    free(parties[i].key_right);
    free(parties[i].public_key);
    free(parties[i].secret_key);
  }
  free(parties);
}

void compute_sk_sid(OQS_KEM* kem, Party* parties, int num_parties, size_t length) {
  for (int i = 0; i < num_parties; i++) {
    unsigned char mki[(length + PID_LENGTH*sizeof(char))*num_parties];

    // Concat master key
    concat_masterkey(parties[i].masterkey, parties[i].pids, num_parties, mki, kem->length_shared_secret);

    unsigned char sk_sid[2*length];

    OQS_SHA3_sha3_512(sk_sid, mki, 2*length);

    memcpy(parties[i].sk, sk_sid, length);
    memcpy(parties[i].sid, sk_sid + length, length);

    parties[i].acc = 1;
    parties[i].term = 1;
  }
}

void compute_masterkey(OQS_KEM* kem, Party* parties, int num_parties, size_t length) {

  for (int i = 0; i < num_parties; i++) {
    memcpy(parties[i].masterkey[i],
           parties[i].key_left, length);

    for (int j = 1; j < num_parties; j++) {
      MasterKey mk = malloc(num_parties*kem->length_shared_secret);
      memcpy(mk, parties[i].key_left, length);
      for (int k = 0; k < j; k++) {
        xor_keys(mk, parties[i].xs[mod(i-k-1,num_parties)], mk, length);
      }

      memcpy(parties[i].masterkey[mod(i-j, num_parties)],
             mk, length);

      free(mk);
    }
  }
}

int check_commitments(Party* parties, int i, int num_parties, size_t length) {
  for (int j = 0; j < num_parties; j++) {
    unsigned char msg[length + sizeof(int)];
    char buf_int[sizeof(int)];
    init_to_zero((unsigned char*) buf_int, sizeof(int));
    itoa(j, buf_int);
    memcpy(msg, parties[i].xs[j], length);
    memcpy(msg + length, buf_int, sizeof(int));

    int res_check = check_commitment(parties[j].public_key,
                     msg,
                     parties[i].coins[j],
                     &parties[i].commitments[j]);

    if (res_check != 0) {
      return 1;
    }
  }
  return 0;
}

int check_xs(OQS_KEM* kem, Party* parties, int i, int num_parties, size_t length) {
  unsigned char zero[length];

  for(size_t j = 0; j < length; j++){
    zero[j] = 0;
  }

  X check = malloc(kem->length_shared_secret);
  memcpy(check, parties[i].xs[0], length);
  for (int j = 0; j < num_parties - 1; j++) {
    xor_keys(parties[i].xs[j+1], check, check, length);
  }

  int res = memcmp(check, zero, length);
  free(check);
  if (res != 0) {
    return 1;
  }
  return 0;
}

void compute_xs_commitments(OQS_KEM* kem, Party* parties, int num_parties, size_t length) {

  for (int i = 0; i < num_parties; i++) {

    X xi;
    Coins ri;
    Commitment ci;

    const int COMMITMENTCOINSBYTES = AES_256_IVEC_LENGTH + kem->length_coins;
    const int DEM_LEN = length + sizeof(int);

    init_commitment(kem, &ci);
    ri = malloc(COMMITMENTCOINSBYTES);
    xi = malloc(length);

    unsigned char msg[length + sizeof(int)];
    init_to_zero(msg, length + sizeof(int));
    char buf_int[sizeof(int)];
    init_to_zero((unsigned char*) buf_int, sizeof(int));
    itoa(i, buf_int);

    xor_keys(parties[i].key_right, parties[i].key_left, xi, length);
    if (is_mceliece(kem)) {
      kem->gen_e(ri);
      OQS_randombytes(ri + kem->length_coins, AES_256_IVEC_LENGTH);
    } else {
      OQS_randombytes(ri, COMMITMENTCOINSBYTES);
    }


    memcpy(msg, xi, length);
    memcpy(msg + length, &buf_int, sizeof(int));
    commit(parties[i].public_key, msg, DEM_LEN, ri, &ci);
    for (int j = 0; j < num_parties; j++) {
      memcpy(parties[j].xs[i], xi, length);
      memcpy(parties[j].coins[i], ri, COMMITMENTCOINSBYTES);
      parties[j].commitments[i] = ci;
    }

    // free_commitment(&ci);
    free(ri);
    free(xi);
  }
}

void compute_left_right_keys(OQS_KEM* kem, Party* parties, int num_parties) {
  for (int i = 0; i < num_parties; i++) {
    int right = mod(i+1, num_parties);
    int left = mod(i-1, num_parties);

    two_ake(kem, parties[i].public_key, parties[right].public_key,
            parties[i].secret_key, parties[right].secret_key,
            parties[i].key_right,   parties[right].key_left);

    two_ake(kem, parties[i].public_key, parties[left].public_key,
            parties[i].secret_key, parties[left].secret_key,
            parties[i].key_left,   parties[left].key_right);
  }
}

int check_all_keys(Party* parties, int num_parties, size_t length) {
  unsigned char  sk[length];
  unsigned char sid[length];

  for (int i = 0; i < num_parties - 1; i++) {
    memcpy(sk,  parties[i].sk,  length);
    memcpy(sid, parties[i].sid, length);

    int res_sk  = memcmp(sk, parties[i+1].sk,  length);
    int res_sid = memcmp(sid, parties[i+1].sid, length);

    if (res_sk != 0 || res_sid != 0) {
      return 1;
    }

    memcpy(sk,  parties[i+1].sk,  length);
    memcpy(sid, parties[i+1].sid, length);

  }
  return 0;
}

void print_stats(clock_t end_init,
                 clock_t end_12,
                 clock_t end_3,
                 clock_t end_4,
                 clock_t begin_total) {

   double time_init  = (double)(end_init - begin_total) / CLOCKS_PER_SEC;
   double time_12    = (double)(end_12 - end_init) / CLOCKS_PER_SEC;
   double time_3     = (double)(end_3 - end_12) / CLOCKS_PER_SEC;
   double time_4     = (double)(end_4 - end_3) / CLOCKS_PER_SEC;
   double time_total = (double)(end_4 - begin_total) / CLOCKS_PER_SEC;

   printf("\n\nTime stats\n");
   printf("\tInit time      : %.3fs (%.2f%%)\n", time_init, time_init*100/time_total);
   printf("\tRound 1-2 time : %.3fs (%.2f%%)\n", time_12, time_12*100/time_total);
   printf("\tRound 3 time   : %.3fs (%.2f%%)\n", time_3, time_3*100/time_total);
   printf("\tRound 4 time   : %.3fs (%.2f%%)\n", time_4, time_4*100/time_total);
   printf("\tTotal time     : %.3fs (%.2f%%)\n", time_total, time_total*100/time_total);
}
