#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>

#include "fsxy-ake.h"

int is_mceliece(OQS_KEM* kem) {
  return strstr(kem->method_name, "McEliece") != NULL ? 1 : 0;
}

void concat_keys(const uint8_t *key1, const uint8_t *key2, const uint8_t *key3,
                 size_t length, uint8_t *out) {
  memcpy(out, key1, length);
  memcpy(out + length, key2, length);
  memcpy(out + 2*length, key3, length);
}

void concat_sid(OQS_KEM* kem,
                const char *UA,
                const char *UB,
                const uint8_t *ekA1,
                const uint8_t *ekB1,
                const uint8_t *cA1,
                const uint8_t *ekA2,
                const uint8_t *cB1,
                const uint8_t *cB2,
                uint8_t *sid) {

  strncpy((char *)sid, UA, PID_LENGTH);
  strncpy((char *)sid + PID_LENGTH, UB, PID_LENGTH);
  memcpy(sid + 2*PID_LENGTH, ekA1, kem->length_public_key);
  memcpy(sid + 2*PID_LENGTH + kem->length_public_key, ekA2, kem->length_public_key);
  memcpy(sid + 2*PID_LENGTH + 2*kem->length_public_key, ekB1, kem->length_public_key);
  memcpy(sid + 2*PID_LENGTH + 3*kem->length_public_key, cA1, kem->length_ciphertext);
  memcpy(sid + 2*PID_LENGTH + 3*kem->length_public_key + kem->length_ciphertext, cB1, kem->length_ciphertext);
  memcpy(sid + 2*PID_LENGTH + 3*kem->length_public_key + 2*kem->length_ciphertext, cB2, kem->length_ciphertext);
}

void gen_sk(uint8_t *sid, uint8_t *concat_keys, size_t length_sid, size_t length_concat_keys, uint8_t *sk){
  uint8_t *temp = malloc(length_sid + length_concat_keys);
  memcpy(temp, concat_keys, length_concat_keys);
  memcpy(temp + length_concat_keys, sid, length_sid);
  OQS_SHA3_sha3_256(sk, temp, length_sid + length_concat_keys);
  OQS_MEM_secure_free(temp, length_sid + length_concat_keys);
}

void ake_init(OQS_KEM* kem,
              uint8_t* dkA1,
              uint8_t* ekB1,
              uint8_t* cA1,
              uint8_t* kA1,
              uint8_t* ekA2,
              uint8_t* dkA2) {

  uint8_t *rA1 = malloc(kem->length_shared_secret);
  OQS_randombytes(rA1, kem->length_shared_secret);

  uint8_t *tempA1 = malloc(kem->length_shared_secret + kem->length_secret_key);
  uint8_t *hashA1 = malloc(kem->length_shared_secret);
  memcpy(tempA1, rA1, kem->length_shared_secret);
  memcpy(tempA1 + kem->length_shared_secret, dkA1, kem->length_secret_key);
  OQS_SHA3_sha3_256(hashA1, tempA1, kem->length_shared_secret + kem->length_secret_key);

  uint8_t *coins = malloc(kem->length_coins);
  if (is_mceliece(kem)) {
    kem->gen_e(coins);
  } else {
    OQS_randombytes(coins, kem->length_coins);
  }

  OQS_KEM_encaps(kem, cA1, kA1, ekB1, coins);

  OQS_KEM_keypair(kem, ekA2, dkA2);

  OQS_MEM_secure_free(tempA1, kem->length_shared_secret + kem->length_secret_key);
  OQS_MEM_secure_free(hashA1, kem->length_shared_secret);
  OQS_MEM_secure_free(rA1, kem->length_shared_secret);
  OQS_MEM_secure_free(coins, kem->length_coins);
}

void ake_algB(OQS_KEM* kem,
              const uint8_t* ekA1,
              const uint8_t* ekA2,
              const uint8_t* dkB1,
              uint8_t* kB1,
              uint8_t* kB2,
              uint8_t* cA1,
              uint8_t* cB1,
              uint8_t* cB2,
              uint8_t* kA1,
              uint8_t* ekB1,
              uint8_t* skB) {

  uint8_t *rB1 = malloc(kem->length_shared_secret);
  uint8_t *coins = malloc(kem->length_coins);

  const size_t sid_length = 2*PID_LENGTH + 3*kem->length_public_key + 3*kem->length_ciphertext;

  OQS_randombytes(rB1, kem->length_shared_secret);

  uint8_t *tempB1 = malloc(kem->length_shared_secret + kem->length_secret_key);
  uint8_t *hashB1 = malloc(kem->length_shared_secret);
  uint8_t *sid = malloc(sid_length);

  memcpy(tempB1, rB1, kem->length_shared_secret);
  memcpy(tempB1 + kem->length_shared_secret, dkB1, kem->length_secret_key);
  OQS_SHA3_sha3_256(hashB1, tempB1, kem->length_shared_secret + kem->length_secret_key);

  if (is_mceliece(kem)) {
    kem->gen_e(coins);
  } else {
    OQS_randombytes(coins, kem->length_coins);
  }
  OQS_KEM_encaps(kem, cB1, kB1, ekA1, coins);

  if (is_mceliece(kem)) {
    kem->gen_e(coins);
  } else {
    OQS_randombytes(coins, kem->length_coins);
  }
  OQS_KEM_encaps(kem, cB2, kB2, ekA2, coins);

  OQS_KEM_decaps(kem, kA1, cA1, dkB1);

  uint8_t *concat_keysB = malloc(3*kem->length_shared_secret);
  concat_keys(kA1, kB1, kB2, kem->length_shared_secret, concat_keysB);
  concat_sid(kem, U_A, U_B, ekA1, ekB1, cA1, ekA2, cB1, cB2, sid);
  gen_sk(sid, concat_keysB, sid_length, 3*kem->length_shared_secret, skB);

  OQS_MEM_secure_free(concat_keysB, 3*kem->length_shared_secret);
  OQS_MEM_secure_free(tempB1, kem->length_shared_secret + kem->length_secret_key);
  OQS_MEM_secure_free(hashB1, kem->length_shared_secret);
  OQS_MEM_secure_free(rB1, kem->length_shared_secret);
  OQS_MEM_secure_free(coins, kem->length_coins);
  OQS_MEM_secure_free(sid, sid_length);
}

void ake_algA(OQS_KEM* kem,
              const uint8_t* cB1,
              const uint8_t* cB2,
              const uint8_t* dkA1,
              const uint8_t* dkA2,
              const uint8_t* kA1,
              const uint8_t* ekA1,
              const uint8_t* ekB1,
              const uint8_t* ekA2,
              const uint8_t* cA1,
              uint8_t* skB){

  const size_t sid_length = 2*PID_LENGTH + 3*kem->length_public_key + 3*kem->length_ciphertext;
  uint8_t *sid = malloc(sid_length);

  uint8_t *kB1_prime = malloc(kem->length_shared_secret);
  OQS_KEM_decaps(kem, kB1_prime, cB1, dkA1);

  uint8_t *kB2_prime = malloc(kem->length_shared_secret);
  OQS_KEM_decaps(kem, kB2_prime, cB2, dkA2);

  uint8_t *concat_keysA = malloc(3*kem->length_shared_secret);
  concat_keys(kA1, kB1_prime, kB2_prime, kem->length_shared_secret, concat_keysA);
  concat_sid(kem, U_A, U_B, ekA1, ekB1, cA1, ekA2, cB1, cB2, sid);
  gen_sk(sid, concat_keysA, sid_length, 3*kem->length_shared_secret, skB);

  OQS_MEM_secure_free(concat_keysA, 3*kem->length_shared_secret);
  OQS_MEM_secure_free(kB1_prime, kem->length_shared_secret);
  OQS_MEM_secure_free(kB2_prime, kem->length_shared_secret);
  OQS_MEM_secure_free(sid, sid_length);

}
