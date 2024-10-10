#ifndef FSXY_AKE_H
#define FSXY_AKE_H

#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>

#include "utils.h"

#define MAX 16
#define U_A "Party A"
#define U_B "Party B"

int is_mceliece(OQS_KEM* kem);

void concat_keys(const uint8_t *key1, const uint8_t *key2, const uint8_t *key3,
                 size_t length, uint8_t *out);

void gen_sk(uint8_t *sid, uint8_t *concat_keys, size_t length_sid, size_t length_concat_keys, uint8_t *sk);


void concat_sid(OQS_KEM* kem,
                const char *UA,
                const char *UB,
                const uint8_t *ekA1,
                const uint8_t *ekB1,
                const uint8_t *cA1,
                const uint8_t *ekA2,
                const uint8_t *cB1,
                const uint8_t *cB2,
                uint8_t *sid);

void ake_init(OQS_KEM* kem,
              uint8_t* dkA1,
              uint8_t* ekB1,
              uint8_t* cA1,
              uint8_t* kA1,
              uint8_t* ekA2,
              uint8_t* dkA2);

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
              uint8_t* skB);

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
              uint8_t* skB);
#endif
