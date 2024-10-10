#ifndef GAKE_H
#define GAKE_H

#include <time.h>

#include "commitment.h"
#include "utils.h"

typedef unsigned char* MasterKey;
typedef unsigned char* X;
typedef char* Pid[PID_LENGTH];
typedef unsigned char* Coins;

typedef struct Party {
    unsigned char* public_key;
    unsigned char* secret_key;
    unsigned char* key_left;
    unsigned char* key_right;
    unsigned char* sid;
    unsigned char* sk;
    X* xs;
    Coins* coins;
    Commitment* commitments;
    MasterKey* masterkey;
    Pid* pids;
    uint8_t acc;
    uint8_t term;
} Party;

void print_sk(uint8_t *key, size_t length);
int check_keys(uint8_t *ka, uint8_t *kb, uint8_t *zero, size_t length);
void xor_keys(uint8_t *x_a, uint8_t *x_b, uint8_t *x_out, size_t length);
void two_ake(OQS_KEM* kem, uint8_t *pka, uint8_t *pkb, uint8_t *ska, uint8_t *skb, uint8_t *ka, uint8_t *kb);
void print_party(OQS_KEM* kem, Party* parties, int i, int num_parties, int show);
void print_parties(OQS_KEM* kem, Party* parties, int num_parties, int show);
void concat_masterkey(MasterKey* mk, Pid* pids, int num_parties, uint8_t *concat_mk, size_t length);
void init_parties(OQS_KEM* kem, Party* parties, int num_parties);
void free_parties(Party* parties, int num_parties);
void compute_sk_sid(OQS_KEM* kem, Party* parties, int num_parties, size_t length);
void compute_masterkey(OQS_KEM* kem, Party* parties, int num_parties, size_t length);
int check_commitments(Party* parties, int i, int num_parties, size_t length);
int check_xs(OQS_KEM* kem, Party* parties, int i, int num_parties, size_t length);
void compute_xs_commitments(OQS_KEM* kem, Party* parties, int num_parties, size_t length);
void compute_left_right_keys(OQS_KEM* kem, Party* parties, int num_parties);
int check_all_keys(Party* parties, int num_parties, size_t length);
void print_stats(clock_t end_init,
                 clock_t end_12,
                 clock_t end_3,
                 clock_t end_4,
                 clock_t begin_total);

#endif
