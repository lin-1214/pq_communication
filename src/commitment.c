#include <string.h>

#include "commitment.h"
#include "indcca.h"
#include "utils.h"

void print_commitment(Commitment* commitment) {
  const int DEM_LEN = commitment->kem->length_shared_secret + sizeof(int);
  print_short_key_sep(commitment->ciphertext_kem, commitment->kem->length_ciphertext, 10, "|");
  print_short_key_sep(commitment->ciphertext_dem, DEM_LEN, 10, "|");
  print_hex(commitment->tag, AES_256_GCM_TAG_LENGTH);
}

void init_commitment(OQS_KEM* kem, Commitment* commitment) {
  commitment->kem = kem;
  commitment->ciphertext_kem = malloc(kem->length_ciphertext);
  init_to_zero(commitment->ciphertext_kem, kem->length_ciphertext);
  const int DEM_LEN = commitment->kem->length_shared_secret + sizeof(int);
  commitment->ciphertext_dem = malloc(DEM_LEN);
  init_to_zero(commitment->ciphertext_dem, DEM_LEN);
  init_to_zero(commitment->tag, AES_256_GCM_TAG_LENGTH);
}

void free_commitment(Commitment* commitment) {
  free(commitment->ciphertext_kem);
  free(commitment->ciphertext_dem);
  free(commitment);
}

int commit(unsigned char* pk,
           unsigned char* m,
           int len_m,
           unsigned char* coins,
           Commitment* commitment) {

   // Coins = iv + coins kem
   unsigned char iv[AES_256_IVEC_LENGTH];
   unsigned char coins_kem[commitment->kem->length_coins];

   memcpy(iv, coins, AES_256_IVEC_LENGTH);
   memcpy(coins_kem, coins + AES_256_IVEC_LENGTH, commitment->kem->length_coins);

   int ret = pke_enc(commitment->kem,
                     m, len_m,
                     pk,
                     commitment->ciphertext_kem,
                     commitment->ciphertext_dem,
                     commitment->tag,
                     iv,
                     coins_kem);

  return ret;
}

int check_commitment(unsigned char* pk,
                     unsigned char* m,
                     unsigned char* coins,
                     Commitment* commitment_check){

  const int DEM_LEN = commitment_check->kem->length_shared_secret + sizeof(int);
  Commitment* commitment = (Commitment*) malloc(sizeof(Commitment));
  init_commitment(commitment_check->kem, commitment);
  init_to_zero(commitment->ciphertext_kem, commitment->kem->length_ciphertext);
  init_to_zero(commitment->ciphertext_dem, DEM_LEN);
  init_to_zero(commitment->tag, AES_256_GCM_TAG_LENGTH);

  commit(pk, m, DEM_LEN, coins, commitment);

  int ret_ct_kem = memcmp(commitment->ciphertext_kem, commitment_check->ciphertext_kem, commitment->kem->length_ciphertext);
  int ret_ct_dem = memcmp(commitment->ciphertext_dem, commitment_check->ciphertext_dem, DEM_LEN);
  int ret_tag    = memcmp(commitment->tag, commitment_check->tag, AES_256_GCM_TAG_LENGTH);

  free_commitment(commitment);

  if (ret_ct_kem != 0 || ret_ct_dem != 0 || ret_tag != 0) {
    return 1;
  }

  return 0;

}
