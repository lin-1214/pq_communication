#include <openssl/rand.h>
#include <string.h>

#include "../src/aes256gcm.h"
#include "../src/utils.h"

int main() {

  unsigned char* plaintext = (unsigned char *) "The quick brown fox jumps over the lazy dog";
  int plaintext_len = strlen((char *) plaintext);

  unsigned char* aad = (unsigned char *) "";
  int aad_len = strlen((char *) plaintext);

  unsigned char key[AES_256_KEY_LENGTH];
  unsigned char iv[AES_256_IVEC_LENGTH];

  if(RAND_bytes(key, AES_256_KEY_LENGTH) != 1) return 1;
  if(RAND_bytes(iv,  AES_256_IVEC_LENGTH) != 1) return 1;

  printf("key: ");
  print_hex(key, AES_256_KEY_LENGTH);
  printf("iv: ");
  print_hex(iv, AES_256_IVEC_LENGTH);

  printf("plaintext: %s\n", plaintext);

  int iv_len = sizeof(iv);

  unsigned char ciphertext[1000];
  unsigned char tag[AES_256_GCM_TAG_LENGTH];

  int ciphertext_len = gcm_encrypt(plaintext, plaintext_len,
                                   aad, aad_len,
                                   key,
                                   iv, iv_len,
                                   ciphertext,
                                   tag);

  if (ciphertext_len == -1) {
    printf("Error!\n");
    return 1;
  }

  printf("Ciphertext: ");
  print_hex(ciphertext, ciphertext_len);
  printf("Tag: ");
  print_hex(tag, AES_256_GCM_TAG_LENGTH);

  unsigned char plaintext_dec[1000];

  plaintext_len = gcm_decrypt(ciphertext, ciphertext_len,
                              aad, aad_len,
                              tag,
                              key,
                              iv, iv_len,
                              plaintext_dec);

  if (plaintext_len == -1) {
    printf("Error!\n");
    return 1;
  }

  plaintext_dec[plaintext_len] = '\0';
  printf("Plaintext: %s\n", plaintext_dec);

  return 0;
}
