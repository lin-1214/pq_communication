#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "utils.h"

// https://cboard.cprogramming.com/c-programming/101643-mod-negatives.html
int mod(int x, int y){
   int t = x - ((x / y) * y);
   if (t < 0) t += y;
   return t;
}

void itoa(int n, char s[]) {
     int i, sign;

     if ((sign = n) < 0)  /* record sign */
         n = -n;          /* make n positive */
     i = 0;
     do {       /* generate digits in reverse order */
         s[i++] = n % 10 + '0';   /* get next digit */
     } while ((n /= 10) > 0);     /* delete it */
     if (sign < 0)
         s[i++] = '-';
     s[i] = '\0';
     reverse(s);
}

void reverse(char s[]) {
    int i, j;
    char c;

    for (i = 0, j = strlen(s)-1; i<j; i++, j--) {
        c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
}

void ake_print_stats(clock_t begin_init,
                 clock_t end_init,
                 clock_t end_keys,
                 clock_t end_alg_init,
                 clock_t end_algB,
                 clock_t end_algA,
                 clock_t end_total) {

   int CLOCK_TICKS = sysconf(_SC_CLK_TCK);
   double time_init     = (double)(end_init - begin_init) / CLOCK_TICKS;
   double time_keys     = (double)(end_keys - end_init) / CLOCK_TICKS;
   double time_alg_init = (double)(end_alg_init - end_keys) / CLOCK_TICKS;
   double time_alg_b    = (double)(end_algB - end_alg_init) / CLOCK_TICKS;
   double time_alg_a    = (double)(end_algA - end_algB) / CLOCK_TICKS;
   double time_total    = (double)(end_total - end_init) / CLOCK_TICKS;

   printf("\n\nTime stats\n");
   printf("\tInit time       : %.3fs (%.2f%%)\n", time_init, time_init*100/time_total);
   printf("\tRound keys time : %.3fs (%.2f%%)\n", time_keys, time_keys*100/time_total);
   printf("\tRound alg. Init : %.3fs (%.2f%%)\n", time_alg_init, time_alg_init*100/time_total);
   printf("\tRound alg. B    : %.3fs (%.2f%%)\n", time_alg_b, time_alg_b*100/time_total);
   printf("\tRound alg. A    : %.3fs (%.2f%%)\n", time_alg_a, time_alg_a*100/time_total);
   printf("\tTotal time      : %.3fs (%.2f%%)\n", time_total, time_total*100/time_total);
}

void print_hex(const uint8_t *bytes, size_t length) {
  for(size_t i = 0; i < length; i++){
    printf("%02x", bytes[i]);
  }
  printf("\n");
}

void print_hex_short(const uint8_t *bytes, size_t length, size_t max) {
  for(size_t i = 0; i < max; i++){
    printf("%02x", bytes[i]);
  }
  printf("...");
  for(size_t i = length - max; i < length; i++){
    printf("%02x", bytes[i]);
  }
  printf("\n");
}

void print_short_key_sep(const uint8_t *key, size_t length, size_t show, char* sep) {
  for (size_t i = 0; i < show; i++) {
    printf("%02x", key[i]);
  }
  printf("...");
  for (size_t i = length - show; i < length; i++) {
    printf("%02x", key[i]);
  }
  printf("%s", sep);
}

void init_to_zero(uint8_t *key, int length){
  for(int i = 0; i < length; i++){
    key[i] = 0;
  }
}

void bytes_to_hex_string(const uint8_t *bytes, size_t length, char *hex_string) {
    for (size_t i = 0; i < length; i++) {
        sprintf(hex_string + (i * 2), "%02x", bytes[i]);
    }
    hex_string[length * 2] = '\0';  // Null-terminate the string
}

int create_cert_key(SSL_CTX *ctx, char *algname, char *public_key, char *secret_key) {
    
}
