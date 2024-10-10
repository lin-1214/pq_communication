#ifndef UTILS_H
#define UTILS_H

#include <time.h>
#include <sys/times.h>
#include <unistd.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/x509.h>


#ifndef PID_LENGTH
#define PID_LENGTH 20
#endif

int mod(int x, int y);
void itoa(int n, char s[]);
void reverse(char s[]);

void ake_print_stats(clock_t begin_init,
                     clock_t end_init,
                     clock_t end_keys,
                     clock_t end_alg_init,
                     clock_t end_algB,
                     clock_t end_algA,
                     clock_t end_total);

void print_hex(const uint8_t *bytes, size_t length);
void print_hex_short(const uint8_t *bytes, size_t length, size_t max);
void print_short_key_sep(const uint8_t *key, size_t length, size_t show, char* sep);
void init_to_zero(uint8_t *key, int length);
void bytes_to_hex_string(const uint8_t *bytes, size_t length, char *hex_string);
int create_cert_key(SSL_CTX *ctx, char *algname, char *certfilename, char *privkeyfilename);

#endif
