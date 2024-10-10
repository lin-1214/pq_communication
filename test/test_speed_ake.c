// SPDX-License-Identifier: MIT

#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <oqs/oqs.h>

#if defined(USE_RASPBERRY_PI)
#define _RASPBERRY_PI
#endif
#if defined(OQS_SPEED_USE_ARM_PMU)
#define SPEED_USE_ARM_PMU
#endif
#include "ds_benchmark.h"
#include "system_info.h"
#include "../src/fsxy-ake.h"
#include "../src/utils.h"

static OQS_STATUS ake_speed_wrapper(const char *method_name, int iterations, bool printInfo) {

	OQS_KEM *kem = NULL;
  uint8_t *cA1 = NULL;
  uint8_t *kA1 = NULL;
  uint8_t *ekA1 = NULL;
  uint8_t *dkA1 = NULL;
  uint8_t *ekA2 = NULL;
  uint8_t *dkA2 = NULL;
  uint8_t *ekB1 = NULL;
  uint8_t *dkB1 = NULL;
  uint8_t *cB1 = NULL;
  uint8_t *kB1 = NULL;
  uint8_t *cB2 = NULL;
  uint8_t *kB2 = NULL;
  uint8_t *skB = NULL;
  uint8_t *kA1_prime = NULL;
  uint8_t *skA = NULL;
	OQS_STATUS ret = OQS_ERROR;

	kem = OQS_KEM_new(method_name);
	if (kem == NULL) {
		return OQS_SUCCESS;
	}

  cA1 = malloc(kem->length_ciphertext);
  kA1 = malloc(kem->length_shared_secret);
  ekA2 = malloc(kem->length_public_key);
  dkA2 = malloc(kem->length_secret_key);
  cB1 = malloc(kem->length_ciphertext);
  kB1 = malloc(kem->length_shared_secret);
  cB2 = malloc(kem->length_ciphertext);
  kB2 = malloc(kem->length_shared_secret);
  skB = malloc(kem->length_shared_secret);
  kA1_prime = malloc(kem->length_shared_secret);
  skA = malloc(kem->length_shared_secret);
  ekA1 = malloc(kem->length_public_key);
  dkA1 = malloc(kem->length_secret_key);
  ekB1 = malloc(kem->length_public_key);
  dkB1 = malloc(kem->length_secret_key);

	if ((cA1 == NULL) ||
      (kA1 == NULL) ||
      (ekA2 == NULL) ||
      (dkA2 == NULL) ||
      (cB1 == NULL) ||
      (kB1 == NULL) ||
      (cB2 == NULL) ||
      (kB2 == NULL) ||
      (skB == NULL) ||
      (kA1_prime == NULL) ||
      (skA == NULL) ||
      (ekA1 == NULL) ||
      (dkA1 == NULL) ||
      (ekB1 == NULL) ||
      (dkB1 == NULL)) {
		fprintf(stderr, "ERROR: malloc failed\n");
		goto err;
	}

  OQS_KEM_keypair(kem, ekA1, dkA1);
  OQS_KEM_keypair(kem, ekB1, dkB1);

  printf("%-30s | %10s | %14s | %15s | %10s | %25s | %10s\n", kem->method_name, "", "", "", "", "", "");
  TIME_OPERATION_ITERATIONS(
    ake_init(kem, dkA1, ekB1, cA1, kA1, ekA2, dkA2),
    "init",
    iterations
  )

  TIME_OPERATION_ITERATIONS(
		ake_algB(kem, ekA1, ekA2, dkB1, kB1, kB2, cA1, cB1, cB2, kA1_prime, ekB1, skB),
    "algB",
    iterations
  )

  TIME_OPERATION_ITERATIONS(
		ake_algA(kem, cB1, cB2, dkA1, dkA2, kA1, ekA1, ekB1, ekA2, cA1, skA),
    "algA",
    iterations
  )

	if (printInfo) {
		printf("public key bytes: %zu, ciphertext bytes: %zu, secret key bytes: %zu, shared secret key bytes: %zu, NIST level: %d, IND-CCA: %s\n", kem->length_public_key, kem->length_ciphertext, kem->length_secret_key, kem->length_shared_secret, kem->claimed_nist_level, kem->ind_cca ? "Y" : "N");
	}

	ret = OQS_SUCCESS;
	goto cleanup;

err:
	ret = OQS_ERROR;

cleanup:

	OQS_KEM_free(kem);

	return ret;
}

static OQS_STATUS printAlgs(void) {
	for (size_t i = 0; i < OQS_KEM_algs_length; i++) {
		OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_identifier(i));
		if (kem == NULL) {
			printf("%s (disabled)\n", OQS_KEM_alg_identifier(i));
		} else {
			printf("%s\n", OQS_KEM_alg_identifier(i));
		}
		OQS_KEM_free(kem);
	}
	return OQS_SUCCESS;
}

int main(int argc, char **argv) {

	int ret = EXIT_SUCCESS;
	OQS_STATUS rc;

	bool printUsage = false;
	uint64_t iterations = 10000;
	bool printKemInfo = false;

	OQS_KEM *single_kem = NULL;

	OQS_randombytes_switch_algorithm(OQS_RAND_alg_openssl);

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--algs") == 0) {
			rc = printAlgs();
			if (rc == OQS_SUCCESS) {
				return EXIT_SUCCESS;
			} else {
				return EXIT_FAILURE;
			}
		} else if ((strcmp(argv[i], "--iterations") == 0) || (strcmp(argv[i], "-d") == 0)) {
			if (i < argc - 1) {
				iterations = (uint64_t)strtol(argv[i + 1], NULL, 10);
				if (iterations > 0) {
					i += 1;
					continue;
				}
			}
		} else if ((strcmp(argv[i], "--help") == 0) || (strcmp(argv[i], "-h") == 0)) {
			printUsage = true;
			break;
		} else if ((strcmp(argv[i], "--info") == 0) || (strcmp(argv[i], "-i") == 0)) {
			printKemInfo = true;
			continue;
		} else {
			single_kem = OQS_KEM_new(argv[i]);
			if (single_kem == NULL) {
				printUsage = true;
				break;
			}
		}
	}

	if (printUsage) {
		fprintf(stderr, "Usage: speed_kem <options> <alg>\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "<options>\n");
		fprintf(stderr, "--algs             Print supported algorithms and terminate\n");
		fprintf(stderr, "--iterations n\n");
		fprintf(stderr, " -d n              Run each speed test for approximately n seconds, default n=3\n");
		fprintf(stderr, "--help\n");
		fprintf(stderr, " -h                Print usage\n");
		fprintf(stderr, "--info\n");
		fprintf(stderr, " -i                Print info (sizes, security level) about each KEM\n");
		fprintf(stderr, "\n");
		fprintf(stderr, "<alg>              Only run the specified KEM method; must be one of the algorithms output by --algs\n");
		return EXIT_FAILURE;
	}

	print_system_info();

	printf("Speed test\n");
	printf("==========\n");

	PRINT_TIMER_HEADER
	if (single_kem != NULL) {
		rc = ake_speed_wrapper(single_kem->method_name, iterations, printKemInfo);
		if (rc != OQS_SUCCESS) {
			ret = EXIT_FAILURE;
		}
	} else {
		for (size_t i = 0; i < OQS_KEM_algs_length; i++) {
			rc = ake_speed_wrapper(OQS_KEM_alg_identifier(i), iterations, printKemInfo);
			if (rc != OQS_SUCCESS) {
				ret = EXIT_FAILURE;
			}
		}
	}
	PRINT_TIMER_FOOTER

	return ret;
}
