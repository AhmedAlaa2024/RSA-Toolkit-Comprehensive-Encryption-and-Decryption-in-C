#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <gmp.h>

typedef struct RSA_KEY {
  mpz_t p;
  mpz_t q;
  mpz_t n;
  mpz_t phi_n;
  mpz_t e;
  mpz_t d;
} RSA_KEY_t;

void RSA_Key_Generate(RSA_KEY_t *key, int nbits);
void RSA_free(RSA_KEY_t *key);
void RSA_Key_print(RSA_KEY_t *key);
void encrypt(mpz_t m, RSA_KEY_t *key, mpz_t c);
void decrypt(mpz_t c, RSA_KEY_t *key, mpz_t m);
int encode(char *plainText, char*** cipherText, int n);
void decode(char*** cipherText, char** plainText, int n, int nBlocks);

int Encrypt(char *plainText, RSA_KEY_t *key, char **ciphertext, int blockSize);
int Decrypt(char *ciphertext, RSA_KEY_t *key, char **plaintext, int blockSize);