#include <stdio.h>
#include <time.h>
#include "../RSAToolkit/RSA_toolkit.h"

#include <gmp.h>

void prime_factorization(mpz_t n, mpz_t p, mpz_t q);

void Analysis(int key_size);

int main()
{
  for (int key_size = 28; key_size <= 128; key_size++)
  {
    Analysis(key_size);
  }

  return 0;
}

void prime_factorization(mpz_t n, mpz_t p, mpz_t q)
{
  mpz_t i, j, sqrt_n;
  mpz_init_set_ui(i, 2);
  mpz_init(j);
  mpz_init(sqrt_n);
  mpz_sqrt(sqrt_n, n);
  mpz_sqrt(sqrt_n, n);

  while (mpz_cmp(i, sqrt_n) < 0)
  {
    mpz_mod(j, n, i);
    if (mpz_cmp_ui(j, 0) == 0)
    {
      mpz_divexact(p, n, i);
      mpz_divexact(q, n, p);
      break;
    }
    mpz_add_ui(i, i, 1);
  }

  mpz_clear(i);
  mpz_clear(j);
  mpz_clear(sqrt_n);
}

void Analysis(int key_size)
{
  char plainText[1024] = "this message is used for analysis purpose this message is used for analysis purpose this message is used for analysis purpose this message is used for analysis purpose this message is used for analysis purpose";

  // Generate public key and private key
  RSA_KEY_t key;
  RSA_Key_Generate(&key, key_size);
  // RSA_Key_print(&key);
  printf("\nKey Size: %d bits\n", key_size);

  mpz_t p, q;
  mpz_init(p);
  mpz_init(q);

  clock_t start_time = clock();
  prime_factorization(key.n, p, q);
  clock_t end_time = clock();
  double attack_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

  printf("Attack Time: %f seconds\n", attack_time);

  FILE *enc_file = fopen("bruteforce_attack_time.txt", "a");
  fprintf(enc_file, "%f\n", attack_time);
  fclose(enc_file);

  if (((mpz_cmp(key.p, p) == 0) && (mpz_cmp(key.q, q) == 0)) || ((mpz_cmp(key.p, q) == 0) && (mpz_cmp(key.q, p) == 0)))
  {
    printf("PASSED\n\n");
  }
  else
  {
    printf("FAILED\n\n");
  }

  RSA_free(&key);
  mpz_clear(p);
  mpz_clear(q);
}