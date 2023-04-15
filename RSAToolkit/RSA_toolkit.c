#include "RSA_toolkit.h"

void reverse_string(char *str)
{
  int len = strlen(str);
  int i, j;
  char temp;

  for (i = 0, j = len - 1; i < j; i++, j--)
  {
    temp = str[i];
    str[i] = str[j];
    str[j] = temp;
  }
}

void RSA_Key_Generate(RSA_KEY_t *key, int nbits)
{
  mpz_t gcd, eul_quot;
  gmp_randstate_t state;

  // initialize GMP variables
  mpz_init(key->p);
  mpz_init(key->q);
  mpz_init(key->n);
  mpz_init(key->phi_n);
  mpz_init(key->e);
  mpz_init(key->d);
  mpz_init(gcd);
  mpz_init(eul_quot);
  gmp_randinit_default(state);
  gmp_randseed_ui(state, time(NULL));

  // generate random primes p and q with specified bit size
  mpz_urandomb(key->p, state, nbits / 2);
  mpz_urandomb(key->q, state, nbits / 2);
  mpz_nextprime(key->p, key->p);
  mpz_nextprime(key->q, key->q);

  // calculate n and phi_n
  mpz_mul(key->n, key->p, key->q);
  mpz_sub_ui(key->p, key->p, 1);
  mpz_sub_ui(key->q, key->q, 1);
  mpz_mul(key->phi_n, key->p, key->q);
  mpz_tdiv_q(eul_quot, key->phi_n, key->p);
  mpz_add_ui(key->p, key->p, 1);
  mpz_add_ui(key->q, key->q, 1);

  // generate random public key e
  do
  {
    mpz_urandomm(key->e, state, key->phi_n);
    mpz_add_ui(key->e, key->e, 2);
    mpz_gcd(gcd, key->e, key->phi_n);
  } while (mpz_cmp_ui(gcd, 1) != 0);

  // calculate private key d
  mpz_invert(key->d, key->e, key->phi_n);

  mpz_clear(gcd);
  mpz_clear(eul_quot);
  gmp_randclear(state);
}

void RSA_free(RSA_KEY_t *key)
{
  mpz_clear(key->p);
  mpz_clear(key->q);
  mpz_clear(key->n);
  mpz_clear(key->phi_n);
  mpz_clear(key->e);
  mpz_clear(key->d);
}

void RSA_Key_print(RSA_KEY_t *key)
{

  char *p = mpz_get_str(NULL, 10, key->p);
  char *q = mpz_get_str(NULL, 10, key->q);
  char *n = mpz_get_str(NULL, 10, key->n);
  char *phi_n = mpz_get_str(NULL, 10, key->phi_n);
  char *e = mpz_get_str(NULL, 10, key->e);
  char *d = mpz_get_str(NULL, 10, key->d);

  printf("================= RSA Key =================\n");
  printf("p = %s\n", p);
  printf("q = %s\n", q);
  printf("n = %s\n", n);
  printf("phi_n = %s\n", phi_n);
  printf("e = %s\n", e);
  printf("d = %s\n\n", d);

  free(p);
  free(q);
  free(n);
  free(phi_n);
  free(e);
  free(d);
}

void encrypt(mpz_t m, RSA_KEY_t *key, mpz_t c)
{
  mpz_powm(c, m, key->e, key->n);
}

void decrypt(mpz_t c, RSA_KEY_t *key, mpz_t m)
{
  mpz_powm(m, c, key->d, key->n);
}

int encode(char *plainText, char ***cipherText, int n)
{
  unsigned long long code = 0;
  char tempCipherTextBuf[128];

  *cipherText = (char **)malloc(sizeof(char *) * (int)ceil((unsigned long long)strlen(plainText) / (double)n));
  int k = 0;

  unsigned long long i = 0;
  if (strlen(plainText) % 5 != 0)
  {
    for (i = 0; i <= (unsigned long long)(ceil((unsigned long long)strlen(plainText) / (double)n) * n) - (unsigned long long)strlen(plainText); i++)
    {
      plainText[strlen(plainText) + i] = ' ';
    }
    plainText[strlen(plainText) + i] = '\0';

    i = 0;
  }

  for (unsigned long long i = 0; i < (unsigned long long)strlen(plainText); i += n)
  {
    (*cipherText)[k] = malloc(sizeof(char) * 1024);
    code = 0;

    for (unsigned long long j = 0; j < n; j++)
    {
      switch (plainText[i + j])
      {
      case '0':
        code += 0 * (unsigned long long)pow(37, n - j - 1);
        break;
      case '1':
        code += 1 * (unsigned long long)pow(37, n - j - 1);
        break;
      case '2':
        code += 2 * (unsigned long long)pow(37, n - j - 1);
        break;
      case '3':
        code += 3 * (unsigned long long)pow(37, n - j - 1);
        break;
      case '4':
        code += 4 * (unsigned long long)pow(37, n - j - 1);
        break;
      case '5':
        code += 5 * (unsigned long long)pow(37, n - j - 1);
        break;
      case '6':
        code += 2 * (unsigned long long)pow(37, n - j - 1);
        break;
      case '7':
        code += 7 * (unsigned long long)pow(37, n - j - 1);
        break;
      case '8':
        code += 8 * (unsigned long long)pow(37, n - j - 1);
        break;
      case '9':
        code += 9 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'a':
      case 'A':
        code += 10 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'b':
      case 'B':
        code += 11 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'c':
      case 'C':
        code += 12 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'd':
      case 'D':
        code += 13 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'e':
      case 'E':
        code += 14 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'f':
      case 'F':
        code += 15 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'g':
      case 'G':
        code += 16 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'h':
      case 'H':
        code += 17 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'i':
      case 'I':
        code += 18 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'j':
      case 'J':
        code += 19 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'k':
      case 'K':
        code += 20 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'l':
      case 'L':
        code += 21 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'm':
      case 'M':
        code += 22 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'n':
      case 'N':
        code += 23 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'o':
      case 'O':
        code += 24 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'p':
      case 'P':
        code += 25 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'q':
      case 'Q':
        code += 26 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'r':
      case 'R':
        code += 27 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 's':
      case 'S':
        code += 28 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 't':
      case 'T':
        code += 29 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'u':
      case 'U':
        code += 30 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'v':
      case 'V':
        code += 31 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'w':
      case 'W':
        code += 32 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'x':
      case 'X':
        code += 33 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'y':
      case 'Y':
        code += 34 * (unsigned long long)pow(37, n - j - 1);
        break;
      case 'z':
      case 'Z':
        code += 35 * (unsigned long long)pow(37, n - j - 1);
        break;

      default:
        code += 36 * (unsigned long long)pow(37, n - j - 1);
        break;
      }
    }

    sprintf(tempCipherTextBuf, "%lld", code);
    strcpy((*cipherText)[k++], tempCipherTextBuf);
    memset(tempCipherTextBuf, 0, 128);
  }

  return k;
}

void decode(char ***cipherText, char **plainText, int n, int nBlocks)
{
  unsigned long long code = 0;
  unsigned long long tempCode = 0;

  *plainText = (char *)malloc(sizeof(char) * 1024);
  char temp[64];
  memset(*plainText, '\0', 128);

  for (int k = 0; k < nBlocks; k++)
  {
    tempCode = strtoull((*cipherText)[k], NULL, 10);

    for (int i = 0; i < n; i++)
    {
      switch (tempCode % 37)
      {
      case 0:
        temp[i] = '0';
        break;
      case 1:
        temp[i] = '1';
        break;
      case 2:
        temp[i] = '2';
        break;
      case 3:
        temp[i] = '3';
        break;
      case 4:
        temp[i] = '4';
        break;
      case 5:
        temp[i] = '5';
        break;
      case 6:
        temp[i] = '6';
        break;
      case 7:
        temp[i] = '7';
        break;
      case 8:
        temp[i] = '8';
        break;
      case 9:
        temp[i] = '9';
        break;
      case 10:
        temp[i] = 'a';
        break;
      case 11:
        temp[i] = 'b';
        break;
      case 12:
        temp[i] = 'c';
        break;
      case 13:
        temp[i] = 'd';
        break;
      case 14:
        temp[i] = 'e';
        break;
      case 15:
        temp[i] = 'f';
        break;
      case 16:
        temp[i] = 'g';
        break;
      case 17:
        temp[i] = 'h';
        break;
      case 18:
        temp[i] = 'i';
        break;
      case 19:
        temp[i] = 'j';
        break;
      case 20:
        temp[i] = 'k';
        break;
      case 21:
        temp[i] = 'l';
        break;
      case 22:
        temp[i] = 'm';
        break;
      case 23:
        temp[i] = 'n';
        break;
      case 24:
        temp[i] = 'o';
        break;
      case 25:
        temp[i] = 'p';
        break;
      case 26:
        temp[i] = 'q';
        break;
      case 27:
        temp[i] = 'r';
        break;
      case 28:
        temp[i] = 's';
        break;
      case 29:
        temp[i] = 't';
        break;
      case 30:
        temp[i] = 'u';
        break;
      case 31:
        temp[i] = 'v';
        break;
      case 32:
        temp[i] = 'w';
        break;
      case 33:
        temp[i] = 'x';
        break;
      case 34:
        temp[i] = 'y';
        break;
      case 35:
        temp[i] = 'z';
        break;
      case 36:
        temp[i] = ' ';
        break;

      default:
        temp[i] = ' ';
        break;
      }

      tempCode /= 37;
    }
    reverse_string(temp);
    strcat(*plainText, temp);
    memset(temp, 0, 64);
  }
}

int Encrypt(char *plainText, RSA_KEY_t *key, char **ciphertext, int blockSize)
{
  // Encode the plainText
  char **encodedPlainText;
  int nBlocks = encode(plainText, &encodedPlainText, blockSize);
  *ciphertext = (char *)malloc(sizeof(char) * strlen(plainText) * 50);
  // memset(ciphertext, 0, strlen(plainText) * 50);

  // Encrypt the encoded plainText
  mpz_t cipherBlocks[nBlocks];
  mpz_t tempCode;
  mpz_init(tempCode);
  char tempStr[128];
  for (int i = 0; i < nBlocks; i++)
  {
    mpz_init(cipherBlocks[i]);
    mpz_set_str(tempCode, encodedPlainText[i], 10);
    encrypt(tempCode, key, cipherBlocks[i]);
    mpz_get_str(tempStr, 10, cipherBlocks[i]);
    if (i == 0)
      strcpy(*ciphertext, tempStr);
    else
    {
      strcat(*ciphertext, tempStr);
    }
    strcat(*ciphertext, ".");
  }
  mpz_clear(tempCode);

  return strlen(*ciphertext);
}

int splitIntoBlocks(char *str, char ***blocks) {
  int n = 0;
  char *str_copy = strdup(str);  // create a copy of the input string
  char *token = strtok(str_copy, ".");
  while (token) {
    n++;
    token = strtok(NULL, ".");
  }
  free(str_copy);  // free the copy of the input string

  *blocks = (char **)malloc(sizeof(char *) * n);
  token = strtok(str, ".");
  for (int i = 0; i < n; i++) {
    (*blocks)[i] = (char *)malloc(sizeof(char) * strlen(token));
    strcpy((*blocks)[i], token);
    token = strtok(NULL, ".");
  }

  return n;
}

int Decrypt(char *ciphertext, RSA_KEY_t *key, char **plaintext, int blockSize)
{
  // Split the ciphertext into blocks
  char **cipherBlocks;
  int nBlocks = splitIntoBlocks(ciphertext, &cipherBlocks);

  // Decrypt each cipher block
  char **decodedCipherText;
  decodedCipherText = (char **)malloc(sizeof(char *) * nBlocks);
  for (int i = 0; i < nBlocks; i++)
  {
    mpz_t cipherCode;
    mpz_init(cipherCode);
    mpz_set_str(cipherCode, cipherBlocks[i], 10);
    mpz_t plainCode;
    mpz_init(plainCode);
    decrypt(cipherCode, key, plainCode);
    decodedCipherText[i] = (char *)malloc(sizeof(char) * 50);
    mpz_get_str(decodedCipherText[i], 10, plainCode);
    mpz_clear(cipherCode);
    mpz_clear(plainCode);
  }

  // Decode the plain text
  *plaintext = (char *)malloc(sizeof(char) * strlen(ciphertext));
  decode(&decodedCipherText, plaintext, blockSize, nBlocks);

  // Clean up memory
  for (int i = 0; i < nBlocks; i++)
  {
    free(cipherBlocks[i]);
    free(decodedCipherText[i]);
  }
  free(cipherBlocks);
  free(decodedCipherText);

  return strlen(*plaintext);
}
