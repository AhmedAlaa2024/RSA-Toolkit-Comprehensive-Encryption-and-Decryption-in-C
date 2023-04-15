#include <stdio.h>
#include <time.h>
#include "../RSAToolkit/RSA_toolkit.h"

void Analysis(int key_size);

int main()
{

  for (int key_size = 28; key_size <= 2024; key_size++)
  {
    Analysis(key_size);
  }

  return 0;
}

void Analysis(int key_size)
{
  char plainText[1024] = "this message is used for analysis purpose this message is used for analysis purpose this message is used for analysis purpose this message is used for analysis purpose this message is used for analysis purpose";

  // Generate public key and private key
  RSA_KEY_t key;
  RSA_Key_Generate(&key, key_size);
  printf("\nKey Size: %d bits\n", key_size);

  // Encode the plainText
  char **encodedPlainText;
  int nBlocks = encode(plainText, &encodedPlainText, 5);

  // Encrypt the encoded plainText
  mpz_t cipherBlocks[nBlocks];
  mpz_t tempCode;
  mpz_init(tempCode);
  char tempStr[128];
  clock_t start_time = clock();
  for (int i = 0; i < nBlocks; i++)
  {
    mpz_init(cipherBlocks[i]);
    mpz_set_str(tempCode, encodedPlainText[i], 10);
    encrypt(tempCode, &key, cipherBlocks[i]);
  }
  clock_t end_time = clock();
  double encryption_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

  // Decrypt the ciphertext blocks
  mpz_t decryptedBlocks[nBlocks];
  start_time = clock();
  for (int i = 0; i < nBlocks; i++)
  {
    mpz_init(decryptedBlocks[i]);
    decrypt(cipherBlocks[i], &key, decryptedBlocks[i]);
    mpz_clear(cipherBlocks[i]);
  }
  end_time = clock();
  double decryption_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

  // Decode the decrypted blocs
  char **decryptedCipherBlocks = (char **)malloc(sizeof(char *) * nBlocks);
  char *decodedDecryptedPlainText;
  for (int i = 0; i < nBlocks; i++)
  {
    decryptedCipherBlocks[i] = (char *)malloc(sizeof(char) * 128);
    mpz_get_str(decryptedCipherBlocks[i], 10, decryptedBlocks[i]);
    mpz_clear(decryptedBlocks[i]);
  }
  decode(&decryptedCipherBlocks, &decodedDecryptedPlainText, 5, nBlocks);

  printf("Encryption Time: %f seconds\n", encryption_time);
  printf("Decryption Time: %f seconds\n", decryption_time);

  FILE *enc_file = fopen("encryption_time.txt", "a");
  fprintf(enc_file, "%f\n", encryption_time);
  fclose(enc_file);

  FILE *dec_file = fopen("decryption_time.txt", "a");
  fprintf(dec_file, "%f\n", decryption_time);
  fclose(dec_file);

  if(strcmp(plainText, decodedDecryptedPlainText) == 0) {
    printf("PASSED\n");
  } else {
    printf("FAILED\n");
  }

  for (int i = 0; i < nBlocks; i++)
  {
    free(encodedPlainText[i]);
    free(decryptedCipherBlocks[i]);
  }

  free(encodedPlainText);
  free(decodedDecryptedPlainText);
  free(decryptedCipherBlocks);

  RSA_free(&key);
}
