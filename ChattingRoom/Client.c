#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include "../RSAToolkit/RSA_toolkit.h"

#define PORT 8080

int sock = 0, valread;

RSA_KEY_t key;

void garbage_collector(int signum)
{
  close(sock);
  exit(0);
}

int main(int argc, char const *argv[])
{
  signal(SIGINT, garbage_collector);
  int sock = 0, valread;
  struct sockaddr_in serv_addr;
  char *hello = "Hello from client";
  char message[1024] = {0};

  // Create socket file descriptor
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
  {
    printf("\n Socket creation error \n");
    return -1;
  }

  // Set server address
  memset(&serv_addr, '0', sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);

  // Convert IPv4 and IPv6 addresses from text to binary form
  if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0)
  {
    printf("\nInvalid address/ Address not supported \n");
    return -1;
  }

  // Connect to server
  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
    printf("\nConnection Failed \n");
    return -1;
  }

  // Fork a child process for sending messages
  pid_t pid = fork();

  if (pid == -1)
  {
    printf("\nFork error\n");
    return -1;
  }
  else if (pid == 0)
  {
    signal(SIGINT, garbage_collector);
    sleep(2);
    FILE *fp = fopen("Server.key", "r");
    if (fp == NULL)
    {
      printf("Failed to open file\n");
      return 1;
    }

    char buffer[1024];
    char *public_key = NULL;
    char *n = NULL;

    while (fgets(buffer, sizeof(buffer), fp) != NULL)
    {
      if (strncmp(buffer, "PUBLIC_KEY=", strlen("PUBLIC_KEY=")) == 0)
      {
        public_key = strdup(buffer + strlen("PUBLIC_KEY="));
        public_key[strcspn(public_key, "\r\n")] = 0; // remove trailing newline
      }
      else if (strncmp(buffer, "N=", strlen("N=")) == 0)
      {
        n = strdup(buffer + strlen("N="));
        n[strcspn(n, "\r\n")] = 0; // remove trailing newline
      }

      if (public_key != NULL && n != NULL)
      {
        break; // both values found, exit loop
      }
    }

    fclose(fp);

    if (public_key == NULL || n == NULL)
    {
      printf("Failed to extract values from Client.key\n");
      return 1;
    }

    mpz_set_str(key.e, public_key, 10);
    mpz_set_str(key.n, n, 10);

    char *serverCipherTextBuffer;
    unsigned long long cipherTextLength = 0;

    // Child process: send messages to server
    while (1)
    {
      memset(message, 0, 1024);
      fgets(message, 1024, stdin);
      message[strlen(message) - 1] = '\0';

      cipherTextLength = Encrypt(message, &key, &serverCipherTextBuffer, 5);

      valread = write(sock, serverCipherTextBuffer, strlen(serverCipherTextBuffer));
      free(serverCipherTextBuffer);
    }
  }
  else
  {
    signal(SIGINT, garbage_collector);
    sleep(1);
    RSA_Key_Generate(&key, 30);
    FILE *fp = fopen("Client.key", "w");
    char *str = mpz_get_str(NULL, 10, key.e);
    fprintf(fp, "PUBLIC_KEY=%s\n", str);
    str = mpz_get_str(NULL, 10, key.n);
    fprintf(fp, "N=%s\n", str);
    fclose(fp);

    char *serverPlainTextBuffer;
    unsigned long long cipherTextLength = 0;

    // Parent process: receive messages from server
    while (1)
    {
      memset(message, 0, sizeof(message));
      valread = read(sock, message, 1024);
      // printf("\nBDebug: %s\n", message);

      cipherTextLength = Decrypt(message, &key, &serverPlainTextBuffer, 5);

      printf("<Server>: %s\n\n", serverPlainTextBuffer);
      free(serverPlainTextBuffer);
    }
  }

  return 0;
}
