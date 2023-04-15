#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <signal.h>
#include "../RSAToolkit/RSA_toolkit.h"

#define PORT 8080
#define MAX_CONN 5
#define MAX_MSG_LEN 1024

int sockfd, connfd, len;

void garbage_collector(int signum)
{
  close(connfd);
  close(sockfd);
  exit(0);
}

RSA_KEY_t key;

int main()
{
  signal(SIGINT, garbage_collector);
  struct sockaddr_in servaddr, cli;
  char message[MAX_MSG_LEN];

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1)
  {
    perror("socket creation failed");
    exit(EXIT_FAILURE);
  }

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(PORT);

  if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) != 0)
  {
    perror("socket bind failed");
    exit(EXIT_FAILURE);
  }

  if (listen(sockfd, MAX_CONN) != 0)
  {
    perror("listen failed");
    exit(EXIT_FAILURE);
  }

  while (1)
  {
    len = sizeof(cli);
    connfd = accept(sockfd, (struct sockaddr *)&cli, &len);
    if (connfd < 0)
    {
      perror("accept failed");
      exit(EXIT_FAILURE);
    }

    int pid = fork();
    if (pid == -1)
    {
      perror("fork failed");
      exit(EXIT_FAILURE);
    }
    else if (pid == 0)
    {
      signal(SIGINT, garbage_collector);
      close(sockfd);

      sleep(2);
      FILE *fp = fopen("Client.key", "r");
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

      // Child process: send messages to client
      while (1)
      {
        memset(message, 0, MAX_MSG_LEN);
        fgets(message, MAX_MSG_LEN, stdin);
        message[strlen(message) - 1] = '\0';

        cipherTextLength = Encrypt(message, &key, &serverCipherTextBuffer, 5);

        int n = write(connfd, serverCipherTextBuffer, strlen(serverCipherTextBuffer));
        free(serverCipherTextBuffer);
        if (n == -1)
        {
          perror("write failed");
          exit(EXIT_FAILURE);
        }
      }
      close(connfd);
      exit(EXIT_SUCCESS);
    }
    else
    {
      signal(SIGINT, garbage_collector);
      close(sockfd);
      RSA_Key_Generate(&key, 30);
      RSA_Key_print(&key);
      FILE *fp = fopen("Server.key", "w");
      char *str = mpz_get_str(NULL, 10, key.e);
      fprintf(fp, "PUBLIC_KEY=%s\n", str);
      str = mpz_get_str(NULL, 10, key.n);
      fprintf(fp, "N=%s\n", str);
      fclose(fp);

      char *serverPlainTextBuffer;
      unsigned long long cipherTextLength = 0;

      while (1)
      {
        memset(message, 0, MAX_MSG_LEN);
        int n = read(connfd, message, MAX_MSG_LEN);
        // printf("\nBDebug: %s\n", message);
        cipherTextLength = Decrypt(message, &key, &serverPlainTextBuffer, 5);

        if (n == -1)
        {
          perror("read failed");
          exit(EXIT_FAILURE);
        }
        else if (n == 0)
        {
          printf("Client disconnected\n");
          break;
        }
        printf("<Client>: %s\n", serverPlainTextBuffer);
        free(serverPlainTextBuffer);
      }
    }
    close(connfd);
  }

  close(sockfd);
  return 0;
}
