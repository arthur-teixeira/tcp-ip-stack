#include "libsockets.h"
#include <bits/pthreadtypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define da_init(da, size)                                                      \
  do {                                                                         \
    da->cap = 16;                                                              \
    da->values = calloc(da->cap, size);                                        \
    da->len = 0;                                                               \
  } while (0)

#define da_append(da, value)                                                   \
  do {                                                                         \
    if (da->len == da->cap) {                                                  \
      da->cap *= 2;                                                            \
      da->values = realloc(da->values, da->cap * sizeof(da->values[0]));       \
    }                                                                          \
    da->values[da->len++] = value;                                             \
  } while (0)

void *handle_connection(void *arg);

int main() {
  int sockfd = socket_new(AF_INET, SOCK_STREAM, 0);

  if (sockfd < 0) {
    perror("socket");
    exit(1);
  }

  struct sockaddr_in addr = {0};
  addr.sin_port = 8080;

  if (socket_bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("bind");
    exit(1);
  }

  if (socket_listen(sockfd, 10) < 0) {
    perror("listen");
    exit(1);
  }

  pthread_t thread;

  for (;;) {
    int connfd = socket_accept(sockfd, NULL, NULL);
    printf("Accepted connection\n");
    if (connfd < 0) {
      perror("accept");
      exit(1);
    }

    printf("Accepted connection in C! %d\n", connfd);
    char buf[4096];
    for (;;) {
      ssize_t nb = socket_read(connfd, buf, sizeof(buf));
      if (nb < 0) {
        printf("ERROR: %s\n", strerror(-nb));
        perror("Read");
        continue;
      }

      buf[nb] = '\0';

      printf("Got message!\n%s\n", buf);
    }

    // int *conn_state = malloc(1);
    // *conn_state = connfd;
    //
    // pthread_create(&thread, NULL, handle_connection, conn_state);
  }
}

void *handle_connection(void *arg) {
  int sockfd = *(int *)arg;
  printf("Accepted connection in C! %d\n", sockfd);
  char buf[4096];
  for (;;) {
    ssize_t nb = socket_read(sockfd, buf, sizeof(buf));
    if (nb < 0) {
      printf("ERROR: %s\n", strerror(-nb));
      perror("Read");
      return NULL;
    }

    buf[nb] = '\0';

    printf("Got message!\n%s\n", buf);
  }
}
