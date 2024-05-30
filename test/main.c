#include "libsockets.h"
#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
  printf("Calling from C!\n");
  int sockfd = socket_new(AF_INET, SOCK_DGRAM, 0);

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

  // if (socket_listen(sockfd, 10) < 0) {
  //   perror("listen");
  //   exit(1);
  // }
  //

  for (;;) {
    char msg[4096] = {0};
    ssize_t nb = socket_read(sockfd, msg, sizeof(msg));
    if (nb < 0) {
      perror("Read");
      exit(1);
    }

    printf("Got message!\n-----------------");

    for (size_t i = 0; i < nb; i++) {
      printf("%d ", msg[i]);
    }

    printf("\n-----------------------------\n");
  }
}
