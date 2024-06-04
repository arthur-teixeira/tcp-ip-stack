#include "libsockets.h"
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int main() {
  struct addrinfo hints, *res, *p;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_flags = 0;
  hints.ai_protocol = IPPROTO_UDP;

  int rv, sockfd;
  if ((rv = getaddrinfo("127.0.0.1", "8080", &hints, &res)) != 0) {
    perror("getaddrinfo");
    fprintf(stderr, "Could not resolve address :%s\n",
            rv != EAI_SYSTEM ? gai_strerror(rv) : strerror(errno));

    exit(EXIT_FAILURE);
  }

  for (p = res; p != NULL; p = p->ai_next) {
    if ((sockfd = socket_new(p->ai_family, p->ai_socktype, p->ai_protocol)) <
        0) {
      perror("socket");
      continue;
    }

    if (socket_connect(sockfd, p->ai_addr, p->ai_addrlen) < 0) {
      perror("connect");
      // TODO: socket_close(sockfd);
      continue;
    }

    break;
  }

  if (p == NULL) {
    return 1;
  }

  freeaddrinfo(res);
  char *msg = "Hello world!";
  ssize_t nb = socket_write(sockfd, msg, strlen(msg));
  if (nb < 0) {
    perror("Read");
    exit(1);
  }
}
