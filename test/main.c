#include <stdio.h>
#include "libsockets.h"

#define AF_INET		2
#define SOCK_DGRAM 2

int main() {
  printf("Calling from C!\n");
  int result = socket_new(AF_INET, SOCK_DGRAM, 0);

  if (result < 0) {
  }
}
