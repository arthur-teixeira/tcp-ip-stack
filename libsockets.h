#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>


int32_t socket_bind(int32_t sockfd, const sockaddr *addr, socklen_t addrlen);

int32_t socket_new(int32_t domain, int32_t ptype, int32_t protocol);
