#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

int32_t socket_accept(int32_t sockfd, struct sockaddr *addr, socklen_t *addrlen);

int32_t socket_bind(int32_t sockfd, const struct sockaddr *addr, socklen_t addrlen);

int32_t socket_connect(int32_t sockfd, const struct sockaddr *addr, socklen_t addrlen);

int32_t socket_listen(int32_t sockfd, int32_t backlog);

int32_t socket_new(int32_t domain, int32_t ptype, int32_t protocol);

ssize_t socket_read(int32_t sockfd, void *read_buf, size_t count);

ptrdiff_t socket_write(int32_t sockfd, const void *buf, size_t count);
