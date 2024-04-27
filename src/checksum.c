#include <stdint.h>

uint16_t checksum(void *addr, int count) {
  register uint32_t sum = 0;
  uint16_t *ptr = addr;

  while (count > 1) {
    sum += *ptr++;
    count -= 2;
  }

  if (count > 0) {
    sum += *(uint8_t*)ptr;
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum << 16);
  }

  return ~sum;
}
