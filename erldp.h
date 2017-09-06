#ifndef ERLDP_H
#define ERLDP_H

#include <stdint.h>
#include <sys/types.h>

void create_cookie(uint64_t seed, char *cookie, size_t size);

void compute_response(size_t cookie_size, const char *cookie,
  uint32_t challenge, uint8_t *digest);

#endif /* ERLDP_H */
