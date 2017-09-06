#include <stdio.h>
#include <string.h>

#include "erldp.h"

#include <nettle/md5.h>
#include <nettle/base16.h>


static uint64_t next_random(uint64_t x);

void create_cookie(uint64_t seed, char *cookie, size_t size) {
  uint64_t x;
  int i;

  x = seed;

  for (i = size-1; i >= 0; i--) {
    x = next_random(x);
    cookie[i] = 'A' + ((26*x) / 0x1000000000);
  }
}

static uint64_t next_random(uint64_t x) {
  uint64_t ret;
  ret = (x * 17059465ULL + 1) & 0xfffffffff;
  return ret;
}

void compute_response(size_t cookie_size, const char *cookie,
  uint32_t challenge, uint8_t *digest) {
  struct md5_ctx ctx;
  char challenge_s[256];

  memset(challenge_s, 0, sizeof(challenge_s));
  snprintf(challenge_s, sizeof(challenge_s)-1, "%u", challenge);

  md5_init(&ctx);

  md5_update(&ctx, cookie_size, (uint8_t *) cookie);
  md5_update(&ctx, strlen(challenge_s), (uint8_t *) challenge_s);

  md5_digest(&ctx, 16, digest);
}
