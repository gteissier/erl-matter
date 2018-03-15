#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <inttypes.h>
#include <assert.h>

#include "erldp.h"

static uint64_t next_random(uint64_t x);
static uint64_t iterated_random(uint64_t x, int times);

int fast_test_seed(uint64_t seed, const char *cookie, size_t size) {
  uint64_t seed0, seed10, seed4;

  seed0 = seed;

  seed10 = iterated_random(seed0, 10);
  if (cookie[19-10] != 'A' + ((26*seed10) / 0x1000000000))
    return 1;

  seed4 = iterated_random(seed0, 4);
  if (cookie[19-4] != 'A' + ((26*seed4) / 0x1000000000))
    return 1;

  return 0;
}

int test_seed(uint64_t seed, const char *cookie, size_t size) {
  uint64_t x;
  int i;

  x = seed;

  for (i = size-1; i >= 0; i--) {
    if (cookie[i] != 'A' + ((26*x) / 0x1000000000))
      return size - i;
    x = next_random(x);
  }

  return 0;
}

static uint64_t next_random(uint64_t x) {
  unsigned __int128 z = x;
  z = (z * 17059465ULL + 1) & 0xfffffffff;
  return (uint64_t) z;
}

static uint64_t revert_random(uint64_t x) {
  unsigned __int128 z = x;
  z = ((z-1)*67451848633ULL) & 0xfffffffff;
  return (uint64_t) z;
}

static const uint64_t a[20] = {17059465, 67081586001, 5731731033, 8693990305, 50580340521, 50510613233, 5704255737, 30394329921, 15524262857, 32648606865, 49299214233, 57662584545, 59097148521, 23224943153, 6786685497, 23686801025, 23383877897, 21534618577, 40671733977, 5654919713};

static const uint64_t b[20] = {1, 17059466, 67098645467, 4110899764, 12804890069, 63385230590, 45176367087, 50880622824, 12555476009, 28079738866, 60728345731, 41308083228, 30251191037, 20628862822, 43853805975, 50640491472, 5607815761, 28991693658, 50526312235, 22478569476};

static uint64_t iterated_random(uint64_t x, int times) {
  assert(times >= 1 && times <= 20);
  unsigned __int128 z = x;
  z = (z * a[times-1] + b[times-1]) & 0xfffffffff;
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

  for (seed = w->start; seed <= w->end && !quit; seed += w->incr) {
    if (fast_test_seed(seed, w->cookie, 20) == 0 && test_seed(seed, w->cookie, 20) == 0) {
      seed0 = seed;
      //quit = 1;
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
  uint64_t seed;

  if (argc != 2) {
    fprintf(stderr, "usage: %s <20 capital letters cookie>\n", argv[0]);
    exit(1);
  }

  cookie = argv[1];
  c = cookie[19] - 'A';

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

  seed = revert_random(seed0);
  printf("%" PRIu64 "\n", seed);

  return 0;
}

