#!/usr/bin/env python2.7

import sys
import json

def load_seeds(f):
  data = [int(x) for x in f.readlines()]
  return data

def make_bins(data):
  _min = min(data)
  _max = max(data)

  _delta = _max-_min+1
  _epsilon = 1000000

  _bins = [0 for x in range(int(_delta//_epsilon) + 1)]
  for d in data:
    _bins[int((d-_min)//_epsilon)] += 1

  indexes = sorted(range(len(_bins)), key=lambda x: _bins[x], reverse=True)

  for i in indexes:
    yield (_min+i*int(_epsilon), _min+(i+1)*int(_epsilon), _bins[i])

data = load_seeds(sys.stdin)
n = len(data)
intervals = []
for (a, b, count) in make_bins(data):
  intervals.append({'start': a, 'stop': b, 'prob': (100.0*count)/n})

print(json.dumps(intervals))
