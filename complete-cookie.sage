#!/usr/bin/env sage

'''
Adapted from initial work performed by guillaume kaim.

Example usage:

echo "ELDUPJHMPTCVINSPFDTA" | ./revert-prng.sage
'''

import string
import sys
from scipy.stats import describe, tstd, cumfreq

N = 2**36

F = IntegerModRing(N)

A = F(17059465)
B = F(1)

a = [A]
b = [B]
for i in xrange(1, 20):
  a.append(a[-1]*A)
  b.append(b[-1]*A + B)

a_1 = []
b_1 = []
for i in range(20):
  a_1.append(a[i]^(-1))
  b_1.append(-b[i]*a_1[-1])


intervals = [(0, 2643056797), (2643056798, 5286113595), (5286113596, 7929170392), (7929170393, 10572227190), (10572227191, 13215283987), (13215283988, 15858340785), (15858340786, 18501397582), (18501397583, 21144454380), (21144454381, 23787511177), (23787511178, 26430567975), (26430567976, 29073624772), (29073624773, 31716681570), (31716681571, 34359738367), (34359738368, 37002795165), (37002795166, 39645851963), (39645851964, 42288908760), (42288908761, 44931965558), (44931965559, 47575022355), (47575022356, 50218079153), (50218079154, 52861135950), (52861135951, 55504192748), (55504192749, 58147249545), (58147249546, 60790306343), (60790306344, 63433363140), (63433363141, 66076419938), (66076419939, 68719476735)]

cookie = sys.argv[1]


nums = []
for c in cookie[::-1]:
  assert(c in string.ascii_uppercase)
  nums.append(ord(c) - ord('A'))

L = len(nums)
M = matrix(F, L-1, L)
for i in range(L-1):
  M[i,0] = a_1[0]
  for j in range(1, i+1):
    M[i,j] = 0
  M[i,i+1] = -a_1[i+1]
  for j in range(i+2, L):
    M[i,j] = 0

v = a_1[0]*intervals[nums[0]][0]+b_1[0]

n = matrix(F, L-1, 1)
for i in range(L-1):
  n[i,0] = a_1[i+1]*F(intervals[nums[i+1]][0])+b_1[i+1] - v

x = M.solve_right(n)


def derive_cookie(seed):
  cookie = ''.join([c for c in random_cookie(20, seed)])
  return cookie[::-1]

def random_cookie(n, seed):
  x = seed
  for i in range(n):
    x = next_random(x)
    yield chr((x*(26) / 0x1000000000) + ord('A'))

def next_random(x):
  ret = (x*17059465+1) & 0xfffffffff
  return ret

seed = a_1[0]*(x[0][0]+F(intervals[nums[0]][0]))+b_1[0]
seed = int(seed)

if derive_cookie(seed)[-L:] == cookie:
  print('cookie has been revealed: %s' % derive_cookie(seed))
else:
  print('failed to reveal cookie')
