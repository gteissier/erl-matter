#!/usr/bin/env sage

'''
Adapted from initial work performed by guillaume kaim.

Example usage:

echo "ELDUPJHMPTCVINSPFDTA" | ./revert-prng.sage
404289480

it works with sage 10.3

to verify the solution, you can use derive_cookie(seed), and check it effectively equals the input cookie
'''

import string
import sys
from scipy.stats import describe, tstd, cumfreq
from sage.all import QQ, ZZ, matrix, vector


def attack(y, n, m, a, c):
    """
    Slightly modified version from https://github.com/jvdsn/crypto-attacks/blob/master/attacks/lcg/truncated_state_recovery.py

    Recovers the states associated with the outputs from a truncated linear congruential generator.
    More information: Frieze, A. et al., "Reconstructing Truncated Integer Variables Satisfying Linear Congruences"
    :param y: the sequential output values obtained from the truncated LCG (the states truncated in n possible values)
    :param n: the number of possible y values
    :param m: the modulus of the LCG
    :param a: the multiplier of the LCG
    :param c: the increment of the LCG
    :return: a list containing the states associated with the provided outputs
    """
    # Preparing for the lattice reduction.
    delta = c % m
    y = vector(ZZ, y)
    for i in range(len(y)):
        # Shift output value to the MSBs and remove the increment.
        y[i] = y[i] * m // n - delta
        delta = (a * delta + c) % m

    # This lattice only works for increment = 0.
    B = matrix(ZZ, len(y), len(y))
    B[0, 0] = m
    for i in range(1, len(y)):
        B[i, 0] = a ** i
        B[i, i] = -1

    B = B.LLL()

    # Finding the target value to solve the equation for the states.
    b = B * y
    for i in range(len(b)):
        b[i] = round(QQ(b[i]) / m) * m - b[i]

    # Recovering the states
    delta = c % m
    x = list(B.solve_right(b))
    for i, state in enumerate(x):
        # Adding the MSBs and the increment back again.
        x[i] = int(y[i] + state + delta)
        delta = (a * delta + c) % m

    return x

N = 2**36

F = IntegerModRing(N)

A = F(17059465)
B = F(1)


def split_cookie(cookie):
  nums = []
  for i in range(19, -1, -1):
    assert(cookie[i] in string.ascii_uppercase)
    nums.append(ord(cookie[i]) - ord('A'))
  return nums

def revert_prng(cookie):
  nums = split_cookie(cookie)
  assert(len(nums) == 20)

  x = attack(nums, 26, N, int(A), int(B))
  seed = (x[0] - B) / A

  return int(seed)


def derive_cookie(seed):
  cookie = ''.join([c for c in random_cookie(20, seed)])
  return cookie[::-1]

def random_cookie(n, seed):
  x = seed
  for i in range(n):
    x = next_random(x)
    yield chr((x*(26) // 0x1000000000) + ord('A'))

def next_random(x):
  ret = (x*17059465+1) & 0xfffffffff
  return ret


mode = 'print'
if len(sys.argv) == 2 and sys.argv[1] == 'stats':
  mode = 'stats'


seeds = []
for cookie in sys.stdin.readlines():
  cookie = cookie.rstrip('\n')
  if len(cookie) == 0:
    break

  seed = revert_prng(cookie)
  assert(derive_cookie(seed) == cookie)

  if mode == 'print':
    print(seed)
  elif mode == 'stats':
    seeds.append(seed)

if mode == 'stats':
  desc = describe(seeds)
  stddev = tstd(seeds)
  print('number of cookies: %d' % desc.nobs)
  print('  min seed: %d' % desc.minmax[0])
  print('  max seed: %d' % desc.minmax[1])
  print('  mean seed: %.f' % desc.mean)
  print('  std deviation: %.f' % stddev)

