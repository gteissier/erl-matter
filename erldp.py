#!/usr/bin/env python3

from struct import pack, unpack
import asyncio
from hashlib import md5
from random import choice
from string import ascii_uppercase


# TCP framing: 2-bytes length followed by the message itself
# The length field is the length of the message, not including length field
async def send_frame(w, msg):
  assert(len(msg) < 2**16)
  data = pack('!H', len(msg)) + msg
  w.write(data)
  await w.drain()

async def recv_deframe(r):
  data = await r.readexactly(2)
  assert(len(data) == 2)
  (total_length,) = unpack('!H', data)
  data = await r.readexactly(total_length)
  return data



# Erlang distribution primitive messages
async def send_name_v5(w, name, flags_low=0x7499c, creation=0xdeadbeef):
  assert(len(name) < 2**16)
  msg = pack('!cIH', b'n', flags_low, len(name)) + name
  await send_frame(w, msg)

async def send_name_v6(w, name, flags=0x1074f9c, creation=0xdeadbeef):
  assert(len(name) < 2**16)
  msg = pack('!cQIH', b'N', flags, creation, len(name)) + name
  await send_frame(w, msg)

async def recv_status(r):
  msg = await recv_deframe(r)
  assert(msg[0] == ord('s'))
  return msg[1:]

async def recv_challenge_v6(r):
  msg = await recv_deframe(r)
  assert(msg[0] == ord('N'))

  (flags, challenge, creation, nlen) = unpack('!QIIH', msg[1:19])
  name = msg[19:]
  assert(nlen == len(name))
  return (flags, challenge, creation, name)

async def recv_challenge_v5(r):
  #   (length, tag, version, flags, challenge) = unpack('!HcHII', data[:13])
  msg = await recv_deframe(r)
  assert(msg[0] == ord('n'))

  (version, flags, challenge) = unpack('!HII', msg[1:11])
  return (version, flags, challenge)

async def send_complement(w, flags_high, creation):
  msg = pack('!cII', b'c', flags_high, creation)
  await send_frame(w, msg)

async def send_challenge_reply(w, digest, challenge=0):
  msg = pack('!cI', b'r', challenge) + digest
  await send_frame(w, msg)

async def recv_challenge_ack(r):
  msg = await recv_deframe(r)
  assert(msg[0] == ord('a'))
  assert(len(msg[1:]) == 16)



def compute_digest(cookie, challenge):
  challenge = '%u' % challenge
  challenge = challenge.encode()

  m = md5()
  m.update(cookie)
  m.update(challenge)
  return m.digest()


def rand_id(n=6):
  return ''.join([choice(ascii_uppercase) for c in range(n)]) + '@nowhere'


async def authenticate(host, port, cookie):
  r, w = await asyncio.open_connection(host, port)

  await send_name_v6(w, rand_id().encode())

  reason = await recv_status(r)
  assert(reason == b'ok')

  (flags, challenge, creation, name) = await recv_challenge_v6(r)

  digest = compute_digest(cookie, challenge)

  await send_challenge_reply(w, digest)

  try:
    await recv_challenge_ack(r)
  except:
    return

  return (r, w)



if __name__ == '__main__':
  import argparse
  parser = argparse.ArgumentParser()
  parser.add_argument('--host', default='127.0.0.1')
  parser.add_argument('port', type=int)
  parser.add_argument('cookie')
  args = parser.parse_args()

  asyncio.run(authenticate(args.host, args.port, args.cookie.encode()))

