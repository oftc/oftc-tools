#!/usr/bin/env python2.5
# Copyright (c) 2010 TJ Fontaine tjfontaine@gmail.com
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import socket
import datetime
import os
import select
import json
import sys

try:
  import ssl as ssl_layer
except:
  ssl_layer = None

class IRC(object):
  def __init__(self, nickname='test', username='test',
      realname='test client', server='irc.example.com', port=6667,
      ssl=False, ssl_cert=None, reconnect=True):

    self.nickname = nickname
    self.username = username
    self.realname = realname
    self.server = server
    self.use_ssl = ssl
    self.ssl_cert = ssl_cert
    self.socket = None
    self.recv_buf = ''

    if self.use_ssl and port == 6667:
      self.port = 6697
    else:
      self.port = port
   
    if reconnect:
      self.reconnect = 5
    else:
      self.reconnect = 0

  def create_socket(self):
    if self.use_ssl and not ssl_layer:
      raise "Couldn't import python ssl module"

    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if self.use_ssl:
      self.socket = ssl_layer.wrap_socket(self.socket, certfile=self.ssl_cert)

  def connect(self):
    if not self.socket:
      self.create_socket()

    self.socket.connect((self.server, self.port))
    self.socket.settimeout(0.1)
    self.send('NICK %s' % self.nickname)
    self.send('USER %s no no :%s' % (self.username, self.realname))

  def cmd_ping(self, source, *params):
    self.send('PONG :%s' % (' '.join(params)))

  def cmd_376(self, source, *params):
    if self.reconnect > 0:
      self.reconnect = 5

  def one_loop(self):
    try:
      self.recv_buf += self.socket.recv(512)
    except socket.timeout:
      pass
    except ssl_layer.SSLError, x:
      if x.args[0] == 'The read operation timed out':
        pass
      else:
        raise x
    except Exception, x:
      if self.reconnect > 0:
        self.socket = None
        self.connect()
        self.reconnect -= 1
      else:
        raise x
    
    while self.recv_buf.find('\r\n') > -1:
      comm, self.recv_buf = self.recv_buf.split('\r\n', 1)
      self.parse(comm)

  def send(self, msg, *args):
    msg = msg % args
    self.socket.send('%s\r\n'%msg)

  def parse(self, msg):
    source = None
    if msg[0] == ':': 
      (source, msg) = msg.split(' ', 1)
    if source: 
      source = source[1:len(source)]
    split = msg.split(' ', 1)
    if(len(split) == 1):
      comm = split[0]
      msg = None
    else:
      comm, msg = split

    params = []
    while msg and msg[0] != ':':
      middle = msg.split(' ', 1)
      params.append(middle[0])
      if len(middle) > 1:
        msg = middle[1]
      else:
        msg = None

    if msg and msg[0] == ':':
      params.append(msg[1:len(msg)])

    comm = 'cmd_' + comm.lower()
    if hasattr(self, comm):
      f = getattr(self, comm)
      f(source, *params)
    else:
      pass

class StatusBot(IRC):
  def __init__(self, default_chan=None, fifo=None, *args, **kwargs):
    IRC.__init__(self, *args, **kwargs)
    self.default_chan = default_chan
    self.fifo = fifo
    try:
      os.unlink(self.fifo)
    except:
      pass
    os.mkfifo(self.fifo)
    self.poll = select.poll()
    self.fd = os.open(self.fifo, os.O_RDONLY|os.O_NONBLOCK)
    self.poll.register(self.fd, select.POLLIN)
    self.fd = os.fdopen(self.fd)

  def join(self, channels):
    if not isinstance(channels, list) and not isinstance(channels, tuple):
      channels = [channels]

    for c in channels:
      self.send('JOIN %s' % c)

  def cmd_376(self, source, *params):
    self.join(self.default_chan)
    super(MyClient, self).cmd_376(source, *params)

  def privmsg(self, channel, msg):
    self.send('PRIVMSG %s :%s', channel, msg)

  def one_loop(self):
    super(MyClient, self).one_loop()
    fds = self.poll.poll(100)
    if fds:
      msgs = self.fd.readlines()
      for msg in msgs:
        if msg.find(':') > -1:
          channel, msg = msg.split(':', 1)
          msg = msg.strip()
          msg = self.colorize(msg)
          self.privmsg(channel, msg)
        else:
          print 'MSG has no destination: %s' % msg

  def colorize(self, msg):
    state, foo = msg.split(' ', 1)
    if state in ('OK', 'UP'):
      msg = '9' + msg
    elif state in ('WARNING'):
      msg = '8' + msg
    elif state in ('CRITICAL', 'DOWN', 'UNREACHABLE'):
      msg = '4' + msg
    elif state in ('UNKNOWN'):
      msg = '7' + msg

    return msg

if __name__ == '__main__':
  if len(sys.argv) < 2:
    print "statusbot.py config.json"
    exit(1)
  fh = open(sys.argv[1], 'r')
  config = json.read(fh.read())
  fh.close()

  c = StatusBot(nickname=config['nick'], server=config['server'], ssl=config['ssl'], default_chan=config['channel'], fifo=config['fifo'])
  c.connect()
  while True:
    c.one_loop()
