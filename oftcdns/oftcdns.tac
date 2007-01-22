#!/usr/bin/env python
# Copyright (C) 2006 Luca Filipozzi
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.

from twisted.application import internet, service
from twisted.protocols import irc, dns
from twisted.names import server, authority, common
from twisted.internet import reactor, protocol
from twisted.python import log
import os, radix, socket, string, syck, sys

config = syck.load(open(os.environ['oftcdnscfg']).read())

class MyDNSServerFactory(server.DNSServerFactory):
  ip2region = None   # map of ip addresses to region

  def __init__(self, authorities=None, caches=None, clients=None, verbose=0):
    self.loadRegionDatabase()
    server.DNSServerFactory.__init__(self, authorities, caches, clients, verbose)

  def loadRegionDatabase(self):
    if self.ip2region:
      del self.ip2region
    self.ip2region = radix.Radix()
    f = open(config['dns']['region database'])
    for line in f:
      cidr,region = line.strip().split(' ')
      self.ip2region.add(cidr).data["region"] = region
    f.close()

  def getRegion(self, ip):
    rnode = self.ip2region.search_best(ip)
    if rnode:
      return rnode.data["region"]
    else:
      return config['dns']['default region']

  def handleQuery(self, message, proto, address):
    ip = address[0] or proto.transport.getPeer().host
    if message.queries[0].name == dns.Name("irc.geo.oftc.net"):
      message.queries[0].name = dns.Name(self.getRegion(ip) + "-irc.geo.oftc.net")
    if message.queries[0].name == dns.Name("irc6.geo.oftc.net"):
      message.queries[0].name = dns.Name(self.getRegion(ip) + "-irc6.geo.oftc.net")
    server.DNSServerFactory.handleQuery(self, message, proto, address)

  def gotResolverResponse(self, (ans, auth, add), protocol, message, address):
    for r in ans:
      if str(r.name).endswith("-irc.geo.oftc.net"):
        r.name = dns.Name("irc.geo.oftc.net")
        message.queries[0].name = dns.Name("irc.geo.oftc.net")
      if str(r.name).endswith("-irc6.geo.oftc.net"):
        r.name = dns.Name("irc6.geo.oftc.net")
        message.queries[0].name = dns.Name("irc6.geo.oftc.net")
    server.DNSServerFactory.gotResolverResponse(self, (ans, auth, add), protocol, message, address)

class MyRecord_A(dns.Record_A):
  def setAddress(self, address):
    self.__init__(address, self.ttl)

class MyRecord_AAAA(dns.Record_AAAA):
  def setAddress(self, address):
    self.__init__(address, self.ttl)

# TODO need some object that will order the servers for a region
class MyList(list):
  def topN(self):
    log.debug("FIXME")

class MyAuthority(authority.FileAuthority):
  def __init__(self, soa, records):
    common.ResolverBase.__init__(self)
    self.soa, self.records = soa, records

class Bot(irc.IRCClient):
  nickname = config['irc']['nickname']

  def connectionMade(self):
    irc.IRCClient.connectionMade(self)
    log.debug("connected to %s:%s" % (config['irc']['server'], config['irc']['port']))

  def connectionLost(self, reason):
    irc.IRCClient.connectionLost(self, reason)
    log.debug("disconnected from %s:%s" % (config['irc']['server'], config['irc']['port']))

  def signedOn(self):
    log.debug("signed on")
    self.join(config['irc']['channel'])

  def joined(self, channel):
    log.debug("joined %s" % channel)

  def privmsg(self, user, channel, msg):
    user = user.split('!', 1)[0]
    if channel == self.nickname:
      self.msg(user, "privmsgs not accepted; go away")
    elif msg.startswith(self.nickname + ": "):
      getattr(self, 'do_'+msg[len(self.nickname) + 2:].split(' ')[0])(user, channel)

  def do_status(self, user, channel):
    self.msg(channel, "%s: hi" % user)

class BotFactory(protocol.ClientFactory):
  protocol = Bot

  def clientConnectionLost(self, connector, reason):
    connector.connect()

  def clientConnectionFailed(self, connector, reason):
    log.err("connection failed: %s" % reason)
    connector.connect()

soa_record = dns.Record_SOA(
  mname = 'geo.oftc.net',
  rname = 'hostmaster.oftc.net',
  serial = 2007010701,
  refresh = 60,
  minimum = 60,
  expire = 60,
  retry = 60,
  ttl=1)

zone = MyAuthority(
  soa = ('geo.oftc.net', soa_record),
  records = {
    'geo.oftc.net': [
      soa_record,
      dns.Record_NS('gns1.oftc.net'),
      dns.Record_NS('gns2.oftc.net'),
      dns.Record_NS('gns3.oftc.net'),
      dns.Record_NS('gns4.oftc.net')],
    'eu-irc.geo.oftc.net'       : MyList([dns.Record_TXT('eu region'), MyRecord_A('1.2.1.1'), MyRecord_A('1.2.1.2'), MyRecord_A('1.2.1.3')]),
    'na-irc.geo.oftc.net'       : MyList([dns.Record_TXT('na region'), MyRecord_A('1.2.2.1'), MyRecord_A('1.2.2.2'), MyRecord_A('1.2.2.3')]),
    'oc-irc.geo.oftc.net'       : MyList([dns.Record_TXT('oc region'), MyRecord_A('1.2.3.1'), MyRecord_A('1.2.3.2'), MyRecord_A('1.2.3.3')]),
    'uq-irc.geo.oftc.net'       : MyList([dns.Record_TXT('uq region'), MyRecord_A('1.2.4.1'), MyRecord_A('1.2.4.2'), MyRecord_A('1.2.4.3')]),
    'global-irc.geo.oftc.net'   : MyList([dns.Record_TXT('global region'), MyRecord_A('1.2.5.1'), MyRecord_A('1.2.5.2'), MyRecord_A('1.2.5.3')]),
    'na-irc6.geo.oftc.net'      : MyList([dns.Record_TXT('na region'), MyRecord_AAAA('2001:968:1::6666'), MyRecord_AAAA('2001:780:0:1c:42:42:42:42')]),
    'global-irc6.geo.oftc.net'  : MyList([dns.Record_TXT('global region'), MyRecord_AAAA('2001:968:1::6666'), MyRecord_AAAA('2001:780:0:1c:42:42:42:42')]), })

application = service.Application('oftcdns')
serviceCollection = service.IServiceCollection(application)
internet.UDPServer(config['dns']['port'], dns.DNSDatagramProtocol(MyDNSServerFactory([zone], verbose=2)), interface=config['dns']['interface']).setServiceParent(serviceCollection)
internet.TCPClient(config['irc']['server'], config['irc']['port'], BotFactory()).setServiceParent(serviceCollection)

# vim: set ts=2 sw=2 et fdm=indent:
