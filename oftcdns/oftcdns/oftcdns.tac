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
import itertools, os, radix, socket, string, syck, sys

config = syck.load(open(os.environ['oftcdnscfg']).read())
application = service.Application('oftcdns')
serviceCollection = service.IServiceCollection(application)

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

class MyRecord_TXT(dns.Record_TXT):
  active = True
  load = 0

class MyRecord_A(dns.Record_A):
  active = True
  load = 0

class MyRecord_AAAA(dns.Record_AAAA):
  active = True
  load = 0

class MyList(list):
  def __iter__(self):
    return itertools.islice(itertools.ifilter(self.filter, list.__iter__(self)),3)

  def all(self):
    return list.__iter__(self)

  def filter(self, x): # TODO this is where we pick which A records to return
    return x.active

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

subconfig = config['dns']
soa_record = dns.Record_SOA(subconfig['zone'], subconfig['contact'], subconfig['serial'], subconfig['refresh'], subconfig['minimum'], subconfig['expire'], subconfig['retry'], subconfig['ttl'])
records = {subconfig['zone']: [soa_record] + [dns.Record_NS(x) for x in subconfig['name servers']]}
for region in subconfig['regions']:
  records["%s-irc.%s" % (region, subconfig['zone'])] = MyList([MyRecord_TXT('%s region' % region)] + [MyRecord_A(x) for x in subconfig['regions'][region]])
zone = MyAuthority((subconfig['zone'], soa_record), records)
internet.UDPServer(subconfig['port'], dns.DNSDatagramProtocol(MyDNSServerFactory([zone])), interface=subconfig['interface']).setServiceParent(serviceCollection)

subconfig = config['irc']
internet.TCPClient(subconfig['server'], subconfig['port'], BotFactory()).setServiceParent(serviceCollection)

# vim: set ts=2 sw=2 et fdm=indent:
