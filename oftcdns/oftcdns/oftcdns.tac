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
import itertools, os, radix, socket, string, syck, sys, weakref, pprint

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
    for zone in config['dns']['zones']:
      if message.queries[0].name == dns.Name("irc.%s" % zone):
        message.queries[0].name = dns.Name("%s-irc.%s" % (self.getRegion(ip), zone))
      if message.queries[0].name == dns.Name("irc6.%s" % zone):
        message.queries[0].name = dns.Name("%s-irc6.%s" % (self.getRegion(ip), zone))
    server.DNSServerFactory.handleQuery(self, message, proto, address)

  def gotResolverResponse(self, (ans, auth, add), protocol, message, address):
    for r in ans:
      for zone in config['dns']['zones']:
        if str(r.name).endswith("-irc.%s" % zone):
          r.name = dns.Name("irc.%s" % zone)
          message.queries[0].name = dns.Name("irc.%s" % zone)
        if str(r.name).endswith("-irc6.%s" % zone):
          r.name = dns.Name("irc6.%s" % zone)
          message.queries[0].name = dns.Name("irc6.%s" % zone)
    server.DNSServerFactory.gotResolverResponse(self, (ans, auth, add), protocol, message, address)

class MyRecord_TXT(dns.Record_TXT):
  parent = None

class MyRecord_A(dns.Record_A):
  parent = None

class MyRecord_AAAA(dns.Record_AAAA):
  parent = None

class MyList(list):
  def __iter__(self):
    return itertools.islice(itertools.ifilter(self.filter, list.__iter__(self)),3)

  def all(self):
    return list.__iter__(self)

  def filter(self, x): # TODO this is where we pick which A records to return
    if x.parent == None:
      return True
    else:
      return x.parent.active

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

class MyIrcServer:
  active = True
  a_record = None
  aaaa_record = None
  txt_record = None

subconfig = config['dns']

# dns server wants records by region
regions = {}
for region in subconfig['regions']:
  regions[region] = [MyRecord_TXT("%s region" % region)]

# load check wants records by irc server
irc_servers = {}
for x in subconfig['irc servers']:
  c = subconfig['irc servers'][x]
  y = MyIrcServer()
  if 'ipv4' in c:
    y.a_record = MyRecord_A(c['ipv4']['address'])
    y.a_record.parent = y
    for region in c['regions']:
      regions[region].append(y.a_record)
  if 'ipv6' in c:
    y.aaaa_record = MyRecord_AAAA(c['ipv6']['address'])
    y.aaaa_record.parent = y
    for region in c['regions']:
      regions[region].append(y.aaaa_record)
  y.txt_record = MyRecord_TXT("%s" % x)
  y.txt_record.parent = y
  irc_servers[x] = y

authorities = []
for zone in subconfig['zones']:
  c = subconfig['zones'][zone]
  soa_record = dns.Record_SOA(
    zone,
    c['start of authority']['contact'],
    c['start of authority']['serial'],
    c['start of authority']['refresh'],
    c['start of authority']['minimum'],
    c['start of authority']['expire'],
    c['start of authority']['retry'],
    c['start of authority']['ttl'])
  records = {zone: [soa_record] + [dns.Record_NS(x) for x in c['name servers']]}
  for key,val in regions.iteritems():
    records["%s-irc.%s" % (key, zone)] = MyList(val)
    records["%s.%s" % (key, zone)] = val
  for key,val in irc_servers.iteritems():
    records["%s.%s" % (key, zone)] = [val.txt_record]
    if y.a_record:
      records["%s.%s" % (key, zone)] += [val.a_record]
    if y.aaaa_record:
      records["%s.%s" % (key, zone)] += [val.aaaa_record]
  authorities.append(MyAuthority((zone, soa_record), records))
internet.UDPServer(subconfig['port'], dns.DNSDatagramProtocol(MyDNSServerFactory(authorities)), interface=subconfig['interface']).setServiceParent(serviceCollection)

subconfig = config['irc']
internet.TCPClient(subconfig['server'], subconfig['port'], BotFactory()).setServiceParent(serviceCollection)

# vim: set ts=2 sw=2 et fdm=indent:
