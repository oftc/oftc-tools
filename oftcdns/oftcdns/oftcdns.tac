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
from twisted.internet import reactor, protocol, task
from twisted.python import log
import itertools, os, radix, socket, string, syck, sys, weakref, pprint, IPy

config = syck.load(open(os.environ['oftcdnscfg']).read())
application = service.Application('oftcdns')
serviceCollection = service.IServiceCollection(application)

nodes = {} # keep track of nodes so that we can update their rank periodically
pools = [] # keep track of pools so that we can sort() them periodically

class Node:
  """ generic object that keeps track of statistics for a node """
  def __init__(self, name, config, services, regions):
    self.last = 0 # TODO need to keep track of last time node was updated
    self.name = name
    self.rank = 0
    self.active = True
    self.records = {}
    self.services = []
    self.regions = []
    for service in services:
      self.records[service] = {}
      if service in config:
        for address in config[service]['addresses']:
          record = {4: MyRecord_A, 6: MyRecord_AAAA}[IPy.IP(address).version()](address)
          record.parent = self
          self.services.append(service)
          for region in regions:
            if region in config[service]['regions']:
              self.records[service][region] = record
              self.regions.append(region)
  def __str__(self):
    return "%s %s %s" % (self.name, self.active, self.rank)

class MyDNSServerFactory(server.DNSServerFactory):
  """ subclass of DNSServerFactory that can intercept and modify certain queries and answers"""
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
  """ subclass of Record_TXT that has a 'parent' member """
  parent = Node('blah', [], [], [])

class MyRecord_A(dns.Record_A):
  """ subclass of Record_A that has a 'parent' member """
  parent = None

class MyRecord_AAAA(dns.Record_AAAA):
  """ subclass of Record_AAAA that has a 'parent' member """
  parent = None

class MyList(list):
  """ subclass of list that returns filtered slice """
  def __init__(self, sequence=[], stop=3):
    list.__init__(self, sequence)
    self.stop = stop
  def __iter__(self):
    return itertools.islice(itertools.ifilter(lambda x: x.parent.active, list.__iter__(self)), self.stop)
  def sort(self):
    list.sort(self, lambda x, y: x.parent.rank - y.parent.rank)

class MyAuthority(authority.FileAuthority):
  """ subclass of FileAuthority that doesn't need to read in a file """
  def __init__(self, soa, records):
    common.ResolverBase.__init__(self)
    self.soa, self.records = soa, records

class MyBot(irc.IRCClient):
  """ concrete subclass of IRCClient """
  nickname = config['irc']['nickname']
  def connectionMade(self):
    """ action when connection made (to a server)"""
    irc.IRCClient.connectionMade(self)
    log.debug("connected to %s:%s" % (config['irc']['server'], config['irc']['port']))
  def connectionLost(self, reason):
    """ action when connection lost (from a server)"""
    irc.IRCClient.connectionLost(self, reason)
    log.debug("disconnected from %s:%s" % (config['irc']['server'], config['irc']['port']))
  def signedOn(self):
    """ action when signed on (to a server) """
    log.debug("signed on")
    self.join(config['irc']['channel'])
  def joined(self, channel):
    """ action when joined (to a channel) """
    log.debug("joined %s" % channel)
  def privmsg(self, username, channel, msg):
    """ request dispatcher """
    username = username.split('!', 1)[0]
    if channel == self.nickname:
      self.msg(username, "privmsgs not accepted; go away")
    elif msg.startswith(self.nickname + ": "):
      method = 'do_' + msg[len(self.nickname)+2:].split(' ')[0]
      if hasattr(self, method):
        getattr(self, method)(username, channel)
  def do_status(self, username, channel):
    """ handle status request """
    self.msg(channel, "%s: node status is" % username)
    for node in nodes:
      self.msg(channel, "%s:   %s" % (username, nodes[node]))
  def do_rotate(self, username, channel):
    """ handle rotate request """
    self.msg(channel, "%s: requesting statistics from all nodes" % username)
    for node in nodes:
      log.debug("requesting statistics from %s" % node)
      self.sendLine("STATS P %s.oftc.net" % node)
  def irc_220(self, prefix, params):
    """ handle 220 responses """
    node = params[3].split('.')[0]
    log.debug("updating node: %s" % node)
    if node in nodes:
      port = params[2]
      if port == '6667':
        if params[5] == 'active':
          nodes[node].active = True
        else:
          nodes[node].active = False
        nodes[node].rank = string.atoi(params[4])
    else:
      log.debug("unknown node: %s" % node)
  def irc_RPL_ENDOFSTATS(self, prefix, params):
    """ handle 219 responses """
    log.debug("sorting pools")
    for pool in pools:
      pool.sort()

class MyBotFactory(protocol.ClientFactory):
  """ subclass of ClientFactory that always reconnects """
  protocol = MyBot
  def clientConnectionLost(self, connector, reason):
    connector.connect()
  def clientConnectionFailed(self, connector, reason):
    log.err("connection failed: %s" % reason)
    connector.connect()

subconfig = config['dns']
for node in subconfig['nodes']:
  nodes[node] = Node(node, subconfig['nodes'][node], subconfig['services'], subconfig['regions'])
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
  for service in subconfig['services']:
    for region in subconfig['regions']:
      x = [nodes[node].records[service][region] for node in nodes if region in nodes[node].regions and service in nodes[node].services]
      txt_record = MyRecord_TXT("%s service for %s region" % (service, region))
      records["%s-%s-foo.%s" % (service, region, zone)] = [ txt_record ] + x # FIXME foo?
      pool = MyList([ txt_record ] + x)
      pools.append(pool)
      records["%s-%s-bar.%s" % (service, region, zone)] = pool               # FIXME bar?
  authorities.append(MyAuthority((zone, soa_record), records))
internet.UDPServer(subconfig['port'], dns.DNSDatagramProtocol(MyDNSServerFactory(authorities)), interface=subconfig['interface']).setServiceParent(serviceCollection)

subconfig = config['irc']
internet.TCPClient(subconfig['server'], subconfig['port'], MyBotFactory()).setServiceParent(serviceCollection)
# vim: set ts=2 sw=2 et fdm=indent:
