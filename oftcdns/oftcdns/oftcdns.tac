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

class Node:
  """ generic object that keeps track of statistics for a node """
  def __init__(self, name, config, services, regions, ttl):
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
          record = {4: MyRecord_A, 6: MyRecord_AAAA}[IPy.IP(address).version()](address, ttl)
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
  def __init__(self, config, authorities=None, caches=None, clients=None, verbose=0):
    self.config = config
    self.loadRegionDatabase()
    server.DNSServerFactory.__init__(self, authorities, caches, clients, verbose)
  def loadRegionDatabase(self):
    if self.ip2region:
      del self.ip2region
    self.ip2region = radix.Radix()
    f = open(self.config['region database'])
    for line in f:
      cidr,region = line.strip().split(' ')
      self.ip2region.add(cidr).data["region"] = region
    f.close()
  def getRegion(self, ip):
    rnode = self.ip2region.search_best(ip)
    if rnode:
      return rnode.data["region"]
    else:
      return self.config['default region']
  def handleQuery(self, message, proto, address):
    ip = address[0] or proto.transport.getPeer().host
    for service in self.config['services']:
      zone = self.config['zone']
      if message.queries[0].name == dns.Name("%s.%s" % (service, zone)):
        message.queries[0].name = dns.Name("%s-%s.%s" % (self.getRegion(ip), service, zone))
    server.DNSServerFactory.handleQuery(self, message, proto, address)
  def gotResolverResponse(self, (ans, auth, add), protocol, message, address):
    for r in ans:
      for service in self.config['services']:
        zone = self.config['zone']
        if str(r.name).endswith("-%s.%s" % (service, zone)):
          r.name = dns.Name("%s.%s" % (service, zone))
          message.queries[0].name = dns.Name("%s.%s" % (service, zone))
    server.DNSServerFactory.gotResolverResponse(self, (ans, auth, add), protocol, message, address)

class MyRecord_TXT(dns.Record_TXT):
  """ subclass of Record_TXT that has a 'parent' member """
  parent = Node('fake parent', [], [], [], 0)

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

class MyBot(irc.IRCClient):
  """ concrete subclass of IRCClient """
  def __init__(self, config):
    """ class constructor """
    self.config = config
    self.nickname = self.config['nickname']
    self.timer = task.LoopingCall(self.update)
  def connectionMade(self):
    """ action when connection made (to a server)"""
    irc.IRCClient.connectionMade(self)
    log.debug("connected to %s:%s" % (self.config['server'], self.config['port']))
  def connectionLost(self, reason):
    """ action when connection lost (from a server)"""
    irc.IRCClient.connectionLost(self, reason)
    log.debug("disconnected from %s:%s" % (self.config['server'], self.config['port']))
    self.timer.stop()
  def signedOn(self):
    """ action when signed on (to a server) """
    log.debug("signed on")
    self.join(self.config['channel'])
    self.timer.start(self.config['update period'])
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
    for node in self.factory.nodes:
      self.msg(channel, "%s:   %s" % (username, self.factory.nodes[node]))
  def do_update(self, username, channel):
    """ handle update request """
    self.msg(channel, "%s: requesting statistics from all nodes" % username)
    self.update()
  def irc_220(self, prefix, params):
    """ handle 220 responses """
    node = params[3].split('.')[0]
    log.debug("updating node: %s" % node)
    if node in self.factory.nodes:
      port = params[2]
      if port == '6667':
        if params[5] == 'active':
          self.factory.nodes[node].active = True
        else:
          self.factory.nodes[node].active = False
        self.factory.nodes[node].rank = string.atoi(params[4])
    else:
      log.debug("unknown node: %s" % node)
  def irc_RPL_ENDOFSTATS(self, prefix, params):
    """ handle 219 responses """
    log.debug("sorting pools")
    for pool in self.factory.pools:
      pool.sort()
  def update(self):
    """ update nodes (by asking them to report statistics) """
    for node in self.factory.nodes:
      log.debug("requesting statistics from %s" % node)
      self.sendLine("STATS P %s.oftc.net" % node)

class MyBotFactory(protocol.ClientFactory):
  """ subclass of ClientFactory that always reconnects """
  def __init__(self, config, nodes, pools):
    """ class constructor """
    self.protocol = MyBot
    self.config = config
    self.nodes = nodes
    self. pools = pools
  def buildProtocol(self, addr):
    """ protocol instantiator """
    p = self.protocol(self.config)
    p.factory = self
    return p
  def clientConnectionLost(self, connector, reason):
    """ action on connection lost """
    log.debug("connection lost: %s" % reason)
    connector.connect() # connect again!
  def clientConnectionFailed(self, connector, reason):
    """ action on connection failed """
    log.debug("connection failed: %s" % reason)
    connector.connect() # connect again!

config = syck.load(open(os.environ['oftcdnscfg']).read())
application = service.Application('oftcdns')
serviceCollection = service.IServiceCollection(application)

nodes = {}
pools = []

subconfig = config['dns']
for node in subconfig['nodes']:
  nodes[node] = Node(node, subconfig['nodes'][node], subconfig['services'], subconfig['regions'], subconfig['ttl'])
authority = authority.BindAuthority(subconfig['zone'])
for service in subconfig['services']:
  for region in subconfig['regions']:
    x = [nodes[node].records[service][region] for node in nodes if region in nodes[node].regions and service in nodes[node].services]
    txt_record = MyRecord_TXT("%s service for %s region" % (service, region), subconfig['ttl'])
    pool = MyList([ txt_record ] + x)
    pools.append(pool)
    authority.records["%s-%s.%s" % (region, service, subconfig['zone'])] = pool
    authority.records["%s-%s-all.%s" % (region, service, subconfig['zone'])] = [ txt_record ] + x
internet.UDPServer(subconfig['port'], dns.DNSDatagramProtocol(MyDNSServerFactory(config=subconfig, authorities=[authority])), interface=subconfig['interface']).setServiceParent(serviceCollection)

subconfig = config['irc']
internet.TCPClient(subconfig['server'], subconfig['port'], MyBotFactory(subconfig, nodes, pools)).setServiceParent(serviceCollection)
# vim: set ts=2 sw=2 et fdm=indent:
