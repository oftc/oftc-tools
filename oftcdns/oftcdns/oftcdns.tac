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
import IPy, itertools, os, radix, socket, string, syck, sys, time

class Node:
  """ generic object that keeps track of statistics for a node """
  def __init__(self, name, records=[], ttl=600):
    """ class constructor """
    self.name = name
    self.active = 'active'
    self.rank = 0
    self.last = time.time()
    self.records = {}
    for record in records:
      key = record[0]
      val = record[1]
      if key not in self.records: self.records[key] = []
      self.records[key] += [{4: MyRecord_A, 6: MyRecord_AAAA}[IPy.IP(val).version()](self, val, ttl)]
  def update_query(self):
    """ prepare node for update query """
    log.debug("querying %s" % self.name)
    self.rank = 0
  def update_reply(self, active, rank):
    """ process update reply for node """
    log.debug("updating %s" % self.name)
    self.active = active
    self.rank += rank
    self.last = time.time()
  def update_check(self):
    """ check that node is up to date """
    log.debug("checking %s" % self.name)
    if time.time() > self.last + 1200:
      log.debug("setting %s to 'disabled'" % self.name)
      self.active = 'disabled'
  def __str__(self):
    """ string representation """
    s = "%s %s %s:" % (self.name, self.active, self.rank)
    for key,values in self.records.iteritems():
      s += " %s=[" % key
      for value in values:
        s += " %s" % value
      s += " ]"
    return s

class Pool(list):
  """ subclass of list that returns a filtered slice from the base list """
  def __init__(self, name, sequence=[], stop=2):
    """ class constructor """
    self.name = name
    self.stop = stop
    list.__init__(self, sequence)
  def __iter__(self):
    """ class iterator """
    return itertools.islice(itertools.ifilter(lambda x: x.parent.active == 'active', list.__iter__(self)), self.stop)
  def __str__(self):
    """ string representation """
    s = "%s:" % self.name
    for x in list.__iter__(self):
      s += " %s" % x.parent.name
    return s
  def sort(self):
    """ utility function to sort list members """
    log.debug("sorting %s" % self.name)
    list.sort(self, lambda x, y: x.parent.rank - y.parent.rank)

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
    if address:
      ip = address[0]
    else:
      ip = proto.transport.getPeer().host
    zone = self.config['zone']
    for service in self.config['services']:
      if message.queries[0].name == dns.Name("%s.%s" % (service, zone)):
        message.queries[0].name = dns.Name("%s-%s.%s" % (self.getRegion(ip), service, zone))
    server.DNSServerFactory.handleQuery(self, message, proto, address)
  def gotResolverResponse(self, (ans, auth, add), protocol, message, address):
    zone = self.config['zone']
    for r in ans:
      for service in self.config['services']:
        if str(r.name).endswith("-%s.%s" % (service, zone)):
          r.name = dns.Name("%s.%s" % (service, zone))
          message.queries[0].name = dns.Name("%s.%s" % (service, zone))
    server.DNSServerFactory.gotResolverResponse(self, (ans, auth, add), protocol, message, address)

class MyRecord_TXT(dns.Record_TXT):
  """ subclass of Record_TXT that has a 'parent' member """
  parent = Node('')

class MyRecord_A(dns.Record_A):
  """ subclass of Record_A that has a 'parent' member """
  def __init__(self, parent, address="0.0.0.0", ttl=None):
    """ class constructor """
    self.parent = parent
    dns.Record_A.__init__(self, address, ttl)

class MyRecord_AAAA(dns.Record_AAAA):
  """ subclass of Record_AAAA that has a 'parent' member """
  def __init__(self, parent, address="::", ttl=None):
    """ class constructor """
    self.parent = parent
    dns.Record_AAAA.__init__(self, address, ttl)

class MyBot(irc.IRCClient):
  """ subclass of IRCClient that implements our ircbot's functionality """
  def __init__(self, config):
    """ class constructor """
    self.config = config
    self.nickname = self.config['nickname']
    self.timer = task.LoopingCall(self.update_query)
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
    log.debug("signed on to %s:%s" % (self.config['server'], self.config['port']))
    self.join(self.config['channel'])
    self.timer.start(self.config['update period'])
  def joined(self, channel):
    """ action when joined (to a channel) """
    log.debug("joined %s on %s" % (channel, self.config['server']))
  def privmsg(self, username, channel, msg):
    """ request dispatcher """
    username = username.split('!', 1)[0]
    if channel == self.nickname:
      self.msg(username, "privmsgs not accepted; go away")
    elif msg.startswith(self.nickname + ": "):
      method = 'do_' + msg[len(self.nickname)+2:].split(' ')[0]
      if hasattr(self, method):
        getattr(self, method)(username, channel)
  def do_nodes(self, username, channel):
    """ handle nodes request """
    self.msg(channel, "%s: node status is" % username)
    for node in self.factory.nodes:
      self.msg(channel, "%s:   %s" % (username, self.factory.nodes[node]))
  def do_pools(self, username, channel):
    """ handle pools request """
    self.msg(channel, "%s: pool status is" % username)
    for pool in self.factory.pools:
      self.msg(channel, "%s:   %s" % (username, pool))
  def irc_220(self, prefix, params): # update reply
    """ handle 220 responses """
    if params[2] == '6667':
      self.factory.nodes[prefix].update_reply(params[-1], string.atoi(params[4]))
  def update_query(self):
    """ update nodes (by asking them to report statistics) """
    for node in self.factory.nodes:
      self.factory.nodes[node].update_query()
      self.sendLine("STATS P %s" % node)
    reactor.callLater(10, self.update_check)
  def update_check(self):
    """ check that nodes are up to date and sort pools """
    for node in self.factory.nodes:
      self.factory.nodes[node].update_check()
    for pool in self.factory.pools:
      pool.sort()

class MyBotFactory(protocol.ClientFactory):
  """ subclass of ClientFactory that always reconnects """
  def __init__(self, config, nodes, pools):
    """ class constructor """
    self.protocol = MyBot
    self.config = config
    self.nodes = nodes
    self.pools = pools
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

def Application():
  """ the application """
  config = syck.load(open(os.environ['oftcdnscfg']).read())
  application = service.Application('oftcdns')
  serviceCollection = service.IServiceCollection(application)

  # dns server
  subconfig = config['dns']
  nodes = {}
  for node,records in subconfig['nodes'].iteritems():
    nodes[node] = Node(node,records)
  pools = []
  _authority = authority.BindAuthority(subconfig['zone'])
  for _service in subconfig['services']:
    for _region in subconfig['regions']:
      x = [MyRecord_TXT("%s service for %s region" % (_service, _region))]
      for node in nodes:
        k = "%s-%s" % (_region, _service)
        if k in nodes[node].records:
          x += nodes[node].records[k]
      pools.append(Pool(k, x))
      _authority.records["%s.%s" % (k, subconfig['zone'])] = pools[-1]
      _authority.records["%s-unfiltered.%s" % (k, subconfig['zone'])] = x
  tcpFactory = MyDNSServerFactory(config=subconfig, authorities=[_authority])
  internet.TCPServer(subconfig['port'], tcpFactory).setServiceParent(serviceCollection)
  udpFactory = dns.DNSDatagramProtocol(tcpFactory)
  internet.UDPServer(subconfig['port'], udpFactory).setServiceParent(serviceCollection)

  # irc client
  subconfig = config['irc']
  botFactory = MyBotFactory(subconfig, nodes, pools)
  internet.TCPClient(subconfig['server'], subconfig['port'], botFactory).setServiceParent(serviceCollection)

  return application

application = Application()

# vim: set ts=2 sw=2 et fdm=indent:
