#!/usr/bin/env python
# Copyright (C) 2007 Luca Filipozzi
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
from twisted.words.protocols import irc
from twisted.names import dns, server, authority, common
from twisted.internet import reactor, protocol, task
from twisted.python import log
import IPy, itertools, logging, os, radix, signal, socket, string, syck, sys, time

def any(seq, pred=None):
  """ returns True if pred(x) is true for at least one element in the seq """
  for elem in itertools.ifilter(pred, seq):
    return True
  return False

def flatten(listOfLists):
  """ returns a flattened list from a list of lists """
  return list(itertools.chain(*listOfLists))

class Node:
  """ generic object that keeps track of statistics for a node """
  def __init__(self, name, records=[], ttl=600):
    """ class constructor """
    self.name = name
    self.records = {}
    for k,v in records:
      if k not in self.records: self.records[k] = []
      self.records[k] += [{4: MyRecord_A, 6: MyRecord_AAAA}[IPy.IP(v).version()](self, v, ttl)]
    self.active = 'disabled'
    self.rank = 0
    self.last = time.time()
  def update_query(self):
    """ prepare node for update query """
    logging.debug("querying %s" % self.name)
    self.rank = 0
  def update_reply(self, active, rank):
    """ process update reply for node """
    logging.debug("updating %s" % self.name)
    self.active = active
    self.rank += rank
    self.last = time.time()
  def update_check(self):
    """ check that node is up to date """
    logging.debug("checking %s" % self.name)
    if time.time() > self.last + 1200:
      logging.debug("setting %s to 'disabled'" % self.name)
      self.active = 'disabled'
  def __str__(self):
    """ string representation """
    s = "%s %s %s:" % (self.name, self.active, self.rank)
    for key,vals in self.records.iteritems():
      s += " %s=[" % key
      for val in vals:
        s += " %s" % val
      s += " ]"
    return s

class Pool(list):
  """ subclass of list that returns a filtered slice from the base list """
  def __init__(self, name, sequence=[], count=1):
    """ class constructor """
    self.name = name
    self.count = count
    list.__init__(self, sequence)
  def __iter__(self):
    """ class iterator """
    # a Pool contains one TXT record, zero of more A records and zero or more AAAA records
    # this iteroator returns 'self.count' number of active TXT, A and AAAA records
    return itertools.chain(
      itertools.islice(itertools.ifilter(lambda x: x.TYPE == dns.TXT  and x.parent.active == 'active', list.__iter__(self)), self.count),
      itertools.islice(itertools.ifilter(lambda x: x.TYPE == dns.A    and x.parent.active == 'active', list.__iter__(self)), self.count),
      itertools.islice(itertools.ifilter(lambda x: x.TYPE == dns.AAAA and x.parent.active == 'active', list.__iter__(self)), self.count))
  def __str__(self):
    """ string representation """
    s = "%s:" % self.name
    for x in list.__iter__(self):
      s += " %s" % x.parent.name
    return s
  def sort(self):
    """ utility function to sort list members """
    logging.debug("sorting %s" % self.name)
    list.sort(self, lambda x, y: x.parent.rank - y.parent.rank)

class MyAuthority(authority.BindAuthority):
  """ subclass of BindAuthority knows about nodes and pools """
  def __init__(self, config):
    """ class constructor """
    authority.FileAuthority.__init__(self, config['zone'])
    if config['zone'] not in self.records: raise ValueError, "No records defined for %s." % config['zone']
    if not any(self.records[config['zone']], lambda x: x.TYPE == dns.SOA): raise ValueError, "No SOA record defined for %s." % config['zone']
    if not any(self.records[config['zone']], lambda x: x.TYPE == dns.NS): raise ValueError, "No NS records defined for %s." % config['zone']
    self.nodes = {}
    for node in config['nodes']:
      self.nodes[node['name']] = Node(node['name'], node['records'])
    self.pools = []
    for _service in config['services']:
      for _region in config['regions']:
        k = "%s-%s" % (_region, _service)
        v = [MyRecord_TXT("%s service for %s region" % (_service, _region))] + flatten([self.nodes[node].records[k] for node in self.nodes if k in self.nodes[node].records])
        self.pools.append(Pool(k, v, config['count']))
        self.records["%s.%s" % (k, config['zone'])] = self.pools[-1]
        self.records["%s-unfiltered.%s" % (k, config['zone'])] = v

class MyDNSServerFactory(server.DNSServerFactory):
  """ subclass of DNSServerFactory that can intercept and modify certain queries and answers"""
  def __init__(self, config, authorities=None, caches=None, clients=None, verbose=0):
    self.config = config
    self.ip2region = radix.Radix()
    f = open(self.config['region database'])
    for line in f:
      cidr,region = line.strip().split(' ')
      self.ip2region.add(cidr).data["region"] = region
    f.close()
    server.DNSServerFactory.__init__(self, authorities, caches, clients, verbose)
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
  """ subclass of IRCClient that implements our bot's functionality """
  def __init__(self, config):
    """ class constructor """
    self.config = config
    self.nickname = self.config['nickname']
    self.timer = task.LoopingCall(self.update_query)
  def connectionMade(self):
    """ action when connection made (to a server)"""
    irc.IRCClient.connectionMade(self)
    logging.info("connected to %s:%s" % (self.config['server'], self.config['port']))
  def connectionLost(self, reason):
    """ action when connection lost (from a server)"""
    irc.IRCClient.connectionLost(self, reason)
    logging.warning("disconnected from %s:%s" % (self.config['server'], self.config['port']))
    self.timer.stop()
  def signedOn(self):
    """ action when signed on (to a server) """
    logging.info("signed on to %s:%s" % (self.config['server'], self.config['port']))
    self.join(self.config['channel'])
    self.timer.start(self.config['update period'])
  def joined(self, channel):
    """ action when joined (to a channel) """
    logging.info("joined %s on %s" % (channel, self.config['server']))
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
    for node in self.factory.auth.nodes:
      self.msg(channel, "%s:   %s" % (username, self.factory.auth.nodes[node]))
  def do_pools(self, username, channel):
    """ handle pools request """
    self.msg(channel, "%s: pool status is" % username)
    for pool in self.factory.auth.pools:
      self.msg(channel, "%s:   %s" % (username, pool))
  def irc_220(self, prefix, params): # update reply
    """ handle 220 responses """
    if params[2] == '6667':
      self.factory.auth.nodes[prefix].update_reply(params[-1], string.atoi(params[4]))
  def update_query(self):
    """ update nodes (by asking them to report statistics) """
    for node in self.factory.auth.nodes:
      self.factory.auth.nodes[node].update_query()
      self.sendLine("STATS P %s" % node)
    reactor.callLater(10, self.update_check)
  def update_check(self):
    """ check that nodes are up to date and sort pools """
    for node in self.factory.auth.nodes:
      self.factory.auth.nodes[node].update_check()
    for pool in self.factory.auth.pools:
      pool.sort()

class MyBotFactory(protocol.ClientFactory):
  """ subclass of ClientFactory that always reconnects """
  def __init__(self, config, auth):
    """ class constructor """
    self.protocol = MyBot
    self.config = config
    self.auth = auth
  def buildProtocol(self, addr):
    """ protocol instantiator """
    p = self.protocol(self.config)
    p.factory = self
    return p
  def clientConnectionLost(self, connector, reason):
    """ action on connection lost """
    logging.warning("connection lost: %s" % reason)
    connector.connect() # connect again!
  def clientConnectionFailed(self, connector, reason):
    """ action on connection failed """
    logging.warning("connection failed: %s" % reason)
    connector.connect() # connect again!

def Application():
  """ the application """
  logging.basicConfig(level=logging.WARNING, format='%(message)s')

  config = syck.load(open(os.environ['oftcdnscfg']).read())
  application = service.Application('oftcdns')
  serviceCollection = service.IServiceCollection(application)

  # dns server
  subconfig = config['dns']
  auth = MyAuthority(subconfig)
  dnsFactory = MyDNSServerFactory(config=subconfig, authorities=[auth])
  internet.TCPServer(subconfig['port'], dnsFactory).setServiceParent(serviceCollection)
  internet.UDPServer(subconfig['port'], dns.DNSDatagramProtocol(dnsFactory)).setServiceParent(serviceCollection)

  # irc client
  subconfig = config['irc']
  ircFactory = MyBotFactory(subconfig, auth)
  internet.TCPClient(subconfig['server'], subconfig['port'], ircFactory).setServiceParent(serviceCollection)

  return application

application = Application()

# vim: set ts=2 sw=2 et fdm=indent:
