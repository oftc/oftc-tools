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
from twisted.internet import defer, reactor, protocol, ssl, task
from twisted.python import failure, log
from twisted.spread import pb
import IPy, itertools, logging, os, radix, random, signal, socket, string, syck, sys, time

def any(seq, pred=None):
  """ returns True if pred(x) is true for at least one element in the sequence """
  for elem in itertools.ifilter(pred, seq):
    return True
  return False

class Node:
  """ generic object that keeps track of statistics for a node """
  def __init__(self, config, ttl):
    """ class constructor """
    self.__dict__.update({'active': False, 'rank': 10000, 'limit': None, 'last': time.time()})
    self.__dict__.update(config)
    self.nickname = self.__dict__.get('nickname', self.name)
    self.records = dict([(k, [{4: dns.Record_A, 6: dns.Record_AAAA}[IPy.IP(v).version()](v, ttl)]) for k,v in self.records])
  def update(self, active, rank):
    """ update statistics """
    self.active = active
    self.rank = rank
    self.last = time.time()
  def check(self, period):
    """ check status """
    if self.last + 2 * period < time.time():
      self.active = False
      self.rank = 10000
  def to_str(self, label, type, marker):
    """ string representation """
    if not any(self.records.get(label), lambda x: x.TYPE == type):
      return ""
    return " %s%s(%s%s)%s" % (self.nickname, {True: "+", False: "-"}[self.active == "active"], self.rank, {True: "", False: "/%s" % self.limit}[self.limit is None], marker)

class Pool(list):
  """ subclass of list that knows about nodes """
  def nodes(self):
    """ return a custom iterator """
    if any(self.active_nodes()):      # return active nodes, if any
      return self.active_nodes()
    elif any(self.passive_nodes()):   # else return passive nodes, if any
      return self.passive_nodes()
    elif any(self.disabled_nodes()):  # else return disabled nodes, if any
      return self.disabled_nodes()
    else:                             # else return all nodes (degenerate case)
      return list.__iter__(self)
  def active_nodes(self):
    """ return an iterator of active and unloaded nodes """
    return itertools.ifilter(lambda x: x.active and (x.limit is None or x.rank < x.limit), list.__iter__(self))
  def passive_nodes(self):
    """ return an iterator of active but loaded nodes """
    return itertools.ifilter(lambda x: x.active and (x.limit is not None and x.rank >= x.limit), list.__iter__(self))
  def disabled_nodes(self):
    """ return an iterator of disabled nodes """
    return itertools.ifilter(lambda x: not x.active, list.__iter__(self))
  def sort(self):
    """ utility function to sort list members """
    list.sort(self, lambda x, y: x.rank - y.rank)
  def to_str(self, label, type, count):
    """ string representation """
    s = ""
    for node in itertools.chain(self.active_nodes(), self.passive_nodes(), self.disabled_nodes()):
      s += node.to_str(label, type, {True: "*", False: ""}[count > 0])
      if count > 0: count -= 1
    return s

class ENAME(Exception):
  """ subclass of Exception for NXDOMAIN exceptions """
  def __init__(self, (ans, auth, add)):
    """ class constructor """
    self.ans = ans
    self.auth = auth
    self.add = add

class EREFUSED(Exception):
  """ subclass of Exception for REFUSED exceptions """
  def __init__(self, (ans, auth, add)):
    """ class constructor """
    self.ans = ans
    self.auth = auth
    self.add = add

class MyAuthority(authority.BindAuthority):
  """ subclass of BindAuthority that knows about nodes and pools """
  def __init__(self, config):
    """ class constructor """
    self.__dict__.update(config)
    authority.FileAuthority.__init__(self, self.zone)
    if self.zone not in self.records:
      raise ValueError, "No records defined for %s." % self.zone
    if not any(self.records[self.zone], lambda x: x.TYPE == dns.SOA):
      raise ValueError, "No SOA record defined for %s." % self.zone
    if not any(self.records[self.zone], lambda x: x.TYPE == dns.NS):
      raise ValueError, "No NS records defined for %s." % self.zone
    self.nodes = dict([(node['name'], Node(node, self.ttl)) for node in self.nodes])
    self.pools = dict([(key, Pool([self.nodes[node] for node in self.nodes if key in self.nodes[node].records])) for key in ["%s-%s" % (x, y) for x in self.regions for y in self.services]])
  def _lookup(self, name, cls, type, timeout = None):
    """ look up records """
    (ans,auth,add) = ([], [], [])
    (name, region, ip) = name.split('/')

    if not region:
      region = self.default

    if region not in self.regions:
      return defer.fail(failure.Failure(EREFUSED((ans, auth, add))))

    if not name.lower().endswith(self.zone):
      return defer.fail(failure.Failure(EREFUSED((ans, auth, add))))

    key = name.lower().replace(".%s" % self.zone, "")
    truncate = True
    if key.endswith("-unfiltered"):
      key = key.replace("-unfiltered", "")
      truncate = False

    if type == dns.ALL_RECORDS:
      truncate = False

    shuffle = False
    if key in self.services:
      key = "%s-%s" % (region, key)
      shuffle = True

    # get records
    records = self.records.get("%s.%s" % (key, self.zone), [])
    pool = self.pools.get(key)
    if pool:
      for node in pool.nodes():
        records += node.records.get(key, [])
      
    # construct answer section
    if type == dns.ALL_RECORDS:
      ans = [dns.RRHeader(name, x.TYPE, dns.IN, x.ttl or self.ttl, x, auth=True) for x in records]
    else:
      ans = [dns.RRHeader(name, x.TYPE, dns.IN, x.ttl or self.ttl, x, auth=True) for x in itertools.ifilter(lambda x: x.TYPE == type, records)]
      if not ans:
        ans = [dns.RRHeader(name, x.TYPE, dns.IN, x.ttl or self.ttl, x, auth=True) for x in itertools.ifilter(lambda x: x.TYPE == dns.CNAME, records)]

    # construct authority section
    if ans:
      if type != dns.NS:
        auth = [dns.RRHeader(self.zone, x.TYPE, dns.IN, x.ttl or self.ttl, x, auth=True) for x in itertools.ifilter(lambda x: x.TYPE == dns.NS, self.records.get(self.zone, ()))]
    else:
      auth = [dns.RRHeader(self.zone, x.TYPE, dns.IN, x.ttl or self.ttl, x, auth=True) for x in itertools.ifilter(lambda x: x.TYPE == dns.SOA, self.records.get(self.zone, ()))]
      if not records:
        return defer.fail(failure.Failure(ENAME((ans, auth, add))))

    # construct additional section
    for header in ans + auth:
      section = {dns.NS: add, dns.CNAME: ans, dns.MX: add}.get(header.type)
      if section is not None:
        n = str(header.payload.name)
        for record in self.records.get(n.lower(), ()):
          if record.TYPE == dns.A:
            section.append(dns.RRHeader(n, record.TYPE, dns.IN, record.ttl or self.ttl, record, auth=True))

    if truncate:
      ans = ans[0:self.count]

    if shuffle:
      random.shuffle(ans)

    if type == dns.TXT or type == dns.ALL_RECORDS:
      ans.append(dns.RRHeader(name, dns.TXT, dns.IN, self.ttl, dns.Record_TXT("client is %s / region is %s / server is %s" % (ip, region, self.hostname), ttl=self.ttl), auth=True))

    return defer.succeed((ans, auth, add))
  def to_str(self):
    """ string representation """
    s = self.zone + "\n"
    keys = self.pools.keys()
    keys.sort()
    for key in keys:
      pool = self.pools[key]
      s += " " + key + "(A):" + pool.to_str(key, dns.A, self.count) + "\n"
      s += " " + key + "(AAAA):" + pool.to_str(key, dns.AAAA, self.count) + "\n"
    return s
  def sortPools(self):
    """ sort pools """
    for pool in self.pools.itervalues():
      pool.sort()
  def checkNodes(self, period):
    """ check nodes """
    for node in self.nodes.itervalues():
      node.check(period)
  def updateNode(self, name, active, rank):
    """ update node """
    node = self.nodes.get(name)
    if node:
      node.update(active, rank)

class MyDNSServerFactory(server.DNSServerFactory):
  """ subclass of DNSServerFactory that can geolocate resolvers """
  def __init__(self, database, authorities=None, caches=None, clients=None, verbose=0):
    """ class constructor """
    self.ip2region = radix.Radix()
    f = open(database)
    for line in f:
      (cidr,region) = line.strip().split(' ')
      self.ip2region.add(cidr).data["region"] = region
    f.close()
    server.DNSServerFactory.__init__(self, authorities, caches, clients, verbose)
  def getRegion(self, ip):
    """ determine region from ip address """
    rnode = self.ip2region.search_best(ip)
    if not rnode:
      return ""
    return rnode.data["region"]
  def handleQuery(self, message, proto, address):
    """ reimplement handleQuery to encode geolocation into queries """
    if address:
      ip = address[0]
    else:
      ip = proto.transport.getPeer().host
    message.queries[0].name = dns.Name("%s/%s/%s" % (message.queries[0].name, self.getRegion(ip), ip))
    server.DNSServerFactory.handleQuery(self, message, proto, address)
  def gotResolverResponse(self, (ans, auth, add), protocol, message, address):
    """ reimplement gotResolverResponse to decode geolocation from responses """
    message.queries[0].name = dns.Name("%s" % message.queries[0].name.__str__().split('/')[0])
    if any(itertools.chain(ans, auth), lambda x: x.isAuthoritative()):
      message.auth = 1
    server.DNSServerFactory.gotResolverResponse(self, (ans, auth, add), protocol, message, address)
  def gotResolverError(self, failure, protocol, message, address):
    """ reimplement gotResolverError to decode geolocation from responses """
    message.queries[0].name = dns.Name("%s" % message.queries[0].name.__str__().split('/')[0])
    if failure.check(ENAME):
      message.auth = 1
      message.rCode = dns.ENAME
      message.answers = failure.value.ans
      message.authority = failure.value.auth
      message.additional = failure.value.add
    elif failure.check(EREFUSED):
      message.rCode = dns.EREFUSED
    else:
      message.rCode = dns.ESERVER
    self.sendReply(protocol, message, address)

class MyBot(irc.IRCClient):
  """ subclass of IRCClient that implements our bot's functionality """
  def __init__(self, config):
    """ class constructor """
    self.__dict__.update({'opername': None, 'operpass': None})
    self.__dict__.update(config)
  def signedOn(self):
    """ once signed on, oper up if configured to do so else join channel """
    if self.opername and self.operpass:
      self.sendLine("OPER %s %s" % (self.opername, self.operpass))
    else:
      self.join(self.channel)
  def irc_RPL_YOUREOPER(self, prefix, params):
    """ oper up succeeded, so join channel """
    self.join(self.channel)
  def irc_ERR_PASSWDMISMATCH(self, prefix, params):
    """ oper up failed due to password mismatch; ignore and join channel """
    self.join(self.channel)
  def irc_ERR_NOOPERHOST(self, prefix,params): # oper reply
    """ oper up failed due to no operhost line; ignore and join channel """
    self.join(self.channel)
  def irc_ERR_NEEDMOREPARAMS(self, prefix,params):
    """ oper up failed due to incorrect command syntax; ignore and join channel """
    self.join(self.channel)
  def kickedFrom(self, channel, kicker, message):
    """ rejoin the channel if kicked """
    self.join(channel)
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
    self.msg(channel, "%s: status of %s" % (username, self.factory.auth.to_str()), 200)

class MyBotFactory(protocol.ReconnectingClientFactory):
  """ subclass of ReconnectingClientFactory that knows about MyAuthority and can instantiate MyBot classes """
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

class MyPBClient(pb.Referenceable):
  """ perspective broker client """
  def __init__(self, factory, auth, period):
    """ class constructor """
    self.factory = factory
    self.auth = auth
    self.period = period
    self.remote = None
    self.timer = task.LoopingCall(self.stats_query)
    self.deregister(self.remote)
    self.timer.start(self.period)
  def register(self, remote):
    """ register remote """
    self.remote = remote
    self.remote.notifyOnDisconnect(self.deregister)
  def deregister(self, remote):
    """ deregister remote and try again """
    self.remote = None
    self.factory.getRootObject().addCallback(self.register).addErrback(self.deregister)
  def stats_query(self):
    """ send statistics query to remote """
    self.auth.sortPools()
    self.auth.checkNodes(self.period)
    if self.remote:
      try:
        self.remote.callRemote('stats').addCallback(self.stats_reply)
      except pb.DeadReferenceError:
        pass
  def stats_reply(self, stats):
    """ recv statistics reply from remote """
    for (name,active,rank) in stats:
      self.auth.updateNode(name, active, rank)

class MyPBClientFactory(pb.PBClientFactory, protocol.ReconnectingClientFactory):
  """ perspective broker client factory that knows how to reconnect """
  def __init__(self):
    """ class constructor """
    pb.PBClientFactory.__init__(self)
    self.maxDelay = 30
  def clientConnectionFailed(self, connector, reason):
    """ handle client connection failed event """
    log.msg("connection failed: %s" % reason)
    pb.PBClientFactory.clientConnectionFailed(self, connector, reason)
    protocol.ReconnectingClientFactory.clientConnectionFailed(self, connector, reason)
  def clientConnectionLost(self, connector, reason):
    """ handle client connection lost event """
    log.msg("connection lost: %s" % reason)
    pb.PBClientFactory.clientConnectionLost(self, connector, reason, reconnecting=True)
    protocol.ReconnectingClientFactory.clientConnectionLost(self, connector, reason)
  def clientConnectionMade(self, broker):
    """ handle client connection made event """
    self.resetDelay()
    pb.PBClientFactory.clientConnectionMade(self, broker)

def Application():
  """ the application """
  logging.basicConfig(level=logging.WARNING, format='%(message)s')

  f = open(os.environ['oftcdnscfg'])
  config = syck.load(f.read())
  f.close()
  application = service.Application('oftcdns')
  serviceCollection = service.IServiceCollection(application)

  # dns server
  subconfig = config['dns']
  auth = MyAuthority(subconfig['authority'])
  dnsFactory = MyDNSServerFactory(database=subconfig['database'], authorities=[auth])
  internet.TCPServer(subconfig['port'], dnsFactory, interface=subconfig['interface']).setServiceParent(serviceCollection)
  internet.UDPServer(subconfig['port'], dns.DNSDatagramProtocol(dnsFactory), interface=subconfig['interface']).setServiceParent(serviceCollection)

  # irc client
  subconfig = config['irc']
  ircFactory = MyBotFactory(subconfig['bot'], auth)
  if subconfig['ssl'] == True:
    internet.SSLClient(subconfig['server'], subconfig['port'], ircFactory, ssl.ClientContextFactory()).setServiceParent(serviceCollection)
  else:
    internet.TCPClient(subconfig['server'], subconfig['port'], ircFactory).setServiceParent(serviceCollection)

  # pb client
  subconfig = config['pb']
  pbFactory = MyPBClientFactory()
  client = MyPBClient(pbFactory, auth, subconfig['period'])
  internet.TCPClient(subconfig['server'], subconfig['port'], pbFactory).setServiceParent(serviceCollection)

  return application

application = Application()

# vim: set ts=2 sw=2 et fdm=indent:
