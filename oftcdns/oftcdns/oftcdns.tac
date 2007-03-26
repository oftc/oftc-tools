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
import IPy, itertools, logging, os, radix, random, signal, socket, string, syck, sys, time

def any(seq, pred=None):
  """ returns True if pred(x) is true for at least one element in the sequence """
  for elem in itertools.ifilter(pred, seq):
    return True
  return False

class Node:
  """ generic object that keeps track of statistics for a node """
  def __init__(self, name, nickname=None, limit=None, records=[], ttl=600):
    """ class constructor """
    self.name = name
    self.nickname = nickname
    if not self.nickname: self.nickname=name
    self.limit = limit
    self.records = {}
    for k,v in records:
      if k not in self.records: self.records[k] = []
      self.records[k] += [{4: MyRecord_A, 6: MyRecord_AAAA}[IPy.IP(v).version()](self, v, ttl)]
    self.active = 'disabled'
    self.active_tmp = self.active
    self.rank = 10000
    self.rank_tmp = self.rank
    self.last = time.time()
  def update_init(self):
    """ start the update cycle """
    self.rank_tmp = 0
  def update_active(self, active):
    """ update node's active flag """
    self.active_tmp = active
  def update_rank(self, rank):
    """ update node's rank """
    self.rank_tmp += rank
  def update_fini(self):
    """ complete the update cycle """
    self.active = self.active_tmp
    self.rank = self.rank_tmp
    self.last = time.time()
  def check(self, period):
    """ check that node is up to date """
    if time.time() > self.last + 2 * period:
      self.active = 'disabled'
      self.rank = 10000
  def to_str(self, label, type, marker):
    """ string representation """
    if any(self.records.get(label), lambda x: x.TYPE == type):
      return " %s%s(%s%s)%s" % (self.nickname, {True: "+", False: "-"}[self.active == "active"], self.rank, {True: "", False: "/%s" % self.limit}[self.limit is None], marker)
    else:
      return ""

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
    return itertools.ifilter(lambda x: x.active == 'active' and (x.limit is None or x.rank < x.limit), list.__iter__(self))
  def passive_nodes(self):
    """ return an iterator of active but loaded nodes """
    return itertools.ifilter(lambda x: x.active == 'active' and (x.limit is not None and x.rank >= x.limit), list.__iter__(self))
  def disabled_nodes(self):
    """ return an iterator of disabled nodes """
    return itertools.ifilter(lambda x: x.active == 'disabled', list.__iter__(self))
  def sort(self):
    """ utility function to sort list members """
    list.sort(self, lambda x, y: x.rank - y.rank)
  def to_str(self, label, type, count):
    """ string representation """
    s = ""
    i = 0
    for node in itertools.chain(self.active_nodes(), self.passive_nodes(), self.disabled_nodes()):
      s += node.to_str(label, type, {True: "*", False: ""}[i < count])
      i += 1
    return s

class ENAME(Exception):
  def __init__(self, (ans, auth, add)):
    self.ans = ans
    self.auth = auth
    self.add = add

class EREFUSED(Exception):
  def __init__(self, (ans, auth, add)):
    self.ans = ans
    self.auth = auth
    self.add = add

class MyAuthority(authority.BindAuthority):
  """ subclass of BindAuthority that knows about nodes and pools """
  def __init__(self, config):
    """ class constructor """
    authority.FileAuthority.__init__(self, config['zone'])
    if config['zone'] not in self.records: raise ValueError, "No records defined for %s." % config['zone']
    if not any(self.records[config['zone']], lambda x: x.TYPE == dns.SOA): raise ValueError, "No SOA record defined for %s." % config['zone']
    if not any(self.records[config['zone']], lambda x: x.TYPE == dns.NS): raise ValueError, "No NS records defined for %s." % config['zone']
    self.count = config['count']
    self.zone = config['zone']
    self.ttl = config['ttl']
    self.hostname = config['hostname']
    self.services = config['services']
    self.regions = config['regions']
    self.nodes = {}
    for node in config['nodes']:
      self.nodes[node['name']] = Node(node['name'], node.get('nickname'), node.get('limit'), node['records'], config['ttl'])
    self.pools = {}
    for key in ["%s-%s" % (x, y) for x in self.regions for y in self.services]:
      self.pools[key] = Pool([self.nodes[node] for node in self.nodes if key in self.nodes[node].records])
  def _lookup(self, name, cls, type, timeout = None):
    """ look up records """
    ans = []
    auth = []
    add = []

    (name, region, ip) = name.split('/')

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
      ans.append(dns.RRHeader(name, dns.TXT, dns.IN, self.ttl, dns.Record_TXT("region is %s" % region, ttl=self.ttl), auth=True))
      ans.append(dns.RRHeader(name, dns.TXT, dns.IN, self.ttl, dns.Record_TXT("client is %s / server is %s" % (ip, self.hostname), ttl=self.ttl), auth=True))

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
    message.queries[0].name = dns.Name("%s/%s/%s" % (message.queries[0].name, self.getRegion(ip), ip))
    server.DNSServerFactory.handleQuery(self, message, proto, address)
  def gotResolverResponse(self, (ans, auth, add), protocol, message, address):
    message.queries[0].name = dns.Name("%s" % message.queries[0].name.__str__().split('/')[0])
    for r in ans + auth:
      if r.isAuthoritative():
        message.auth = 1
        break
    server.DNSServerFactory.gotResolverResponse(self, (ans, auth, add), protocol, message, address)
  def gotResolverError(self, failure, protocol, message, address):
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

class MyRecord_A(dns.Record_A):
  """ subclass of Record_A that knows which Node it belongs to """
  def __init__(self, node, address="0.0.0.0", ttl=None):
    """ class constructor """
    self.node = node
    dns.Record_A.__init__(self, address, ttl)
  def __str__(self):
    """ string representation """
    return "A(%s)" % socket.inet_ntop(socket.AF_INET, self.address)

class MyRecord_AAAA(dns.Record_AAAA):
  """ subclass of Record_AAAA that knows which Node it belongs to """
  def __init__(self, node, address="::", ttl=None):
    """ class constructor """
    self.node = node
    dns.Record_AAAA.__init__(self, address, ttl)
  def __str__(self):
    """ string representation """
    return "AAAA(%s)" % socket.inet_ntop(socket.AF_INET6, self.address)

class MyBot(irc.IRCClient):
  """ subclass of IRCClient that implements our bot's functionality """
  def __init__(self, config):
    """ class constructor """
    self.config = config
    self.nickname = self.config['nickname']
    self.realname = self.config['realname']
    self.timer = task.LoopingCall(self.update)
  def __del__(self):
    """ class destructor """
    if self.timer.running:
      self.timer.stop()
    del self.timer
  def connectionLost(self, reason):
    """ stop the timer when connection has been lost """
    irc.IRCClient.connectionLost(self, reason)
    if self.timer.running:
      self.timer.stop()
  def signedOn(self):
    """ once signed on, oper up if configured to do so else join channel """
    logging.info("signed on to %s:%s" % (self.config['server'], self.config['port']))
    if not self.timer.running:
      self.timer.start(self.config['update period'])
    if self.config.has_key('oper') and self.config['oper'].has_key('username') and self.config['oper']['password']:
      self.sendLine("OPER %s %s" % (self.config['oper']['username'], self.config['oper']['password']))
    else:
      self.join(self.config['channel'])
  def irc_RPL_YOUREOPER(self, prefix, params):
    """ oper up succeeded, so join channel """
    logging.info("oper succeeded")
    self.join(self.config['channel'])
  def irc_ERR_PASSWDMISMATCH(self, prefix, params):
    """ oper up failed due to password mismatch; ignore and join channel """
    logging.info("oper failed: password mismatch") # but keep going
    self.join(self.config['channel'])
  def irc_ERR_NOOPERHOST(self, prefix,params): # oper reply
    """ oper up failed due to no operhost line; ignore and join channel """
    logging.info("oper failed: no oper host") # but keep going
    self.join(self.config['channel'])
  def irc_ERR_NEEDMOREPARAMS(self, prefix,params):
    """ oper up failed due to incorrect command syntax; ignore and join channel """
    logging.info("oper failed: need more params") # but keep going
    self.join(self.config['channel'])
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
  def update(self):
    """ asking each node to report its statistics - call update_init """
    for node in self.factory.auth.nodes:
      self.factory.auth.nodes[node].update_init()
      self.sendLine("STATS P %s" % node)
    reactor.callLater(self.config['update period']/2, self.check)
  def irc_220(self, prefix, params):
    """ handle 220 responses - call update_active and update_rank """
    if params[2] == '6667':
      self.factory.auth.nodes[prefix].update_active(params[-1])
    self.factory.auth.nodes[prefix].update_rank(string.atoi(params[4]))
  def irc_RPL_ENDOFSTATS(self, prefix, params):
    """ handle 219 responses - call update_fini """
    self.factory.auth.nodes[prefix].update_fini()
  def check(self):
    for node in self.factory.auth.nodes:
      self.factory.auth.nodes[node].check(self.config['update period'])
    for pool in self.factory.auth.pools:
      self.factory.auth.pools[pool].sort()

class MyBotFactory(protocol.ReconnectingClientFactory):
  """ subclass of ClientFactory that knows about MyAuthority """
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
  internet.TCPServer(subconfig['port'], dnsFactory, interface=subconfig['interface']).setServiceParent(serviceCollection)
  internet.UDPServer(subconfig['port'], dns.DNSDatagramProtocol(dnsFactory), interface=subconfig['interface']).setServiceParent(serviceCollection)

  # irc client
  subconfig = config['irc']
  ircFactory = MyBotFactory(subconfig, auth)
  if subconfig['ssl'] == True:
    internet.SSLClient(subconfig['server'], subconfig['port'], ircFactory, ssl.ClientContextFactory()).setServiceParent(serviceCollection)
  else:
    internet.TCPClient(subconfig['server'], subconfig['port'], ircFactory).setServiceParent(serviceCollection)

  return application

application = Application()

# vim: set ts=2 sw=2 et fdm=indent:
