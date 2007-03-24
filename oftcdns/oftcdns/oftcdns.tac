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

def flatten(seqOfSeqs):
  """ returns a flattened sequence from a sequence of sequences """
  return list(itertools.chain(*seqOfSeqs))

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
  def __str__(self):
    """ string representation """
    s = "%s(%s)%s:" % (self.nickname, self.rank, {True: '+', False: ''}[self.active == 'active'])
    for key,vals in self.records.iteritems():
      s += " %s[%s]" % (key, ",".join([x.__str__() for x in vals]))
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
      itertools.islice(self.records(dns.TXT),  self.count),
      itertools.islice(self.records(dns.A),    self.count),
      itertools.islice(self.records(dns.AAAA), self.count))
  def records(self, type):
    """ iterator helper """
    if any(self.active_records(type)):      # return active records, if any
      return self.active_records(type)
    elif any(self.passive_records(type)):   # else passive records, if any
      return self.passive_records(type)
    elif any(self.disabled_records(type)):  # else disabled records, if any
      return self.disabled_records(type)
    else:                                   # else all records (degenerate case)
      return self.all_records(type)
  def active_records(self, type):
    """ return an iterator of active and unloaded records of the specified type """
    return itertools.ifilter(lambda x: (x.TYPE == type) and (x.node.active == 'active') and ((x.node.limit is None) or (x.node.rank < x.node.limit)), list.__iter__(self))
  def passive_records(self, type):
    """ return an iterator of active but loaded records of the specified type """
    return itertools.ifilter(lambda x: (x.TYPE == type) and (x.node.active == 'active') and (x.node.limit is not None) and (x.node.rank >= x.node.limit), list.__iter__(self))
  def disabled_records(self, type):
    """ return an iterator of disabled records of the specified type """
    return itertools.ifilter(lambda x: (x.TYPE == type) and (x.node.active == 'disabled'), list.__iter__(self))
  def all_records(self, type):
    """ return an iterator all records of the specified type """
    return itertools.ifilter(lambda x: x.TYPE == type, list.__iter__(self))
  def print_pool(self, type):
    """ return a string representation of the pool """
    s = "%s(%s):" % (self.name, {dns.A: "A", dns.AAAA: "AAAA"}[type])
    (s,i) = self.print_records(s, 0, self.active_records(type), "+")
    (s,i) = self.print_records(s, i, self.passive_records(type), "-")
    (s,i) = self.print_records(s, i, self.disabled_records(type))
    return s
  def print_records(self, s, i, seq, marker=""):
    """ return a string representation of the records of the specified type """
    if i > 0: i = self.count
    for x in seq:
      s += " %s%s(%s%s)%s" % (x.node.nickname, marker, x.node.rank, {True: "", False: "/%s" % x.node.limit}[x.node.limit is None], {True: "*", False: ""}[i < self.count])
      i += 1
    return (s, i)
  def sort(self):
    """ utility function to sort list members """
    logging.debug("sorting %s" % self.name)
    list.sort(self, lambda x, y: x.node.rank - y.node.rank)

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
    self.nodes = {}
    for node in config['nodes']:
      # we use get for 'nickname' and 'limit' because we want None when it isn't set
      self.nodes[node['name']] = Node(node['name'], node.get('nickname'), node.get('limit'), node['records'], config['ttl'])
    self.pools = []
    self.hostname = config['hostname']
    self.services = config['services']
    self.regions = config['regions']
    self.default_ttl = config['ttl']
    for _service in self.services:
      for _region in self.regions:
        k = "%s-%s" % (_region, _service)
        v = [MyRecord_TXT("%s service for %s region" % (_service, _region), ttl=self.default_ttl)] + flatten([self.nodes[node].records[k] for node in self.nodes if k in self.nodes[node].records])
        self.pools.append(Pool(k, v, config['count']))
        self.records["%s.%s" % (k, config['zone'])] = self.pools[-1]
        self.records["%s-unfiltered.%s" % (k, config['zone'])] = v
  def _lookup(self, name, cls, type, timeout = None):
    """ lookup records """
    ans = []
    auth = []
    add = []
    ttl = self.default_ttl
    zone = self.soa[0].lower()

    (name, region, ip) = name.split('/')

    if region not in self.regions:
      return defer.fail(failure.Failure(EREFUSED((ans, auth, add))))

    if not name.lower().endswith(zone):
      return defer.fail(failure.Failure(EREFUSED((ans, auth, add))))

    key = name.lower()
    shuffle = False
    for _service in self.services:
      if name.lower().startswith("%s." % _service):
        key = "%s-%s.%s" % (region, _service, zone)
        shuffle = True

    # construct answer section
    records = self.records.get(key, ())
    if type == dns.ALL_RECORDS:
      ans = [dns.RRHeader(name, x.TYPE, dns.IN, x.ttl or ttl, x, auth=True) for x in records]
    else:
      ans = [dns.RRHeader(name, x.TYPE, dns.IN, x.ttl or ttl, x, auth=True) for x in itertools.ifilter(lambda x: x.TYPE == type, records)]
      if not ans:
        ans = [dns.RRHeader(name, x.TYPE, dns.IN, x.ttl or ttl, x, auth=True) for x in itertools.ifilter(lambda x: x.TYPE == dns.CNAME, records)]

    # construct authority section
    if ans:
      if type != dns.NS:
        auth = [dns.RRHeader(zone, x.TYPE, dns.IN, x.ttl or ttl, x, auth=True) for x in itertools.ifilter(lambda x: x.TYPE == dns.NS, self.records.get(zone, ()))]
    else:
      auth = [dns.RRHeader(zone, x.TYPE, dns.IN, x.ttl or ttl, x, auth=True) for x in itertools.ifilter(lambda x: x.TYPE == dns.SOA, self.records.get(zone, ()))]
      if not records:
        return defer.fail(failure.Failure(ENAME((ans, auth, add))))

    # construct additional section
    for header in ans + auth:
      section = {dns.NS: add, dns.CNAME: ans, dns.MX: add}.get(header.type)
      if section is not None:
        n = str(header.payload.name)
        for record in self.records.get(n.lower(), ()):
          if record.TYPE == dns.A:
            section.append(dns.RRHeader(n, record.TYPE, dns.IN, record.ttl or default_ttl, record, auth=True))

    if type == dns.TXT or type == dns.ALL_RECORDS:
      ans.append(dns.RRHeader(name, dns.TXT, dns.IN, ttl, dns.Record_TXT("client is %s / server is %s" % (ip, self.hostname), ttl=0), auth=True))

    if shuffle:
      random.shuffle(ans)

    return defer.succeed((ans, auth, add))

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

class MyRecord_TXT(dns.Record_TXT):
  """ subclass of Record_TXT that has a 'node' member """
  def __init__(self, data, ttl=None):
    """ class constructor """
    self.node = Node('', '')
    dns.Record_TXT.__init__(self, data, ttl=ttl)

class MyRecord_A(dns.Record_A):
  """ subclass of Record_A that has a 'node' member """
  def __init__(self, node, address="0.0.0.0", ttl=None):
    """ class constructor """
    self.node = node
    dns.Record_A.__init__(self, address, ttl)
  def __str__(self):
    """ string representation """
    return "A(%s)" % socket.inet_ntop(socket.AF_INET, self.address)

class MyRecord_AAAA(dns.Record_AAAA):
  """ subclass of Record_AAAA that has a 'node' member """
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
  def do_nodes(self, username, channel):
    """ handle nodes request """
    self.msg(channel, "%s: node status is" % username)
    for node in self.factory.auth.nodes:
      self.msg(channel, "%s:   %s" % (username, self.factory.auth.nodes[node]))
  def do_pools(self, username, channel):
    """ handle pools request """
    self.msg(channel, "%s: pool status is" % username)
    for pool in self.factory.auth.pools:
      self.msg(channel, "%s:   %s" % (username, pool.print_pool(dns.A)))
      self.msg(channel, "%s:   %s" % (username, pool.print_pool(dns.AAAA)))
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
      pool.sort()

class MyBotFactory(protocol.ReconnectingClientFactory):
  """ subclass of ClientFactory that knows about """
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
  #logging.basicConfig(level=logging.WARNING, format='%(message)s')

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
