#!/usr/bin/ruby

require 'drb/drb'

SERVER_URI="druby://localhost:8787"

DRb.start_service

irc = DRbObject.new_with_uri(SERVER_URI)

colors = ['red', 'blue', 'green', 'yellow', 'brown']

servers = {}
conns = {}
versions = {}
uqver = {}
count = 0

ret, links = irc.get_links
if ret
  links.each do |x|
    source = x[0]
    dest = x[1]
    servers[source] = servers.length unless servers[source]
    conns[source] = [] unless conns[source]
    conns[source] << dest
  end
end

servers.each_key do |servername|
  if servername != "services.oftc.net"
    ret, value = irc.get_version(servername)
    if ret
      value = value.split('+')[1]
      value = value[4, value.index('(')-4]
      versions[servername] = value if ret
      uqver[value] = uqver.length unless uqver[value]
    else
      $stderr.puts "couldn't get version for #{servername} #{ret} #{value}"
    end
  end
end

puts 'graph OFTC {'
servers.each_key do |name|
  sid = servers[name]
  sname = name.split('.')[0]
  version = versions[name]
  color = 'white'
  color = colors[uqver[version]] if uqver[version]
  puts "\t#{sid} [label=\"#{sname}(#{version})\" style=filled fillcolor=#{color}];"
end

subgraph = {}

conns.each_key do |name|
  conns[name].each { |c| puts "\t#{servers[name]} -- #{servers[c]} [len=5];" unless name == c }
end

puts "}"
