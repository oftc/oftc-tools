#!/usr/bin/ruby

require 'drb/drb'

SERVER_URI="druby://localhost:8787"

DRb.start_service

irc = DRbObject.new_with_uri(SERVER_URI)

servers = {}
conns = {}
versions = {}
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
    else
      $stderr.puts "couldn't get version for #{servername} #{ret} #{value}"
    end
  end
end

puts 'graph OFTC {'
servers.each_key do |name|
  puts "\t#{servers[name]} [label=\"#{name.split('.')[0]}(#{versions[name]})\"];"
end

subgraph = {}

conns.each_key do |name|
  conns[name].each { |c| puts "\t#{servers[name]} -- #{servers[c]};" unless name == c }
end

puts "}"
