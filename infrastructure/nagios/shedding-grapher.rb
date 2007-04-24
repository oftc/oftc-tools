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
users = {}

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
      versions[servername] = value
      uqver[value] = uqver.length unless uqver[value]
    else
      $stderr.puts "couldn't get version for #{servername} #{ret} #{value}"
    end

    ret, value = irc.get_user_count(servername)

    if ret
      local = value[0][0].chomp
      local = local.split(':')[1].strip.to_i
      users[servername] = local
    else
      $stderr.puts "couldn't get users for #{servername} #{ret} #{value}"
    end
  end
end

puts 'graph OFTC {'
puts "\tsubgraph lgd {"
count = servers.length + 1
uqver.each_key do |v|
  version = uqver[v]
  color = 'white'
  color = colors[version] if uqver[v]
  puts "\t\t#{count} [label=\"#{v}\" style=filled fillcolor=#{color}];"
  count += 1
end
puts "\t}"

puts "\trankdir=BT;"

servers.each_key do |name|
  sid = servers[name]
  sname = name.split('.')[0]
  version = versions[name]
  color = 'white'
  color = colors[uqver[version]] if uqver[version]
  user = users[name]
  puts "\t#{sid} [label=\"#{sname}(#{user})\" style=filled fillcolor=#{color}];"
end

conns.each_key do |name|
  conns[name].each { |c| puts "\t#{servers[name]} -- #{servers[c]} [len=5];" unless name == c }
end

puts "}"
