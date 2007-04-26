#!/usr/bin/ruby

require 'drb/drb'
require 'yaml'

SERVER_URI="druby://localhost:8787"
SERVERSYAML='servers.yaml'

DRb.start_service

irc = DRbObject.new_with_uri(SERVER_URI)

colors = ['red', 'blue', 'green', 'yellow', 'brown']

tmp = YAML::load(File.open(SERVERSYAML))['servers'] 
syaml = {}
tmp.each do |server|
  syaml[server['name']] = server.dup
end

servers = {}
conns = {}
versions = {}
uqver = {}
users = {}
global = 1

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
      global = value[1][0].chomp
      global = global.split(':')[1].strip.to_i
      users[servername] = local
    else
      $stderr.puts "couldn't get users for #{servername} #{ret} #{value}"
    end
  end
end

graph = File.open('oftc.dot', 'w')
graph.puts 'graph OFTC {'
#graph.puts "\tsubgraph lgd {"
#count = servers.length + 1
#uqver.each_key do |v|
#  version = uqver[v]
#  color = 'white'
#  color = colors[version] if uqver[v]
#  graph.puts "\t\t#{count} [label=\"#{v}\" style=filled fillcolor=#{color}];"
#  count += 1
#end
#graph.puts "\t}"

#graph.puts "\trankdir=BT;"

servers.each_key do |name|
  sid = servers[name]
  sname = name.split('.')[0]
  version = versions[name]
  color = 'white'
  color = colors[uqver[version]] if uqver[version]
  user = users[name]
  pct = (user.to_f / global.to_f) * 100
  hub = syaml[sname]['hub'] if sname != 'services'
  region = syaml[sname]['region'] if sname != 'services'
  graph.write "\t#{sid} [label=\"#{sname}"
  graph.write "\\nUsers: #{user} (%0.2f%%)" % pct if user and user > 0
  graph.write "\\n#{region}" if region
  graph.write "\""
  graph.write " shape=octagon" if hub == true
  graph.write " root=true" if hub == true
  graph.write " style=filled fillcolor=#{color}];\n"
end

conns.each_key do |name|
  conns[name].each { |c| graph.puts "\t#{servers[name]} -- #{servers[c]};" unless name == c }
end

graph.puts "}"
graph.close
