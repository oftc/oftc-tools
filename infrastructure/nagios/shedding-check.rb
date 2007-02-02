#!/usr/bin/ruby
#
require 'drb/drb'
require 'yaml'

# The URI to connect to
SERVER_URI="druby://localhost:8787"

# Start a local DRbServer to handle callbacks.
#
# Not necessary for this small example, but will be required
# as soon as we pass a non-marshallable object as an argument
# to a dRuby call.
DRb.start_service

IRCNAGIOSINFO = '/home/oftc/oftc-is/config/.tmp/nagiosinfo'
info = YAML::load( File.open( IRCNAGIOSINFO ) )
ip_to_name = {}
info.each{ |s| ip_to_name[s['ip']] = s['name'] }

name = ip_to_name[ ARGV[0] ]
unless name
	STDERR.puts "Did not find servername for host #{ARGV[0]}"
	exit 1
end
name = name + '.oftc.net'


irc = DRbObject.new_with_uri(SERVER_URI)
retE = irc.get_stats('E', name)

retE.each do |x|
  if x.is_a?(Array) then
    x.each do |y|
      line = y.strip.split(/\s+/)
      $shedding = y.index(/shed/) if line.length >= 3
      break if $shedding
    end
    break if $shedding
  else
    $timeout = true if x.index(/timeout/)
    $noserver = true if x.index(/no such server/i)
    $notoper = true if x.index(/not oper/i)
  end
end

if !$timeout && !$noserver && !$oper && $shedding then
  retP = irc.get_stats('P', name)
  retP.each do |x|
    if x.is_a?(Array) then
      line = x.join(' ')
      $listening = line.index(/6667.*active/)
      break if $listening
    end
  break if $listening
  end
end

if $listening && $shedding then
  puts 'CRITICAL: Shedding and Listening Enabled on '+name
  exit(2)
end

if $timeout then
  puts 'UNKNOWN: Timed out getting stats on '+name
  exit(3)
end

if $noserver then
  puts 'UNKNOWN: No Such Server: '+name
  exit(3)
end

if $notoper then
  puts 'WARNING: Not Oper'
  exit(3)
end

if $shedding
	puts 'OK: '+name+ ": shedding but not listening on userports"
else
	puts 'OK: '+name+ ": not shedding"
end
exit(0)
