#!/usr/bin/ruby
#
require 'drb/drb'

# The URI to connect to
SERVER_URI="druby://localhost:8787"

# Start a local DRbServer to handle callbacks.
#
# Not necessary for this small example, but will be required
# as soon as we pass a non-marshallable object as an argument
# to a dRuby call.
DRb.start_service

irc = DRbObject.new_with_uri(SERVER_URI)
retE = irc.get_stats('E', ARGV[0])

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
  retP = irc.get_stats('P', ARGV[0])
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
  puts 'CRITICAL: Shedding and Listening Enabled on '+ARGV[0]
  exit(2)
end

if $timeout then
  puts 'UNKNOWN: Timed out getting stats on '+ARGV[0]
  exit(3)
end

if $noserver then
  puts 'UNKNOWN: No Such Server: '+ARGV[0]
  exit(3)
end

if $notoper then
  puts 'WARNING: Not Oper'
  exit(3)
end

puts 'OK: '+ARGV[0]
exit(0)
