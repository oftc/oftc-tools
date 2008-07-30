#!/usr/bin/ruby

require 'net/IRC'

NICK      = 'rubyircbot'
USER      = 'rubyircbot'
GECOS     = 'OFTC Ruby IRC Library'
CHANNEL   = '#test'
SERVER    = 'irc.oftc.net'
PORT      = 6697
PASSWORD  = ''
USESSL    = true
BINDIP    = nil

def privmsg(sender, source, params)
  sender.say(params.shift, params.join(' '))
  puts "%s said %s" % [source, params.join(' ')]
end

def end_motd(sender, source, params)
  puts 'conntected'
  sender.join(CHANNEL)
  sender.say(CHANNEL, 'Hello World!')
end

inthandler = proc{
  puts '^C pressed'
  $conn.quit('SIGINT')
}

trap('SIGINT', inthandler)

$conn = IRC.new(NICK, USER, GECOS)
$conn.add_handler('PRIVMSG', method(:privmsg))
$conn.add_handler('376', method(:end_motd))
$conn.connect(SERVER, PORT, PASSWORD, BINDIP, USESSL)
$conn.run
