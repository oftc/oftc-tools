#!/usr/bin/ruby

require 'net/IRC'

NICK      = 'rubyircbot'
USER      = 'rubyircbot'
GECOS     = 'OFTC Ruby IRC Library'
CHANNEL   = '#test'
SERVER    = 'ircs.oftc.net'
PORT      = 9999
PASSWORD  = ''
USESSL    = true

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
$conn.add_handler('PRIVMSG', :privmsg)
$conn.add_handler('376', :end_motd)
$conn.connect(SERVER, PORT, PASSWORD, USESSL)
$conn.run
