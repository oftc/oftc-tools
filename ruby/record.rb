#!/usr/bin/ruby

require 'IRC'

def eob(sender, source, params)
  sender.send("EOB")
end

def raw_recv(sender, source, msg)
  puts "#{Time.now.to_i} #{msg}"
end

server = ''
port = 6667
password = ''
name = ''
info = ''
tsid = ''

conn = IRC.new(name, tsid, info, false, true)
conn.add_handler('EOB', method(:eob))
conn.add_handler('RAWRECV', method(:raw_recv))
conn.connect(server, port, password)
conn.run
