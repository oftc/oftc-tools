#!/usr/bin/ruby

require 'net/IRC'
require 'drb/drb'

OPER_USER = ''
OPER_PASS = ''
NICK = 'oftc-bot-shedding'
USER = 'oftc-bot-shedding'
GCOS = 'OFTC Nagios Shedding'
SERVER = 'irc.oftc.net'
PORT = '9999'
PASSWORD = ''
BINDIP = ''
USESSL = true

class SheddingCheck
  def initialize
    @conn = nil
    @is_oper = false
    @in_stats = false

    Thread.new do
      @conn = IRC.new(NICK, USER, GCOS)
      @conn.add_handler('219', method(:stats_end))
      @conn.add_handler('220', method(:stats_pline))
      @conn.add_handler('249', method(:stats_debug))
      @conn.add_handler('381', method(:is_oper))
      @conn.add_handler('402', method(:no_such_server))
      @conn.add_handler('RECONNECT', method(:reconnect))
      @conn.add_handler('CONNECTED', method(:connected))
      @conn.connect(SERVER, PORT, PASSWORD, BINDIP, USESSL)
      @conn.run
    end
  end

  def reconnect(sender, source, params)
    puts '... reconnecting ...'
    @results = ['timeout'] if @in_stats
    @in_stats = false
    @is_oper = false
  end

  def connected(sender, source, params)
    puts "%s is connected" % sender.nickname
    sender.send("OPER %s %s" % [OPER_USER, OPER_PASS])
    @in_stats = false
  end

  def no_such_server(sender, source, params)
    @results.push('No Such Server')
    @in_stats = false
    Thread.pass
  end

  def is_oper(sender, source, params)
    @is_oper = true
  end

  def stats_pline(sender, source, params)
    @results.push(params)
  end

  def stats_debug(sender, source, params)
    @results.push(params)
  end

  def stats_end(sender, source, params)
    @in_stats = false
  end
  
  def get_stats(letter, server)
    return 'not oper' if !@is_oper
    t = Thread.new do
    puts 'Get Stats For '+server

    timeout = Time.now + 5

    if(@in_stats)
      puts 'Waiting for old stats query' if @in_stats
    
      while(@in_stats && Time.now < timeout) do 
        Thread.pass
      end

      if Time.now > timeout then
        @results.push('timeout')
        @in_stats = false
        puts 'Timeout Waiting for Stats to be available'
        Thread.exit
      end
    end

    @results = []
    @in_stats = true
    @conn.send("VERSION %s" % server)
    @conn.one_loop
    @conn.send("STATS %s %s" % [letter, server]) if @in_stats
    
    while(@in_stats && Time.now < timeout) do
      Thread.pass
    end
    
    if Time.now > timeout then
      @results.push('timeout')
      @in_stats = false
      puts 'Timeout Waiting for Stats for '+server
      Thread.exit
    end
    end

    t.join

    return @results
  end

  def quit
    @conn.quit('')
  end
end

inthandler = proc{
  puts "^C pressed"
  $foo.quit
  DRb.stop_service
}

trap("SIGINT", inthandler)
$SAFE = 1
URI = "druby://localhost:8787"
$foo = SheddingCheck.new
DRb.start_service(URI, $foo)

DRb.thread.join
