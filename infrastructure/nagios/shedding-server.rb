#!/usr/bin/ruby

require 'net/IRC'
require 'drb/drb'
require 'yaml'
require 'optparse'

def show_help(parser, code=0, io=STDOUT)
  program_name = File.basename($0, '.*')
  io.puts "Usage: #{program_name} <configfile>"
  io.puts parser.summarize
  exit(code)
end
ARGV.options do |opts|
        opts.on_tail("-h", "--help" , "Display this help screen")                { show_help(opts) }
        opts.parse!
end
show_help(ARGV.options, 1, STDERR) if ARGV.length != 1
CONFFILE = ARGV.shift

unless File.exists?(CONFFILE)
	STDERR.puts "File #{CONFFILE} does not exist"
	exit 1;
end
CONF = YAML::load( File.open(CONFFILE) )

error = false
%w{operuser operpass nick user gecos server port password bindip usessl}.each do |key|
	unless CONF.has_key?(key)
		STDERR.puts "Key #{key} not found in config file #{CONFFILE}."
		error = true
	end
end
exit 1 if error

OPER_USER = CONF['operuser']
OPER_PASS = CONF['operpass']
NICK = CONF['nick']
USER = CONF['user']
GCOS = CONF['gecos']
SERVER = CONF['server']
PORT = CONF['port']
PASSWORD = CONF['password']
BINDIP = CONF['bindip']
USESSL = CONF['usessl']


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
