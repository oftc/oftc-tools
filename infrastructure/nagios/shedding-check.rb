#!/usr/bin/ruby
#
require 'drb/drb'
require 'yaml'
require 'optparse'
require 'ostruct'

# The URI to connect to
SERVER_URI="druby://localhost:8787"

# Start a local DRbServer to handle callbacks.
#
# Not necessary for this small example, but will be required
# as soon as we pass a non-marshallable object as an argument
# to a dRuby call.
DRb.start_service

OK       = 0
WARNING  = 1
CRITICAL = 2
UNKNOWN  = 3

options = OpenStruct.new
options.check_type = ''
options.server = ''
options.warning = ''
options.critical = ''

def show_help(parser, code=0, io=STDOUT)
  program_name = File.basename($0, '.*')
  io.puts parser.banner
  io.puts parser.summarize
  exit(code)
end

ARGV.options do |opts|
    opts.banner = 'Usage: shedding-check -t <users|stats> [[-w] [-c]] -s <server name>'
    opts.separator ''
    opts.separator 'Specific options:'

    opts.on('-tTYPE', '--type TYPE', 'Either users or stats') do |t|
      options.check_type = t.downcase
    end

    opts.on('-sSERVER', '--server SERVERNAME', 'Specify the server to check') do |s|
      IRCNAGIOSINFO = '/home/oftc/oftc-is/config/.tmp/nagiosinfo'
      if File.exists?(IRCNAGIOSINFO)
        info = YAML::load( File.open( IRCNAGIOSINFO ) )
        ip_to_name = {}
        info.each{ |s| ip_to_name[s['ip']] = s['name'] }
        
        if ip_to_name.has_key?(s)
          options.server = ip_to_name[ s ]
          options.server = options.server + '.oftc.net'
        else
          options.server = s
        end
      else
        # else you just have to give it a proper name
        options.server = s
      end
    end

    opts.on('-wLEVEL', '--warning LEVEL', Float,
            '% to send WARNING',
            '(only necessary for users check)') do |w|
      options.warning = w
    end

    opts.on('-cLEVEL', '--critical LEVEL', Float,
            '% to send CRITICAL',
            '(only necessary for users check)') do |c|
      options.critical = c
    end
    
    opts.on_tail("-h", "--help", "Show this message") do
      show_help(opts, UNKNOWN)
    end

  opts.parse!
end

def check_stats(irc, servername)
  success, result = irc.get_stats(servername, 'E')

  shedding = false
  listening = false
  timeoute = false
  noserver = false
  notoper = false
  result = ''

  if success
    result.each do |x|
      if x.is_a?(Array) then
        x.each do |y|
          line = y.strip.split(/\s+/)
          shedding = y.index(/shed/) if line.length >= 3
          break if shedding
        end
        break if shedding
      end
    end
  else
    timeout = true if result == "timeout"
    noserver = true if result == "No such server"
    notoper = true if result == "not opered"
  end

  if !timeout && !noserver && !notoper && shedding then
    success, result = irc.get_stats(servername, 'P')
    if success
      result.each do |x|
        if x.is_a?(Array) then
        	line = x.join(' ')
        	listening = line.index(/6667.*active/)
        	break if listening
        end
        break if listening
      end
    end
  end

  if listening && shedding then
    puts "CRITICAL: Shedding and Listening Enabled on #{servername}"
    exit(CRITICAL)
  end

  if timeout then
    puts "UNKNOWN: Timed out getting stats on #{servername}"
    exit(UNKNOWN)
  end

  if noserver then
    puts "UNKNOWN: No Such Server: #{servername}"
    exit(UNKNOWN)
  end

  if notoper then
    puts 'WARNING: Not Oper'
    exit(WARNING)
  end

  if shedding
	  puts "OK: #{servername}: shedding but not listening on userports"
  else
	  puts "Ok: #{servername}: not shedding"
  end
  
  exit(OK)
end

def check_users(irc, servername, warning, critical)
  success, result = irc.get_user_count(servername)
  if success
    local = result[0][0].chomp
    local = local.split(':')[1].strip.to_f
    global = result[1][0].chomp
    global = global.split(':')[1].strip.to_f
    percent = local / global * 100
    if percent > critical
      puts "CRITICAL: Network User Load is %02.2f > #{critical} on #{servername}" % percent
      exit(CRITICAL)
    else
      if percent > warning
        puts "WARNING: Network User Load is %02.2f > #{warning} on #{servername}" % percent
        exit(WARNING)
      else
        puts "OK: Network User Load on #{servername} is %02.2f" % percent
        exit(OK)
      end
    end
  else
    case result
      when 'timeout'
        puts "UNKNOWN: Timed out getting users on #{servername}"
        exit(UNKNOWN)
      when 'No such server'
        puts "UNKNOWN: No Such Server: #{servername}"
        exit(UNKNOWN)
      when 'not opered'
        puts 'UNKNOWN: Not Oper'
     end
  end
end

irc = DRbObject.new_with_uri(SERVER_URI)

case options.check_type
  when 'stats'
    check_stats(irc, options.server)
  when 'users'
    check_users(irc, options.server, options.warning, options.critical)
end

