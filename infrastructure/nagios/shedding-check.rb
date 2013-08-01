#!/usr/bin/ruby1.8
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

IRCNAGIOSINFO = '/home/oftc/oftc-is/config/.tmp/nagiosinfo'

options = OpenStruct.new

def show_help(parser, code=0, io=STDOUT)
  program_name = File.basename($0, '.*')
  io.puts parser.banner
  io.puts parser.summarize
  exit(code)
end

ARGV.options do |opts|
  opts.banner = 'Usage: shedding-check -t <users|shedding|rlimit|users-by-rlimit> [[-w] [-c]] -s <server name>'
  opts.separator ''
  opts.separator 'Specific options:'

  opts.on('-tTYPE', '--type TYPE', 'Either users, shedding, rlimit, users-by-rlimit')         { |options.check_type| }
  opts.on('-sSERVER', '--server SERVERNAME', 'Specify the server to check')  { |options.server| }
  opts.on('-wLEVEL', '--warning LEVEL', Float, '% to send WARNING', '(only necessary for users check)') { |options.warning| }
  opts.on('-cLEVEL', '--critical LEVEL', Float, '% to send CRITICAL', '(only necessary for users check)') { |options.critical| }
  opts.on_tail("-h", "--help", "Show this message") { show_help(opts, UNKNOWN) };

  opts.parse!
end

show_help(ARGV.options, UNKNOWN, STDERR) if ARGV.length > 0
show_help(ARGV.options, UNKNOWN, STDERR) unless options.server
show_help(ARGV.options, UNKNOWN, STDERR) unless %w{users shedding rlimit users-by-rlimit}.include?(options.check_type)


if File.exists?(IRCNAGIOSINFO)
  info = YAML::load( File.open( IRCNAGIOSINFO ) )
  ip_to_name = {}
  info.each{ |s| ip_to_name[s['ip']] = s['name'] }

  if ip_to_name.has_key?(options.server)
    options.server = ip_to_name[ options.server ]
    options.server = options.server + '.oftc.net'
  end
else
  # else you just have to give it a proper name
end



def handle_error(infoline, servername)
  case infoline
    when "timeout"
      puts "UNKNOWN: Timed out getting stats on #{servername}"
      exit(UNKNOWN)
    when "No such server"
      puts "UNKNOWN: No Such Server: #{servername}"
      exit(UNKNOWN)
    when "not opered"
      puts 'WARNING: Not Oper'
      exit(WARNING)
  end
  puts "UNKNOWN: Unknown result #{infoline} for #{servername}"
  exit(UNKNOWN)
end


# will exit if it can't get it
def get_rlimit(irc, servername)
  success, result = irc.get_stats(servername, 'z')
  handle_error(result, servername) unless success

  result.each do |line|
    if line.include?('rlimit')
      soft = line.scan(/rlimit_nofile: soft: (\d+);/)
      next unless soft
      soft = soft[0][0].to_i
      return soft
    end
  end

  puts "UNKNOWN: #{servername}: no rlimit info"
  exit(UNKNOWN)
end

def get_user_count(irc, servername)
  success, result = irc.get_user_count(servername)
  handle_error(result, servername) unless success

  local = result[0][0].chomp
  local = local.split(':')[1].strip.to_f
  global = result[1][0].chomp
  global = global.split(':')[1].strip.to_f

  return local, global
end



def check_users(irc, servername, warning, critical)
  local, global = get_user_count(irc, servername)

  percent = local / global * 100
  if percent > critical
    puts "CRITICAL: Network User Load is %02.2f%% > #{critical}%% on #{servername}" % percent
    exit(CRITICAL)
  elsif percent > warning
    puts "WARNING: Network User Load is %02.2f%% > #{warning}%% on #{servername}" % percent
    exit(WARNING)
  else
    puts "OK: Network User Load on #{servername} is %02.2f%%" % percent
    exit(OK)
  end
end

def check_stats_shedding(irc, servername)
  shedding = false
  listening = false

  success, result = irc.get_stats(servername, 'E')
  handle_error(result, servername) unless success
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

  if shedding then
    success, result = irc.get_stats(servername, 'P')
    handle_error(result, servername) unless success
    result.each do |x|
      if x.is_a?(Array) then
        line = x.join(' ')
        listening = line.index(/6667.*active/)
        break if listening
      end
      break if listening
    end
  end

  if listening && shedding then
    puts "CRITICAL: Shedding and Listening Enabled on #{servername}"
    exit(CRITICAL)
  end

  if shedding
    puts "OK: #{servername}: shedding but not listening on userports"
  else
    puts "Ok: #{servername}: not shedding"
  end
  exit(OK)
end

def check_stats_rlimit(irc, servername, warning, critical)
  softlimit = get_rlimit(irc, servername)

  if softlimit < critical
    puts "CRITICAL: #{servername}: soft ulimit #{softlimit} less than #{critical}"
    exit(CRITICAL)
  elsif softlimit < warning
    puts "WARNING: #{servername}: soft ulimit #{softlimit} less than #{warning}"
    exit(WARNING)
  else
    puts "OK: #{servername}: soft ulimit is #{softlimit}"
    exit(OK)
  end
end

def check_stats_users_by_rlimit(irc, servername, warning, critical)
  softlimit = get_rlimit(irc, servername)
  local, global = get_user_count(irc, servername)

  ratio = local / softlimit
  r = "%04.4f" % [ratio]
  if ratio > critical
    puts "CRITICAL: #{servername}: users/ulimit == #{r} > #{critical}. (users: #{local}, ulimit -n: #{softlimit})"
    exit(CRITICAL)
  elsif ratio > warning
    puts "WARNING: #{servername}: users/ulimit == #{r} > #{warning}. (users: #{local}, ulimit -n: #{softlimit})"
    exit(WARNING)
  else
    puts "OK: #{servername}: users/ulimit == #{r}. (users: #{local}, ulimit -n: #{softlimit})"
    exit(OK)
  end
end


irc = DRbObject.new_with_uri(SERVER_URI)

case options.check_type
  when 'shedding'
    check_stats_shedding(irc, options.server)
  when 'users'
    options.warning = 20 unless options.warning
    options.critical = 40 unless options.critical
    check_users(irc, options.server, options.warning, options.critical)
  when 'rlimit'
    options.critical = 1000 unless options.critical
    options.warning = 4000 unless options.warning
    check_stats_rlimit(irc, options.server, options.warning.to_i, options.critical.to_i)
  when 'users-by-rlimit'
    options.critical = 0.9 unless options.critical
    options.warning = 0.8 unless options.warning
    check_stats_users_by_rlimit(irc, options.server, options.warning.to_f, options.critical.to_f)
end

