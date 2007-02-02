require 'socket'
require 'thread'
#require 'openssl'

class IRC
  def initialize(nickname, username, realname)
    @username = username
    @realname = realname
    @nickname = nickname
    @commands = {} if !@commands

    @debug = false
    
    add_handler('PING', method(:pong))
    add_handler('ERROR', method(:error))
  end

  def connect(server, port, password = '', bindip = nil, usessl = false)
    @server = server
    @port = port
    @password = password
    @usessl = usessl
    @quitting = false
    @bindip = bindip
    
    @reconnect = true

    inner_connect
  end

  def inner_connect
    @sock = TCPSocket.open(@server, @port, @bindip)
    
    if @usessl 
      require 'openssl'
      unless defined?(OpenSSL)
        raise "ruby OpenSSL isn't installed"
      end
      context = OpenSSL::SSL::SSLContext.new()
      @sock = OpenSSL::SSL::SSLSocket.new(@sock, context)
      @sock.connect
    end
    
    one_loop
    send_pass if @password != '' and @password.length > 0
    send_user
    nick(@nickname)
    one_loop
    end_connect
  end

  def debug?
    @debug
  end

  def debug(value)
    @debug = value
  end

  def quit(msg = 'No Message')
    @quitting = true
    send('QUIT ' + msg)
  end

  def join(channel, key = '')
    send("JOIN %s %s" % [channel, key])
  end

  def kick(channel, who, reason = 'No Reason')
    send("KICK %s %s :%s" % [channel, who, reason])
  end

  def error(sender, source, params)
    msg = params.join(' ')
    if msg.chomp! == 'Trying to reconnect too fast.' then
      sleep(10)
      inner_connect
    end
  end

  def say(who, what)
    send(":%s PRIVMSG %s :%s" % [@nickname, who, what])
  end

  def pong(sender, source, params)
    send('PONG')
  end

  def send(msg)
    start_reconnect if @sock.closed? && !@quitting
    begin
      puts 'SENDING -- ' + msg if @debug
      @sock.puts msg
    rescue Exception => ex
      puts ex.to_s if @debug
      start_reconnect if !@quitting
    end
  end
  
  def send_user
    send("USER %s . . :%s" % [@username, @realname])
    one_loop
  end

  def send_pass
    send('PASS ' + @password)
    one_loop
  end
  
  def nick(nickname)
    send('NICK ' + nickname)
    one_loop
  end

  def run
    while true and !@quitting do
      one_loop
      Thread.pass
    end
  end

  def one_loop
    start_reconnect if @sock.closed? && !@quitting
    begin
      msg = @sock.readline
      puts msg if msg if @debug
      parse_line(msg) if msg
    rescue Exception => ex
      puts 'No longer connected'
      puts ex.to_s if @debug
      start_reconnect if !@quitting
    end
  end

  def parse_line(msg)
    source = nil
    (source, msg) = msg.split(' ', 2) if msg[0,1] == ':'
    source = source[1, source.length-1] if source
    (command, msg) = msg.split(' ', 2)
    params = []
    while msg and msg[0,1] != ':'
      (middle, msg) = msg.split(' ', 2)
      params << middle
    end
    
    params << msg[1,msg.length-1]    if msg and msg[0,1] == ':'
    throw "hmmmm.  line is '#{line}'." if msg and msg[0,1] != ':'
    
    dispatch(command, source, params)
  end

  def dispatch(command, source, params)
    puts 'got command '+ command if @debug
    cmds = @commands[command]
    if cmds then
      puts 'we have a handler for it' if @debug
      cmds.each do |x|
        puts 'calling '+x if @debug
        x.call(self, source, params)
      end
    end
  end

  def add_handler(command, block)
    @commands[command] = [] if !@commands[command]
    @commands[command].push(block)
  end

  def start_reconnect
    dispatch('RECONNECT', '', [])
    inner_connect if !@quitting
  end

  def end_connect
    dispatch('CONNECTED', '', [])
  end

  def nickname
    @nickname
  end
end
