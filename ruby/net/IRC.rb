require 'socket'
require 'thread'
require 'timeout'
#require 'openssl'

class IRC
  attr_reader :nickname
  attr_writer :debug
  attr :reconnect, true

  def debug?
    @debug
  end

  def initialize(nickname, username, realname, autonickchange = true, isserver = false)
    @username = username
    @realname = realname
    @nickname = nickname
    @isserver = isserver
    @commands = {} if !@commands

    @debug = false
    
    add_handler('PING', method(:pong))
    add_handler('ERROR', method(:error))
    add_handler('433', method(:nick_in_use)) if autonickchange
    add_handler('001', method(:end_connect))
  end

  def connect(server, port, password = '', bindip = nil, usessl = false)
    @server = server
    @port = port
    @password = password
    @usessl = usessl
    @quitting = false
    @bindip = bindip
    
    inner_connect
  end

  def inner_connect
    @sock = TCPSocket.new(@server, @port, @bindip)
    puts "CONNECTING TO #{@server}:#{@port} (#{@sock.peeraddr[3]}:#{@sock.peeraddr[1]} [#{@sock.peeraddr[2]}])"

    if @usessl 
      require 'openssl'
      unless defined?(OpenSSL)
        raise "ruby OpenSSL isn't installed"
      end

      if @sock.closed? and !@quitting and @reconnect
        "TCP Socket not setup, reconnecting"
        start_reconnect
      end

      begin
        context = OpenSSL::SSL::SSLContext.new()
        @sock = OpenSSL::SSL::SSLSocket.new(@sock, context)
        @sock.connect
      rescue OpenSSL::SSL::SSLError => ex
        puts "Error when connecting via SSL #{ex}"
        start_reconnect if @reconnect and !@quitting
      end
    end
    
    one_loop
    
    unless @isserver
      send_pass if @password and @password != ''
      send_user
      nick(@nickname)
    else
      send("PASS #{@password} TS 6 #{@username}")
      send("CAPAB :KLN PARA EOB QS UNKLN GLN ENCAP TBURST CHW IE EX QUIET")
      send("SERVER #{@nickname} 1 :#{@realname}")
    end
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

  def nick_in_use(sender, source, params)
    unless @nick_already_changed_once
      @nickname += 'aa'
      @nick_already_changed_once = true
    else
      @nickname.succ!
    end
    nick(@nickname)
  end

  def say(who, what)
    send(":%s PRIVMSG %s :%s" % [@nickname, who, what])
  end

  def pong(sender, source, params)
    send("PONG #{@nickname} :#{params[0]}")
  end

  def send(msg)
    dispatch('RAWSEND', nil, msg)
    start_reconnect if @sock.closed? && !@quitting
    begin
      @sock.puts msg
    rescue IOError, EOFError, Errno::ECONNRESET, SocketError => ex
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
      msg = ""
      msg = @sock.readline
      dispatch('RAWRECV', nil, msg) if msg.length > 0
      puts "#{Time.now.to_i} #{msg}" if msg.length > 0 if @debug
      parse_line(msg) if msg.length > 0
    rescue IOError, EOFError, SocketError, Errno::ECONNRESET => ex
      puts "No longer connected (exception was: #{ex})"
      puts ex.to_s if @debug
      start_reconnect if !@quitting
    rescue Timeout::Error
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
    cmds = @commands[command]
    if cmds then
      cmds.each {|x| x.call(self, source, params)}
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

  def end_connect(command, source, params)
    dispatch('CONNECTED', '', [])
  end
end
