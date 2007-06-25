#!/usr/bin/ruby

require 'IRC'

def uid_conv(uids, arr)
  ret = []
  arr.each do |u|
    i = u.index(/\d/)
    m = u[0, i] if i
    i = 0 unless i
    id = u[i, u.length]
    id = uids[id] if i > 0
    ret << "#{m}#{id}"
  end
  ret
end

server = ''
port = 17062
password = ''
name = ''
info = ''
tsid = ''

def raw_recv(sender, source, msg)
  puts "#{Time.now.to_i} <- #{msg}"
end

def raw_send(sender, source, msg)
  puts "#{Time.now.to_i} -> #{msg}"
end
  
conn = IRC.new(name, tsid, info, false, true)
conn.add_handler('RAWRECV', method(:raw_recv))
conn.add_handler('RAWSEND', method(:raw_send))
conn.connect(server, port, password)

file = File.open(ARGV[0])
file.readline

uidbase = 'AAAAAA'
uids = {}
eobsent = false
prevtime = 0
lastsend = Time.now

while true
  msg = file.readline
  
  curtime = msg[0, 12].strip.to_i
  prevtime = curtime if prevtime == 0
  distance = curtime - prevtime

  while distance > 0 and Time.now - lastsend <= distance do
    conn.one_loop
  end

  lastsend = Time.now
  prevtime = curtime

  msg = msg[11, msg.length-12].chomp!
  omsg = msg
  source = nil
  (source, msg) = msg.split(' ', 2) if msg[0,1] == ':'
  source = source[1, source.length-1] if source
  (command, msg) = msg.split(' ', 2)
  params = []
  while msg and msg[0,1] != ':'
    (middle, msg) = msg.split(' ', 2)
    params << middle
  end
  params << msg[1,msg.length-1] if msg and msg[0,1] == ':'
  case command
    when 'AWAY'
      #:3Y4AAAYU3 AWAY
      #:83TAAA64Z AWAY :I'm not here right now
      m = ":#{uids[source]} AWAY"
      m = "#{m} :#{params.join(' ')}" if params[0]
      conn.send(m)
    when 'BMASK'
      #:758 BMASK 1178683618 #ASF e :*!*@*
      conn.send(":#{tsid} BMASK #{params[0]} #{params[1]} #{params[2]} :#{params[3]}")
    when 'EOB'
      conn.send('EOB')
      puts "SENDING EOB"
      eobsent = true
    when 'GNOTICE'
      #:synthon.oftc.net GNOTICE synthon.oftc.net 1 :End of burst from record.oftc.net (0 seconds)
      conn.send(":#{name} GNOTICE #{name} #{params[1]} :#{params[2]}")
    when 'JOIN'
      #                0          1              2
      #:8BZAAAVV0 JOIN 1178683611 #kernelnewbies +
      conn.send(":#{uids[source]} JOIN #{params[0]} #{params[1]} #{params[2]}")
    when 'KICK'
      #:18GAAAW5C KICK #dmclub 1GLAAA2OV :mid
      s = uids[source]
      t = uids[params[1]]
      s = source unless s
      t = params[1] unless t
      conn.send(":#{s} KICK #{params[0]} #{t} :#{params[2]}")
    when 'MODE'
      #:ChanServ MODE #cherrypy +o 18GAAAXZQ
      #:4UZAAAVSI MODE 4UZAAAVSI :+w
      ischan = false
      ischan = true if params[0][0,1] == '#'
      s = uids[source]
      t = uids[params[0]] unless ischan
      s = source unless s
      t = params[0] if ischan
      m = ":#{s} MODE #{t}"
      unless ischan
        m = "#{m} :#{params[1]}"
        conn.send(m)
      else
        m = "#{m} #{params[1]}"
        id = uids[params[2]]
        id = params[2] unless id
        m = "#{m} #{id}"
        conn.send(m)
      end
    when 'NICK'
      #NICK NickServ 2 666 +Sao services services.oftc.net services.oftc.net :NickServ
      #:18GAAAXS9 NICK Vany :1182528114
      ts = false
      ts = true if omsg[0,1] == ':'
      unless ts
        ##conn.send(omsg)
      else
        conn.send(":#{uids[source]} NICK #{params[0]} :#{params[1]}")
      end
    when 'NOTICE'
      ##conn.send(omsg if false)
    when 'PART'
      #:4UZAAA7BH PART #glob2
      #:4VLAAAG35 PART #debian.de :Konversation terminated!
      m = ":#{uids[source]} PART #{params[0]}"
      params.shift
      m = "#{m} :#{params.join(' ')}" if params[0]
      conn.send(m)
    when 'QUIT'
      #:8BZAAAU76 QUIT :Quit: Leaving.
      #:8SCAAA2SR QUIT :
      s = uids[source]
      s = source unless s
      conn.send(":#{s} QUIT :#{params.join(' ')}")
    when 'REALHOST'
      conn.send(omsg)
    when 'SID' 
      #conn.send(omsg)
    when 'SJOIN'
      # 0   1     2          3                  4     5 6
      #:758 SJOIN 1182519728 #generation-debian +nt       :@8BZAAAVIH +4VLAAAG5G @3Y4AAA6SC
      #:758 SJOIN 1182519728 #generation-debian +ntl  4   :@8BZAAAVIH +4VLAAAG5G @3Y4AAA6SC
      #:758 SJOIN 1182519728 #generation-debian +ntk  k   :@8BZAAAVIH +4VLAAAG5G @3Y4AAA6SC
      #:758 SJOIN 1182519728 #generation-debian +ntlk 4 k :@8BZAAAVIH +4VLAAAG5G @3Y4AAA6SC
      o = omsg.split(':')
      p = o[1].split(' ')
      u = o[2].split(' ')
      m = ":#{tsid} SJOIN #{p[2]} #{p[3]} #{p[4]}"
      m = "#{m} #{p[5]}" if p.length > 5
      m = "#{m} #{p[6]}" if p.length > 6
      m = "#{m} :"
      u = uid_conv(uids, u)
      u.each{|x| m = "#{m}#{x} "}
      conn.send(m)
    when 'SVSCLOAK'
      #conn.send(omsg)
    when 'SVSMODE'
      #conn.send(omsg)
    when 'TMODE'
      #TODO
      #conn.send(omsg)
    when 'TOPIC'
      conn.send(omsg)
    when 'UID'
      #        0     1 2          3   4     5                        6              7         8
      #4VL UID rvdru 4 1182513539 +i ~rvdru ppp-219.net-408.magic.fr 62.210.233.219 4VLAAAGZT :rvdru
      #uid = params[7][3,params[7].length]
      uid = tsid + uidbase.succ!
      uids[params[7]] = uid
      conn.send(":#{tsid} UID #{params[0]} 1 #{params[2]} #{params[3]} #{params[4]} #{params[5]} #{params[6]} #{uid} :#{params[8]}")
    #when 'PING'  ##conn.send(omsg)
    #when 'KILL'  ##conn.send(omsg)
    #when 'KLINE' ##conn.send(omsg)
    #when 'PASS'  ##conn.send(omsg)
    #when 'CAPAB' ##conn.send(omsg)
    #when 'SERVER'##conn.send(omsg)
    #when 'SVINFO'##conn.send(omsg)
    #when 'SQUIT' ##conn.send(omsg)
  end
  #conn.one_loop
end


