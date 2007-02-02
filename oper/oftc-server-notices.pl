use Irssi;
use Irssi::Irc;

# .irssi/scripts/autorun for this, gets your servernotice in different
# colors, so you can see whats going on a bit easier.

sub sig_mynotice {
    return if $already_processed;

    $already_processed = 1;

    my ($server, $msg, $nick, $address, $target) = @_;

#    $msg =~ s/\.oftc\.net//ig;
#    $msg =~ s/\.openprojects\.net//ig;
#    $msg =~ s/Notice -- //ig;
#    $msg =~ s/\*\*\* //ig;

#    $nick =~ s/\.openprojects\.net//ig;
#    $nick =~ s/\.oftc\.net//ig;

    $colour_format = '%w'; ## Default for non-hilighted messages

    # Chat/nonautomatic stuff
    if ( $msg =~ s/^ChatOps -- from /ChatOps - /ig ) { $colour_format = '%g'; };
    if ( $msg =~ s/^Global -- from /Global - /ig ) { $colour_format = '%G'; };
    if ( $msg =~ /ChanServ invited/ ) { $colour_format = '%C'; };

    # Routing stuff
    if ( $msg =~ /Server already present from/ ) { $colour_format = '%m'; };

    if ( $msg =~ /Server .* not enabled for connecting/ ) { $colour_format = '%M'; };
    if ( $msg =~ /Connect to.*failed/ ) { $colour_format = '%M'; };
    if ( $msg =~ /connect.*from/i ) { $colour_format = '%M'; };


    if ( $msg =~ /Lost server/ ) { $colour_format = '%R'; };
    if ( $msg =~ /was connected to/ ) { $colour_format = '%R'; };
    if ( $msg =~ /exiting server/ ) { $colour_format = '%R'; };
    if ( $msg =~ /Link.*dropped/ ) { $colour_format = '%R'; };
    if ( $msg =~ /closing link/ ) { $colour_format = '%R'; };

    if ( $msg =~ /introducing.*server/ ) { $colour_format = '%G'; };
    if ( $msg =~ /Routing.*has synched to network data/ ) { $colour_format = '%G'; };
    if ( $msg =~ /Connecting to/ ) { $colour_format = '%G'; };

    if ( $msg =~ /Link with.*established/ ) { $colour_format = '%m'; };
    if ( $msg =~ /Input from.*now compressed/ ) { $colour_format = '%m'; };
    if ( $msg =~ /synch to/ ) { $colour_format = '%m'; };

    # Warning stuff
    if ( $msg =~ /User.*possible spambot/ ) { $colour_format = '%y'; };
    if ( $msg =~ /Acess check/ ) { $colour_format = '%y'; };

    if ( $msg =~ /Received unauthorized connection/ ) { $colour_format = '%Y'; };
    if ( $msg =~ /Nick collision on/ ) { $colour_format = '%Y'; };
    if ( $msg =~ /Nick .*collision on/ ) { $colour_format = '%Y'; };
    if ( $msg =~ /Flood/ ) { $colour_format = '%Y'; };

    if ( $msg =~ /SAMODE/ ) { $colour_format = '%R'; };
    if ( $msg =~ /IGNORING BAD NICK/ ) { $colour_format = '%R'; };
    if ( $msg =~ /Bad Nick: / ) { $colour_format = '%R'; };
    if ( $msg =~ /Remote nick .* on UNKNOWN server/ ) { $colour_format = '%R'; };
    if ( $msg =~ /Can't allocate fd for auth/ ) { $colour_format = '%R'; };
    if ( $msg =~ /No more connections allowed/ ) { $colour_format = '%R'; };
    if ( $msg =~ /All connections in use/ ) { $colour_format = '%R'; };
    if ( $msg =~ /Access denied/ ) { $colour_format = '%R'; };
    if ( $msg =~ /count off by/ ) { $colour_format = '%R'; };

    # Informational
    if ( $msg =~ /Activating cloak for:/ ) { $colour_format = '%c'; };
    if ( $msg =~ /Got SIGHUP/ ) { $colour_format = '%c'; };
    if ( $msg =~ /rehash/ ) { $colour_format = '%c'; };
    if ( $msg =~ /Can't open/ ) { $colour_format = '%C'; };
    if ( $msg =~ /requested by/ ) { $colour_format = '%m'; };

    if ( $msg =~ /Client connecting/ ) { $colour_format = '%b'; };
    if ( $msg =~ /Client exiting/ ) { $colour_format = '%b'; };
    if ( $msg =~ /Nick change: / ) { $colour_format = '%b'; };
    if ( $msg =~ /Channel .* created by / ) { $colour_format = '%y'; };

    if ( $msg =~ /Invalid username: / ) { $colour_format = '%b'; };

    if ( $msg =~ /kline/i ) { $colour_format = '%R'; };
    if ( $msg =~ /K-line/ ) { $colour_format = '%R'; };

    if ( $msg =~ /notable TS delta/ ) { $colour_format = '%R'; };

    #if ( $msg =~ /dynamicIP.rima-tde.net/ ) { $colour_format = '%R'; };
    if ( $msg =~ /netvision.net.il/ ) { $colour_format = '%R'; };
    #if ( $msg =~ /Client connecting: (XXXXXXXXXXXx)/ ) { $colour_format = '%Y'; };
    if ( $msg =~ /Client connecting: (Cocoademon|akioa|big_d[ll]|blah|cdsxx|csrg|fraggle_|gd3d|hd{4}lf|imcool|jcsc^|jroe|jugoar4-3|th3d|the_are|theopen|icqd2|jord|mcse|raedyy|thego|dj_big|god_od|skyr|smode|p7868|c-moi|tufx|theboyd)/ ) { $colour_format = '%Y'; };
    if ( $msg =~ /Client connecting: ([a-z][0-9][0-9]+) / ) { $colour_format = '%Y'; };
    if ( $msg =~ /Client connecting: (popeye|ragz|linuxbeak|catbooted|OPS[0-9]+) / ) { $colour_format = '%Y'; };
    if ( $msg =~ /Client connecting: .* \[[a-z][a-z]\]$/ ) { $colour_format = '%Y'; };
    if ( $msg =~ /Client connecting: .* \[=uyi\]$/ ) { $colour_format = '%Y'; };
    if ( $msg =~ /Client connecting: (Sophisticated) / ) { $colour_format = '%Y'; };
    if ( $msg =~ /Client connecting: .*81\.25\./ ) { $colour_format = '%Y'; };
    if ( $msg =~ /Client connecting: (ennn) / ) { $colour_format = '%Y'; };
    if ( $msg =~ /Client connecting: (pitufo[0-9]+) / ) { $colour_format = '%Y'; };


    if ( $msg =~ /Client exiting.*Server closed connection/ ) { $colour_format = '%y'; };

    if ( $msg =~ /X-line Rejecting \[Rob Levin 0710AAD4\] \[reserved gecos\/realname\], user somegeek\S*\[hiddenserv\@tor.noreply.org\] \[86.59.21.38\]/ ) { $colour_format = '%b'; };

    if ( $msg =~ /requested by oftc-bot-shedding.*?@82.149.72.85/ ) { $colour_format = '%b'; };

    $server->command('/^format notice_server '.$colour_format.'{servernotice $0}$1');
    #$server->command('/^format notice_server '.$colour_format.'{servernotice $[-10]0}$1');

    Irssi::signal_emit("message irc notice", $server, $msg,
               $nick, $address, $target);
    Irssi::signal_stop();
    $already_processed = 0;
}

Irssi::signal_add('message irc notice', 'sig_mynotice');

