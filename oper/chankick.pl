# AKILL everyone who joins a channel this script is active for.
#
# usage: Load this script. Join a chan you want to have empty. Add it
# to the chankick_chanfile. Run /chankick_enforce -YESDOIT for an inital clean
# of the channel, after that everyone who joins *except* OFTC staff gets AKILLed.
#
# (C) 2006 by Joerg Jaspert <joerg@debian.org>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this script; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


use strict;
use Irssi;

use vars qw($VERSION %IRSSI @chans);


$VERSION = '0.0.0.0.1.alpha.0.0.3';
%IRSSI = (
    authors     => 'Joerg Jaspert',
    contact     => 'joerg@debian.org',
    name  => 'chankick',
    description => 'AKILLS everyone joining a channel you defined.',
    license     => 'GPL v2 (and no later)',
);


########################################################################
# First ome helper functions                                           #
########################################################################

sub create_chans {
  my $chankick_chanfile = Irssi::settings_get_str('chankick_chanfile');

  Irssi::print("Creating basic channelfile in $chankick_chanfile. please edit it and run /chankick_read");
  if (!(open NICKCHANS, ">$chankick_chanfile")) {
	Irssi::print("Unable to create file $chankick_chanfile $!");
	return;
  }

  print NICKCHANS "# This file should contain a list of all channels\n";
  print NICKCHANS "# where you want to AKILL everyone.\n";
  print NICKCHANS "#\n";
  print NICKCHANS "# Channel       IrcNet Tag     AKILL Reason\n";
  print NICKCHANS "# --------      ----------     ------------\n";

  close NICKCHANS;
  chmod 0600, $chankick_chanfile;
}

sub read_chans {
  my $count = 0;
  my $chankick_chanfile = Irssi::settings_get_str('chankick_chanfile');

  # Lets reset @chans so we can call this as a function.
  @chans = ();

  if (!(open NICKCHANS, "<$chankick_chanfile")) {
	create_chans;
  };

  # apaprently Irssi resets $/, so we set it here.
  $/ = "\n";
  while ( my $line = <NICKCHANS>) {
	if ( $line !~ /^(#|\s*$)/ ) { 
	  my ($channel, $ircnet, $reason) = 
		$line =~ /\s*(\S+)\s+(\S+)\s(.*)/;
	  push @chans, "$channel:$ircnet:$reason";
	  $count++;
	}
  }
  Irssi::print("Found $count channels");
  close NICKCHANS;
}


sub event_join {
  # Someone joins a channel, so lets see if we want to get him out of the net.
  my ($server, $channame, $nick, $host) = @_;
#  Irssi::print("Channame: $channame, nick: $nick");

  return if $server->{chat_type} ne "IRC";   # We only act on IRC nets
  return if ($nick eq $server->{nick});      # We dont kill ourself
  my $rec = $server->{tag};

  foreach $_ (@chans) {                      # Now look at all channels we are asked to work on.
	my ($channel, $ircnet, $akillreason) = split(/:/);

	if ($rec =~ /^$ircnet$/i) {              # Is this a join in the right IRCNet?
	  if ($channame =~ /^$channel$/i) {      # Does the channel match a configured one?

#		Irssi::print "Join in Channel $channame at net $rec with nick $nick and host $host";
		if ($host =~ /.*oftc.net/) {         # But do not AKILL staff from oftc.
		  Irssi::print("Not AKILLing OFTC staff");
		  next;
		}
	    # So lets get the kick done.
		$host =~ /(\S+)@(\S+)/;
		my $user = $1;
		my $khost = $2;
		Irssi::print("AKILLed $nick (ident $user) at $khost with $akillreason");
		$server->command("quote os akill add *\@$khost $akillreason");
	  }
	}
  }
}

sub enforce {
  my ($arg, $server, $channel) = @_;

  if ($arg ne "-YESDOIT") {
	my $window = Irssi::active_win();
	$window->print("You need to run /chankick_enfore -YESDOIT if you really want to AKILL everyone here!");
	return;
  }

  my $channame = $channel->{name};
  my $akillreason="";
  my $found=1;

  foreach $_ (@chans) {
	my ($chan, $ircnet, $akill) = split(/:/);
	if ($channame =~ /^$chan$/i) {
	  $akillreason=$akill;
	  $found=0;
	}
  }

  if ($found) {
	my $window = Irssi::active_win();
	$window->print("You need to enable this channel first!");
	return;
  }

  foreach my $nick ($channel->nicks()) {
	if ($nick->{host} =~ /.*oftc.net/) {         # Do not AKILL staff from oftc.
	  Irssi::print("Not AKILLing OFTC staff");
	  next;
	}
	# So lets get the kick done.
	$nick->{host} =~ /(\S+)@(\S+)/;
	my $user = $1;
	my $khost = $2;
#	Irssi::print("AKILLed $nick->{nick} (ident $user) at $khost with $akillreason");
	$server->command("quote os akill add *\@$khost $akillreason");
  }
}

sub add_chan {
  my ($arg, $server, $channel) = @_;
  my $window = Irssi::active_win();
  my $chankick_chanfile = Irssi::settings_get_str('chankick_chanfile');

  if (!$channel || $channel->{type} ne 'CHANNEL') {
	$window->print("No active channel in this window. Please join the channel you want to enable AKILL for first.");
    return;
  }

  if (length($arg) < 20) {
	$window->print("You should enter a longer reason why you want this channel to be cleaned in the future.");
	return;
  }

  my $server = $channel->{server};

  if (!(open NICKCHANS, ">>$chankick_chanfile")) {
	Irssi::print("Unable to open file $chankick_chanfile $!");
	return;
  }

  print NICKCHANS " $channel->{name}     $server->{tag}   $arg\n";
  close NICKCHANS;
  chmod 0600, $chankick_chanfile;
  $window->print("Added $channel->{name} for net $server->{tag} as an AKILL with reason \"$arg\".");
  read_chans;
}

########################################################################
# ---------- Do the startup tasks ----------

# Add the settings
Irssi::settings_add_str("chankick.pl", "chankick_chanfile", "/home/joerg/.irssi/chankick.channels");

read_chans;
Irssi::command_bind('chankick_read', 'read_chans');
Irssi::command_bind('chankick_enforce', 'enforce');
Irssi::command_bind('chankick_add', 'add_chan');

Irssi::signal_add({'message join' => \&event_join,});
