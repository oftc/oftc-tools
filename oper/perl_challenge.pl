# Run a challenge response oper thingie
#
# (C) 2006 by Joerg Jaspert <joerg@debian.org>
# (C) 2017 by Doug Freed
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


# And you need to have an rsa keypair in your oper block. Create one with
# openssl genrsa -des3 1024 > oper-whatever.key
# openssl rsa -pubout < oper-whatever.key > oper-whatever.pub
# and send the .pub to your noc :)

# The key length shouldn't be longer than 1024 to ensure that the entire
# challenge will fit inside the limits of the ircd message (510+\r\n)

# You have one setting to change after loading this script, just type
# /set challenge to see it. Then you can use it in the future to oper by
# typing /cr YOUROPERNICK PASSWORD

use strict;
use Irssi;
use Crypt::OpenSSL::RSA;
use Convert::PEM;

use vars qw($VERSION %IRSSI);

$VERSION = '0.1';
%IRSSI = (
    authors     => 'Doug Freed, Joerg Jaspert',
    contact     => 'dwfreed!#oftc@OFTC, joerg@debian.org',
    name        => 'challenge',
    description => 'Performs challenge-response oper auth',
    license     => 'GPL v2 (and no later)',
);

my $saved_password = undef;

# *sigh*
sub decryptPEM {
  my ($file, $password) = @_;

  my $pem = Convert::PEM->new(
    Name => 'RSA PRIVATE KEY',
    ASN  => qq(
      RSAPrivateKey SEQUENCE {
        version INTEGER,
        n INTEGER,
        e INTEGER,
        d INTEGER,
        p INTEGER,
        q INTEGER,
        dp INTEGER,
        dq INTEGER,
        iqmp INTEGER
      }
    )
  );
  my $pkey = $pem->read(Filename => $file, Password => $password);

  return undef unless ($pkey); # Decrypt failed.
  $pem->encode(Content => $pkey);
}

sub make_response {
  my ($password, $challenge) = @_;
  my $key_string = decryptPEM(Irssi::settings_get_str('challenge_oper_key'), $password);
  if (defined($key_string)) {
    my $key = Crypt::OpenSSL::RSA->new_private_key($key_string);
    $key->use_pkcs1_padding();
    my $response = $key->decrypt($challenge);
    $response = unpack('H*', $response);
    Irssi::active_server()->send_raw("challenge +$response");
  } elsif (!defined($password)) {
    # TODO: make this work
    # my $pass_prompt = Irssi::active_win()->format_get_text("fe-common/irc", Irssi::active_server(), undef, "ask_oper_pass");
    # Irssi::Script::gui_entry_redirect::gui_entry_redirect(\&make_response, $pass_prompt, 2, $challenge);
    Irssi::print("Password needed", MSGLEVEL_CLIENTERROR);
  } else {
    Irssi::print("Invalid password", MSGLEVEL_CLIENTERROR);
  }
}

# Gets called from user, $arg should contain the oper name and password if needed
sub challenge_oper {
  my ($arg, $server, $window) = @_;

  if (length($arg) < 2) { # a one char oper name? not here
    Irssi::print("Please provide oper name", MSGLEVEL_CLIENTERROR);
  } else {
    my ($oper, $password) = split(/ /, $arg, 2);
    $saved_password = $password;
    $server->redirect_event('challenge', 1, "", -1, undef, { "" => "redir challenge received", });
    $server->send_raw("challenge $oper");
  }
}


# This event now actually handles the challenge, the rest was just setup
sub event_challenge_received {
  my ($server, $data) = @_;
  # Data contains "nick :challenge"
  my (undef, $challenge) = split(/:/, $data);

  $challenge = pack('H*', $challenge);
  make_response($saved_password, $challenge);
  $saved_password = undef;
}


# ---------- Do the startup tasks ----------

Irssi::command_bind('cr', 'challenge_oper');

# Add the settings
Irssi::settings_add_str("challenge", "challenge_oper_key", "$ENV{HOME}/.irssi/oper-$ENV{USER}.key");

# Ok, setup the redirect event, so we can later handle the challenge thing.
Irssi::Irc::Server::redirect_register("challenge",
                                      1, # remote
                                      5, # wait at max 5 seconds for a reply
                                      undef, # no start event
                                      {
                                       "event 386" => -1, # act on the 386, the rsa challenge
                                      },
                                      undef, # no optional event
                                     );
Irssi::signal_add('redir challenge received', 'event_challenge_received');
