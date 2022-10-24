#!/usr/bin/perl

# MIT License
#
# Copyright (c) 2022 The McGrail Foundation
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

use strict;
use warnings;

=head1 NAME

MIMEDefang-smtpd-filter - an OpenSMTPD filter for MIMEDefang

=head1 DESCRIPTION

MIMEDefang-smtpd-filter is an OpenSMTPD filter to integrate MIMEDefang and OpenSMTPD.

To enable the filter just add the following lines into your smtpd.conf:

    filter "mimedefang" proc-exec "filter-mimedefang.pl" user _mdefang group _mdefang
    listen on all filter "mimedefang"

The program has a "-d" parameter to enable debug mode, when debug mode is enabled, logs will
be more verbose and temporary files under /var/spool/MIMEDefang will not be removed.

=cut

use File::Path;
use Getopt::Std;
use IO::Socket::UNIX;
use Mail::MIMEDefang;
use OpenSMTPd::Filter;

# This lets us see if there are other modules we may need to preload
unshift @INC, sub { warn "Attempted to load $_[1]"; return };

my $MDSPOOL_PATH = "/var/spool/MIMEDefang/";
my $SOCK_PATH = "/var/spool/MIMEDefang/mimedefang-multiplexor.sock";

use constant HAS_UNVEIL => eval { require OpenBSD::Unveil; };

my %opts;
getopts("d", \%opts);

my $debug = 0;
if(defined $opts{d}) {
  $debug = 1;
}

if(HAS_UNVEIL) {
  OpenBSD::Unveil->import;
  unveil($MDSPOOL_PATH, "rwcx");
  unveil();
}

my $filter = OpenSMTPd::Filter->new(
    debug => $debug,
    on    => { filter => { 'smtp-in' => {
        'helo'      => \&helo_check,
        'ehlo'      => \&helo_check,
        'data-lines' => \&data_save,
        'commit' => \&data_check,
    } } }
);

$filter->ready;

sub helo_check {
    my ( $phase, $s ) = @_;

    # warn "Checking HELO as requested\n" if $debug;
    return 'proceed';
}

sub _read_headers {
  my ( $message, $lines ) = @_;
  my @lines = @{$lines};

  my $subject;
  my @headers = ();

  mkdir($MDSPOOL_PATH . "mdefang-" . $message->{'envelope-id'}) or return;
  open(my $fh, '>', $MDSPOOL_PATH . "mdefang-" . $message->{'envelope-id'} . "/HEADERS") or return;
  foreach my $ln ( @lines ) {
    last if($ln =~ /^$/);
    if($ln =~ /^Subject\:(.*)/) {
      $subject = percent_encode($1);
    }
    chomp($ln);
    push(@headers, $ln);
    print $fh "$ln\n";
  }
  close($fh);
  return ($subject, @headers);
}

sub data_save {
    my ( $phase, $s, $lines ) = @_;
    my @lines = @{$lines};

    my @headers = ();

    my $state   = $s->{state};
    my $message = $state->{message};

    my ($fh, $fi, $fc);
    my $subject;

    ($subject, @headers) = _read_headers($message, \@lines);
    if(not @headers) {
      $message->{md_status} = "temp_error";
      return;
    }

    open($fi, '>', $MDSPOOL_PATH . "mdefang-" . $message->{'envelope-id'} . "/INPUTMSG");
    delete $lines[-1];
    foreach my $ln ( @lines ) {
      print $fi "$ln\n";
    }
    close($fi);
    open($fc, '>', $MDSPOOL_PATH . "mdefang-" . $message->{'envelope-id'} . "/COMMANDS");
    my $sender = '<' . $message->{'mail-from'} . '>';
    print $fc "S$sender\n";
    my $msgid = $message->{'message-id'};
    print $fc "X$msgid\n";
    my $qid = $message->{'envelope-id'};
    print $fc "Q$qid\n";
    my $identity = $state->{'identity'};
    print $fc "H$identity\n";
    print $fc "E$identity\n";
    print $fc "U$subject\n";
    foreach my $rcpt ( (@{$message->{'rcpt-to'}})[0] ) {
      print $fc "R$rcpt ? ? ?\n";
    }
    print $fc "F\n";
    close($fc);

    my $client = IO::Socket::UNIX->new(
      Type => SOCK_STREAM(),
      Peer => $SOCK_PATH,
    );

    $client->send("scan $message->{'envelope-id'} " . $MDSPOOL_PATH . "mdefang-" . $message->{'envelope-id'} . "\n");
    $client->shutdown(SHUT_WR);

    my $buffer;
    $client->recv($buffer, 1024);
    $client->shutdown(SHUT_RD);

    $message->{md_status} = $buffer;

    my $nbody_path = $MDSPOOL_PATH . "mdefang-" . $message->{'envelope-id'} . '/NEWBODY';
    my @endlines;
    my @nlines;

    my $rh;
    my $ret;
    open(my $fr, '<', $MDSPOOL_PATH . "mdefang-" . $message->{'envelope-id'} . "/RESULTS");
    while(my $lfr = <$fr>) {
      chomp($lfr);
      if($lfr =~ /^I([a-z\-]+)\s+([0-9]+)\s+(.*)/i) {
        my $hkey = $1;
        $rh->{$hkey}{pos} = $2;
        $rh->{$hkey}{val} = $3;
        my $hln = $hkey . ": " . percent_decode($rh->{$hkey}{val});
        push(@endlines, $hln);
      }
      if($lfr =~ /^B(.*)/) {
        $ret = $1;
        $message->{md_ret} = $ret if defined $ret;
      }
    }
    close($fr);
    foreach my $nln ( @headers ) {
      my @kv = split(/:/, $nln);
      if(not exists($rh->{$kv[0]})) {
        push(@nlines, $nln);
      }
    }
    push(@nlines, @endlines);
    push(@nlines, "");
    if(-f $nbody_path) {
      open(my $fn, '<', $nbody_path);
      while(my $lnb = <$fn>) {
        chomp($lnb);
        push(@nlines, $lnb);
      }
      close($fn);
      return @nlines;
    } else {
      foreach my $ln ( @lines ) {
        if($ln =~ /^$/) {
          last;
        } else {
          shift(@lines);
        }
      }
      push(@nlines, @endlines);
      push(@nlines, @lines);
      return @nlines;
    }
}

sub data_check {
    my ( $phase, $s ) = @_;

    my $state   = $s->{state};
    my $message = $state->{message};
    my $buffer = $message->{md_status};

    my $ret;
    if($buffer =~ /ok/) {
      $ret = $message->{md_ret};
      return reject => $ret if defined $ret;
      rmtree($MDSPOOL_PATH . "mdefang-" . $message->{'envelope-id'}) if not $debug;
      return 'proceed';
    } elsif($buffer =~ /temp_error/) {
      return reject => '451 Temporary failure, please try again later.';
    }
    return disconnect => '550 System error.' if $buffer =~ /error/;
}
