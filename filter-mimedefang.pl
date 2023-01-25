#!/usr/bin/perl

# MIT License
#
# Copyright (c) 2022-2023 The McGrail Foundation
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

=head2 USAGE

The program has some parameters to modify its behavior.

-d	enable debug mode, when debug mode is enabled, logs will
	be more verbose and temporary files under /var/spool/MIMEDefang will not be removed.

-H	run helo checks by calling helo_check sub in mimedefang-filter(5)

-X	Do not add an X-Scanned-By: header.

=head2 BUGS AND LIMITATIONS

Some features that are available in MIMEDefang are not implemented.
In particular action_discard(), action_quarantine_entire_message(), add_recipient(),
delete_recipient() and change_sender() are not available.

=cut

use v5.16;	# needed by OpenSMTPd::Filter

use Carp;
use File::Path;
use Getopt::Std;
use IO::Socket::UNIX;
use Mail::MIMEDefang;
use Mail::MIMEDefang::Utils;
use OpenSMTPd::Filter;

# This lets us see if there are other modules we may need to preload
unshift @INC, sub { carp "Attempted to load $_[1]"; return };

my $MDSPOOL_PATH = '/var/spool/MIMEDefang/';
my $SOCK_PATH    = '/var/spool/MIMEDefang/mimedefang-multiplexor.sock';

use constant HAS_UNVEIL => eval { require OpenBSD::Unveil; };
use constant HAS_PLEDGE => eval { require OpenBSD::Pledge; };

my %opts;
getopts( 'dHX', \%opts );

my $debug      = 0;
my $helocheck  = 0;
my $xscannedby = 1;

our $SyslogFacility = "mail";

if ( defined $opts{d} ) {
    $debug = 1;
}
if ( defined $opts{H} ) {
    $helocheck = 1;
}
if ( defined $opts{X} ) {
    $xscannedby = 0;
}

if (HAS_UNVEIL) {
    OpenBSD::Unveil->import;
    # Needed for rmtree to work
    unveil( '/', "r" ) || croak "Unable to unveil: $!";
    unveil( $MDSPOOL_PATH, "rwcx" ) || croak "Unable to unveil: $!";
    unveil()                        || croak "Unable to lock unveil: $!";
}

if (HAS_PLEDGE) {
    OpenBSD::Pledge->import;
    pledge(qw( rpath wpath cpath prot_exec unix )) || croak "Unable to pledge: $!";
}

my $filter = OpenSMTPd::Filter->new(
    debug => $debug,
    on    => {
        report => { 'smtp-in' => {
            'link-disconnect' => \&cleanup,
        } },
        filter => {
            'smtp-in' => {
                'helo'       => \&helo_check,
                'ehlo'       => \&helo_check,
                'data-lines' => \&data_save,
                'commit'     => \&data_check,
            }
        }
    }
);

$filter->ready;

sub helo_check {
    my ( $phase, $s ) = @_;

    return 'proceed' if $helocheck ne 1;

    my $buffer;
    my $identity;
    my $errno;
    my $ret;
    my ( $socket, $sockret );
    my $src  = $s->{state}->{src};
    my $dest = $s->{state}->{dest};

    my @src_addr  = split /\:/, $src;
    my $src_port  = pop @src_addr;
    my @dest_addr = split /\:/, $dest;
    my $dest_port = pop @dest_addr;

    my $client = IO::Socket::UNIX->new(
        Type => SOCK_STREAM(),
        Peer => $SOCK_PATH,
    );
    return reject => '451 Temporary failure, please try again later.'
      if not defined $client;

    foreach my $ev ( @{ $s->{events} } ) {
        if ( defined( $ev->{phase} ) and ( $ev->{phase} eq $phase ) ) {
            $identity = $ev->{identity};
        }
    }

    md_syslog("Warning", "checking helo $identity");
    if ( $client and $client->connected() ) {
        $sockret =
          $client->send( 'helook '
              . join( ':', @src_addr ) . ' '
              . $s->{state}->{hostname} . ' '
              . $identity . ' '
              . $src_port . ''
              . join( ':', @dest_addr ) . ' '
              . $dest_port
              . "\n" );
        return reject => '451 Temporary failure, please try again later.'
          if not defined $sockret;
        $sockret = $client->shutdown(SHUT_WR);
        return reject => '451 Temporary failure, please try again later.'
          if not defined $sockret;

        $sockret = $client->recv( $buffer, 1024 );
        return reject => '451 Temporary failure, please try again later.'
          if not defined $sockret;
        $sockret = $client->shutdown(SHUT_RD);
        return reject => '451 Temporary failure, please try again later.'
          if not defined $sockret;
    }
    else {
        return reject => '451 Temporary failure, please try again later.';
    }

    if ( $buffer =~ /ok\s+([0-9-]+)\s+(.*)/ ) {
        $errno = $1;
        $ret   = $2;

        if ($errno eq -1) {
            return reject => '451 Temporary failure, please try again later.'
        }
        return reject => '550 EHLO failure, go away.' if($errno eq 0);
        return 'proceed' if $errno eq 1;
    }
    return 'proceed';
}

sub _read_headers {
    my ( $message, $lines ) = @_;
    my @lines = @{$lines};

    my $subject;
    my @headers = ();

    if(Mail::MIMEDefang::Utils->can('gen_mx_id')) {
      $message->{'md_mx_id'} = Mail::MIMEDefang::Utils::gen_mx_id();
    }
    if(defined $message->{'envelope-id'}) {
      $message->{md_spool_dir} = $MDSPOOL_PATH . 'mdefang-' . $message->{'envelope-id'};
    } elsif (defined $message->{'md_mx_id'}) {
      $message->{md_spool_dir} = $MDSPOOL_PATH . 'mdefang-' . $message->{'md_mx_id'};
    } else {
      message_cleanup($message);
      return reject => '550 System error, invalid Message-ID.'
    }
    mkdir( $message->{md_spool_dir} ) or return;
    open( my $fh, '>',
        $message->{md_spool_dir} . '/HEADERS' )
      or return;
    foreach my $ln (@lines) {
        last if ( $ln =~ /^$/ );
        if ( $ln =~ /^Subject\:(.*)/ ) {
            $subject = percent_encode($1);
        }
        chomp $ln;
        push @headers, $ln;
        print $fh "$ln\n";
    }
    close $fh;
    return ( $subject, @headers );
}

sub _get_realip {
    my $ip = shift;

    my $realip;
    if ( $ip =~ /\[/ ) {
        # ipv6
        $realip = ( split( /\]/, $ip ) )[0];
    }
    else {
        # ipv4
        $realip = ( split( /\:/, $ip ) )[0];
    }
    return $realip;
}

sub _delete_header {
    my $hkey = shift;
    my $pos = shift;
    my $lines = shift;
    my @endlines = @{ $lines };

    my $count = 1;
    my $idx = 0;
    foreach my $ln ( @endlines ) {
      if($ln eq $hkey) {
        if($pos eq $count) {
          delete $endlines[$idx];
        }
        $count++;
      }
      $idx++;
    }
    return @endlines;
}

sub data_save {
    my ( $phase, $s, $lines ) = @_;
    my @lines = @{$lines};

    my @headers = ();

    my $state   = $s->{state};
    my $message = $state->{message};

    my ( $fh, $fi, $fc );
    my $subject;
    my $sockret;

    ( $subject, @headers ) = _read_headers( $message, \@lines );
    if ( not @headers ) {
        $message->{md_status} = 'temp_error';
        return;
    }

    open( $fi, '>',
        $message->{md_spool_dir} . '/INPUTMSG' )
      or return;

    delete $lines[-1];
    foreach my $ln (@lines) {
      if ( $ln =~ /^\.(.+)$/ ) {
        print $fi "$1\n";
      } else {
        print $fi "$ln\n";
      }
    }
    close $fi;
    open( $fc, '>',
        $message->{md_spool_dir} . '/COMMANDS' )
      or return;
    my $sender = '<' . $message->{'mail-from'} . '>';
    print $fc "S$sender\n";
    print $fc "=mail_addr $sender\n";
    my $msgid = $message->{'message-id'};
    print $fc "X$msgid\n";
    my $qid = $message->{'envelope-id'};
    print $fc "Q$qid\n";
    my $identity = $state->{'identity'};
    print $fc "H$identity\n";
    print $fc "E$identity\n";
    print $fc "=mail_host $identity" . ".\n";

    if ( defined $state->{'username'} ) {
        my $username = $state->{'username'};
        print $fc "=auth_authen $username\n";
    }
    print $fc "U$subject\n" if defined $subject;

    my $realrelay = _get_realip( $state->{'src'} );
    print $fc "I$realrelay\n" if defined $realrelay;
    print $fc "i$message->{'md_mx_id'}\n" if defined $message->{'md_mx_id'};
    foreach my $rcpt ( ( @{ $message->{'rcpt-to'} } )[0] ) {
        print $fc "R$rcpt ? ? ?\n" if defined $rcpt;
    }
    print $fc "F\n";
    close $fc;

    my $client = IO::Socket::UNIX->new(
        Type => SOCK_STREAM(),
        Peer => $SOCK_PATH,
    );
    return if not defined $client;

    my $buffer;
    md_syslog("Warning", "checking message $message->{'envelope-id'}");
    if ( $client and $client->connected() ) {
        $sockret =
          $client->send( "scan $message->{'envelope-id'} "
              . $message->{'md_spool_dir'}
              . "\n" );
        return if not defined $sockret;
        $sockret = $client->shutdown(SHUT_WR);
        return if not defined $sockret;

        $sockret = $client->recv( $buffer, 1024 );
        return if not defined $sockret;
        $sockret = $client->shutdown(SHUT_RD);
        return if not defined $sockret;
        $client->close();
        $message->{md_status} = $buffer;
    }
    else {
        $message->{md_status} = 'temp_error';
        return;
    }

    my $nbody_path =
      $message->{md_spool_dir} . '/NEWBODY';
    my @endlines;
    my @nlines;

    my $rh;
    my $ret;
    my $newbody = 0;
    my $newctype;
    open( my $fr, '<',
        $message->{md_spool_dir} . '/RESULTS' )
      or return;
    while ( my $lfr = <$fr> ) {
        chomp $lfr;
        if ( $lfr =~ /^I([a-z\-]+)\s+([0-9]+)\s+(.*)/i ) {
            my $hkey = $1;
            $rh->{$hkey}{pos} = $2;
            $rh->{$hkey}{pos} //= 0;
            $rh->{$hkey}{val} = $3;
            my $hln = percent_decode($hkey) . ': ' . percent_decode( $rh->{$hkey}{val} );
            if($rh->{$hkey}{pos} > 0) {
              $rh->{$hkey}{pos}--;
            }
            splice @endlines, percent_decode($rh->{$hkey}{pos}), 0, $hln;
        }
        if ( $lfr =~ /^N([a-z\-]+)\s+([0-9]+)\s+(.*)/i ) {
            my $hkey = $1;
            $rh->{$hkey}{pos} = $2;
            $rh->{$hkey}{pos} //= 0;
            $rh->{$hkey}{val} = $3;
            my $hln = percent_decode($hkey) . ': ' . percent_decode( $rh->{$hkey}{val} );
            if($rh->{$hkey}{pos} > 0) {
              $rh->{$hkey}{pos}--;
            }
            splice @endlines, percent_decode($rh->{$hkey}{pos}), 0, $hln;
        }
        if ( $lfr =~ /^J([a-z\-]+)\s+([0-9]+)/i ) {
            my $hkey = $1;
            $rh->{$hkey}{pos} = $2;
            $rh->{$hkey}{pos} //= 0;
            @endlines = _delete_header($hkey, $rh->{$hkey}{pos}, \@endlines);
        }
        if ( $lfr =~ /^(?:B|T)(.*)/ ) {
            $ret = $1;
            if(defined $ret) {
              $message->{md_ret} = $ret;
            }
        }
        if ( $lfr =~ /^C/ ) {
           $newbody = 1;
        }
        if ( $lfr =~ /^D/ ) {
          # XXX discard command is not supported by smtpd-filters(7)
          md_syslog("Warning", "Discard command unsupported, email processing will continue");
        }
        if ( $lfr =~ /^M(.*)/ ) {
           $newctype = $1;
           push @endlines, "Content-Type: " . percent_decode($newctype);
        }
        if ( $lfr =~ /^Q/ ) {
          # XXX quarantine command is not supported by smtpd-filters(7)
          md_syslog("Warning", "Quarantine command unsupported, email processing will continue");
        }
        if ( $lfr =~ /^R(.*)/ ) {
          # XXX Add a new recipient to the message
          md_syslog("Warning", "Adding a new recipient is not supported, email processing will continue");
        }
        if ( $lfr =~ /^S(.*)/ ) {
          # XXX Delete recip from the list of message recipients
          md_syslog("Warning", "Deleting a new recipient is not supported, email processing will continue");
        }
        if ( $lfr =~ /^f(.*)/ ) {
          # XXX Change the envelope sender to sender
          md_syslog("Warning", "Changing the envelope sender is not supported, email processing will continue");
        }
    }
    close $fr;

    my $mimeadded = 0;
    my $ctypeadded = 0;
    foreach my $nln (@headers) {
        my @kv = split( /:/, $nln );
        if($newctype and not $mimeadded) {
          if($nln =~ /^MIME\-Version/) {
            $mimeadded = 1;
          }
          if($nln =~ /^Content\-Type/) {
            $ctypeadded = 1;
            next;
          }
        }
        if ( not exists( $rh->{ $kv[0] } ) ) {
            push @nlines, $nln;
        }
    }
    if($newctype and not $mimeadded) {
      push @nlines, "MIME-Version: 1.0";
      $mimeadded = 1;
    }
    unshift @nlines, @endlines;
    if ($xscannedby) {
        my $dest = _get_realip( $state->{'dest'} );
        push @nlines,
                'X-Scanned-By: MIMEDefang '
              . $Mail::MIMEDefang::VERSION
              . " on $dest";
    }
    if ( $newbody and -f $nbody_path ) {
        push @nlines, '';
        open( my $fn, '<', $nbody_path );
        while ( my $lnb = <$fn> ) {
            chomp $lnb;
            push @nlines, $lnb;
        }
        close $fn;
        return @nlines;
    }
    else {
        my @body;
        my $found = 0;
        foreach my $ln (@lines) {
            if ( $ln eq '' ) {
                $found = 1;
            }
            if ($found) {
                push @body, $ln;
            }
        }
        push @nlines, @body;
        return @nlines;
    }
}

sub data_check {
    my ( $phase, $s ) = @_;

    my $state   = $s->{state};
    my $message = $state->{message};
    my $buffer  = $message->{md_status};

    if(not defined $buffer) {
      message_cleanup($message);
      return reject => '451 Temporary failure, please try again later.'
    }
    my $ret;
    if ( $buffer =~ /ok/ ) {
        $ret = $message->{md_ret};
        if(defined $ret) {
          message_cleanup($message);
          return reject => $ret if defined $ret;
	}
        message_cleanup($message);
        return 'proceed';
    }
    elsif ( $buffer =~ /temp_error/ ) {
        message_cleanup($message);
        return reject => '451 Temporary failure, please try again later.';
    }
    message_cleanup($message);
    return disconnect => '550 System error.' if $buffer =~ /error/;
}

sub cleanup {
    my ( $phase, $s ) = @_;

    my $state   = $s->{state};
    my $message = $state->{message};

    if(not $debug) {
      rmtree( $message->{md_spool_dir} ) if defined $message->{md_spool_dir};
    }
}

sub message_cleanup {
    my $message = shift;

    if(not $debug) {
      rmtree( $message->{md_spool_dir} ) if defined $message->{md_spool_dir};
    }
}
