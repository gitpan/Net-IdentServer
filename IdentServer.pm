# $Id: IdentServer.pm,v 1.28 2004/12/30 20:30:22 jettero Exp $

package Net::IdentServer;

use strict;
use warnings;
use POSIX;
use Carp;
use Config::IniFiles;

# This should totally be configurable... this was a completely arbitrary choice!
use base qw(Net::Server::Fork);
# /choice

our $REVISION = q($Revision: 1.28 $); $REVISION =~ s/[^\.\d]//g; $REVISION =~ s/^1\.//;
our $VERSION  = "0.21" . $REVISION;

1;

# read_config {{{
sub read_config {
    my $this = shift; 
    my $conf = shift;
    
    croak "please call new() first " . ref($this) unless ref($this);

    return $this->{conf} if defined $this->{conf};

    my %ini;

    my @configs = ("/etc/identserver.ini", "/etc/identserver/identserver.ini", "./identserver.ini");

    warn "no config files found or specified\n" unless @configs > 0;
    for my $file (@configs) {
        if( not $conf->{shhh} and $file =~ m/^\.\// ) {
            warn "WARNING: You are reading an ini file located in ./";
            sleep 1;
        }
        if( open IN, $file ) {
            if( my $cfg = new Config::IniFiles( -file => *IN ) ) {
                for my $s ($cfg->Sections) {
                    for my $p ( $cfg->Parameters($s) ) {
                        $ini{$s}{$p} = $cfg->val($s, $p);
                    }
                }
            }
            close IN;

        } elsif( -f $file ) {
            warn "config file named $file found, but could not be opened: $!\n";

        }
    }

    for my $k (keys %$conf) {
        $ini{server}{$k} = $conf->{$k};
    }

    my @must_def = qw(log_level log_file pid_file allow port);

    my $def = 1; 
       $def = ($def and defined $ini{server}{$_}) for @must_def;

    unless( $def ) {
        print STDERR "Unable to read config or did not find the minimum settings there.\n";
        print STDERR "All of the following must be defined in the server section:\n";
        print STDERR "\t$_\n" for @must_def;
        exit 1;
    }

    $this->{conf} = \%ini;

    return $this->{conf};
}
# }}}

# new {{{
sub new {
    my $class = shift;
    my $this  = bless {}, $class;
    my $conf  = { @_ };

    $this->read_config($conf);

    return $this;
}
# }}}
# run {{{
sub run {
    my $this = shift;

    local @ARGV = ();

    $0 = "identd";

    $this->SUPER::run( map(($_ => $this->{conf}{server}{$_}), keys %{ $this->{conf}{server} }) );
}
# }}}
# log {{{
sub log {
    my $this    = shift;
    my ($l, $m) = @_;

    $m =~ s/^\s+//; $m =~ s/\s+$//; $m =~ s/[\r\n]//msg;
    $m =~ s/^\d{4}\/\d{2}\/\d{2}\-\d{2}\:\d{2}\:\d{2} //;

    if( $l > 3 ) {
        $m = "[DEBUG] $m";
    }

    $m = strftime('%Y-%m-%d %H:%M:%S ', localtime) . sprintf('%7s: %s', "[$$]", $m);

    $this->SUPER::log($l, "$m\n");
}
# }}}

# print_error {{{
sub print_error {
    my $this = shift;
    my $type = lc(pop);
    my @p = @_;
       @p = (0, 0) unless @p == 2;

    my $txt;
    unless( $txt = {'u'=> "UNKNOWN-ERROR", 'h' => "HIDDEN-USER", 'n' => "NO-USER", 'i' => "INVALID-PORT"}->{$type} ) {
        die "bad type given to print_error";
    }

    $this->print_response(@p, "ERROR", $txt);
}
# }}}
# print_response {{{
sub print_response {
    my ($this, $port_on_server, $port_on_client, $res_type, $add_info) = @_;

    printf '%d , %d : %s : %s'."\r\n", $port_on_server, $port_on_client, $res_type, $add_info;
}
# }}}
# do_lookup {{{
sub do_lookup {
    my ($this, $local_addr, $local_port, $rem_addr, $rem_port) = @_;

    my $translate_addr = sub { my $a = shift; my @a = (); push @a, $1 while $a =~ m/(..)/g; join(".", map(hex($_), reverse @a)) };
    my $translate_port = sub { hex(shift) };

    my $found = -1;

    open TCP, "/proc/net/tcp" or die "couldn't open proc/net/tcp for read: $!";
    while(<TCP>) {
        # some lunix docs {{{
        # enum {
        #   TCP_ESTABLISHED = 1,
        #   TCP_SYN_SENT,
        #   TCP_SYN_RECV,
        #   TCP_FIN_WAIT1,
        #   TCP_FIN_WAIT2,
        #   TCP_TIME_WAIT,
        #   TCP_CLOSE,
        #   TCP_CLOSE_WAIT,
        #   TCP_LAST_ACK,
        #   TCP_LISTEN,
        #   TCP_CLOSING,   /* now a valid state */

        #   TCP_MAX_STATES /* Leave at the end! */
        # };

        # /proc/net/tcp
        #        Holds  a  dump  of the TCP socket table. Much of the information is not of use apart from debugging. The
        #        "sl" value is the kernel hash slot for the socket, the "local address" is the  local  address  and  port
        #        number  pair.   The  "remote address" is the remote address and port number pair (if connected). 'St' is
        #        the internal status of the socket.  The 'tx_queue' and 'rx_queue' are the  outgoing  and  incoming  data
        #        queue  in terms of kernel memory usage.  The "tr", "tm->when", and "rexmits" fields hold internal infor-
        #        mation of the kernel socket state and are only useful for debugging. The uid  field  holds  the  creator
        #        euid of the socket.

        # 9:  E621A8C0:8030 42A3E342:0016 01 00000000:00000000 02:00053467 00000000  1000        0 8070 2 d548ac00 262 40 30 2 2                             
        # }}}

        if( m/^\s+\d+:\s+([A-F0-9]{8}):([A-F0-9]{4})\s+([A-F0-9]{8}):([A-F0-9]{4})\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(\d+)/ ) {
            my ($la, $lp, $ra, $rp, $state, $uid) = ($1, $2, $3, $4, $5, $6);

            if( $state == 1 ) {
                $la = $translate_addr->($la); $lp = $translate_port->($lp);
                $ra = $translate_addr->($ra); $rp = $translate_port->($rp);

                # wow, mistake... we are NOT comparing addrs, just ports
                # if( $local_addr eq $la and $local_port eq $lp and $rem_addr eq $ra and $rem_port eq $rp ) {

                if( $local_port eq $lp and $rem_port eq $rp ) {
                    $found = $uid;
                    last;
                }
            }
        }
    }
    close TCP;

    if( $found < 0 ) {
        $this->log(2, "lookup from $rem_addr for $local_port, $rem_port: not found");
        $this->print_error($local_port, $rem_port, 'n'); # no user for when we find no sockets!
        return;
    }

    my $name = getpwuid( $found );
    unless( $name =~ m/\w/ ) {
        # This can happen if a deleted user has a socket open.  'u' might be a better choice. 
        # I happen to think hidden user is a nice choice here.  

        $this->log(2, "lookup from $rem_addr for $local_port, $rem_port: found uid, but no pwent");
        $this->print_error($local_port, $rem_port, 'h'); 
        return;
    }

    $this->log(1, "lookup from $rem_addr for $local_port, $rem_port: found $name");
    $this->print_response($local_port, $rem_port, "UNIX", $name);

    return 1;
}
# }}}

# process_request {{{
sub process_request {
    my $this = shift;

    my $master_alarm = alarm ($this->{conf}{server}{timeout}>0 ? $this->{conf}{server}{timeout} : 10);
    local $SIG{ALRM} = sub { die "\n" };
    eval {
        my $input = <STDIN>;
           $input = "" unless $input; # to deal with stupid undef warning
           $input =~ s/[\r\n]//sg;

        unless( $input =~ m/^\s*(\d+)\s*,\s*(\d+)\s*$/ ) {
            $this->log(3, "Malformated request from $this->{server}{peeraddr}");
            $this->print_error("u");
            return;
        }
        my ($s, $c) = ($1, $2);

        $this->do_lookup($this->{server}{sockaddr}, $s, $this->{server}{peeraddr}, $c);
    };
    alarm $master_alarm;

    if( $@ eq "\n" ) {
        # print "500 too slow...\n";
        # on timeout, ident just closes the connection ...

    } elsif( $@ ) {
        $this->log(3, "ERROR during eval { }: $@");

    }
}
# }}}

__END__
# Below is stub documentation for your module. You better edit it!

=head1 NAME

Net::IdentServer - An rfc 1413 Ident server which @ISA [is a] Net::Server.

=head1 SYNOPSIS

  use Net::IdentServer;

  my $nis = new Net::IdentServer;

  run $nis;  # This is a working identd ...

=head1 DESCRIPTION

  Although you can run this as you see in the SYNOPSIS, you'll
  probably want to rewrite a few things.

  Net::IdentServer is a child of Net::Server to be sure.  If you
  wish to override the behaviours of this module, just inherit it
  and start re-writing as you go.  
  
  An example random fifteen-letter-word ident server follows:

    use strict;

    my $s = new RandomIdentServer;

    run $s;

    package RandomIdentServer;

    use strict;
    use base qw(Net::IdentServer);

    1;

    sub new {
        my $class = shift;
        my $this = $class->SUPER::new( @_ );

        open IN, "/usr/share/dict/words" or die "couldn't open dictionary: $!";
        while(<IN>) {
            if( /^(\S{15})$/ ) {
                push @{ $this->{words} }, $1;
            }
        }
        close IN;

        return $this;
    }

    sub choice {
        my $this = shift;

        my $i = int rand @{ $this->{words} };

        return $this->{words}->[$i];
    }

    sub print_response {
        my $this = shift;
        my ($local, $remote, $type, $info) = @_;

        if( $type eq "UNIX" ) {
            # intercept these valid responses and randomize them

            $info = $this->choice;
        }

        # Do what we would have done
        $this->SUPER::print_response( $local, $remote, $type, $info );
    }

=head1 The do_lookup Function

    I'm including this meaty function in it's entirity, because this is 
    what you'd have to re-write to do your own do_lookup.  It should be 
    pretty clear.

    If you're really mad about his documentation, shoot me an email and 
    I WILL try to help.

    sub do_lookup {
        my ($this, $local_addr, $local_port, $rem_addr, $rem_port) = @_;

        my $translate_addr = sub { my $a = shift; my @a = (); push @a, 
            $1 while $a =~ m/(..)/g; join(".", map(hex($_), reverse @a)) };
        my $translate_port = sub { hex(shift) };

        my $found = -1;

        open TCP, "/proc/net/tcp" or die "couldn't open proc/net/tcp for read: $!";
        while(<TCP>) {

            # If you know of a better way to read /proc/net/tcp, drop me a line...
            # because this sorta sucks
            if( m/^\s+\d+:\s+([A-F0-9]{8}):([A-F0-9]{4})\s+([A-F0-9]{8}):([A-F0-9]{4})\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(\d+)/ ) {
                j
                my ($la, $lp, $ra, $rp, $state, $uid) = ($1, $2, $3, $4, $5, $6);

                if( $state == 1 ) {
                    $la = $translate_addr->($la); $lp = $translate_port->($lp);
                    $ra = $translate_addr->($ra); $rp = $translate_port->($rp);

                    # wow, mistake... we are NOT comparing addrs, just ports
                    # if( $local_addr eq $la and $local_port eq $lp and $rem_addr eq $ra and $rem_port eq $rp ) {

                    if( $local_port eq $lp and $rem_port eq $rp ) {
                        $found = $uid;
                        last;
                    }
                }
            }
        }
        close TCP;

        if( $found < 0 ) {
            $this->log(2, "lookup from $rem_addr for $local_port, $rem_port: not found");
            $this->print_error($local_port, $rem_port, 'n'); # no user for when we find no sockets!

            return;
        }

        my $name = getpwuid( $found );
        unless( $name =~ m/\w/ ) {
            # This can happen if a deleted user has a socket open.  'u' might be a better choice. 
            # I happen to think hidden user is a nice choice here.  

            $this->log(2, "lookup from $rem_addr for $local_port, $rem_port: found uid, but no pwent");
            $this->print_error($local_port, $rem_port, 'h'); 

            return;
        }

        $this->log(1, "lookup from $rem_addr for $local_port, $rem_port: found $name");
        $this->print_response($local_port, $rem_port, "UNIX", $name);

        return 1;
    }

=head1 AUTHOR

Jettero Heller <japh@voltar-confed.org>

   Jet is using this software in his own projects...  If you find
   bugs, please please please let him know. :)

   Actually, let him know if you find it handy at all.  Half the
   fun of releasing this stuff is knowing that people use it.

=head1 COPYRIGHT

    GPL!  I included a gpl.txt for your reading enjoyment.

    Though, additionally, I will say that I'll be tickled if you
    were to include this package in any commercial endeavor.
    Also, any thoughts to the effect that using this module will
    somehow make your commercial package GPL should be washed
    away.

    I hereby release you from any such silly conditions.

    This package and any modifications you make to it must remain
    GPL.  Any programs you (or your company) write shall remain
    yours (and under whatever copyright you choose) even if you
    use this package's intended and/or exported interfaces in
    them.

=head1 SPECIAL THANKS

    Holy smokes, Net::Server is the shizzo fo shizzo.  Everyone
    send a blessing to this guy, seriously.

    Paul T. Seamons <paul at seamons.com>

=head1 SEE ALSO

perl(1), Net::Server

=cut
