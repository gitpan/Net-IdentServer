# $Id: IdentServer.pm,v 1.42 2005/05/07 18:05:13 jettero Exp $

package Net::IdentServer;

use strict;
use warnings;
use POSIX;
use Carp;
use Config::IniFiles;

# This should totally be configurable... this was a completely arbitrary choice!
use base qw(Net::Server::Fork);
# /choice

our $REVISION = q($Revision: 1.42 $); $REVISION =~ s/[^\.\d]//g; $REVISION =~ s/^1\.//;
our $VERSION  = "0.56";

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
    my ($this, $port_on_server, $port_on_client, $os_name, $add_info) = @_;

    $os_name = "USERID : $os_name" unless $os_name eq "ERROR";

    printf '%d , %d : %s : %s'."\r\n", $port_on_server, $port_on_client, $os_name, $add_info;
}
# }}}
# do_lookup {{{
sub do_lookup {
    my $this = shift;
    my ($local_addr, $local_port, $rem_addr, $rem_port) = @_;

    my $translate_addr = sub { my $a = shift; my @a = (); push @a, $1 while $a =~ m/(..)/g; join(".", map(hex($_), reverse @a)) };
    my $translate_port = sub { hex(shift) };

    my $found = $this->alt_lookup(@_);

    if( $found =~ m/^JP:(.+)/ ) {
        my $name = $1;

        $this->log(1, "lookup from $rem_addr for $local_port, $rem_port: alt string found $name");
        $this->print_response($local_port, $rem_port, "UNIX", $name);

        return;
    }

    if( $found < 0 ) {
        open TCP, "/proc/net/tcp" or die "couldn't open proc/net/tcp for read: $!";
        while(<TCP>) {
            if( m/^\s+\d+:\s+([A-F0-9]{8}):([A-F0-9]{4})\s+([A-F0-9]{8}):([A-F0-9]{4})\s+(\d+)\s+\S+\s+\S+\s+\S+\s+(\d+)/ ) {
                my ($la, $lp, $ra, $rp, $state, $uid) = ($1, $2, $3, $4, $5, $6);

                if( $state == 1 ) {
                    $la = $translate_addr->($la); $lp = $translate_port->($lp);
                    $ra = $translate_addr->($ra); $rp = $translate_port->($rp);

                    if( $local_port eq $lp and $rem_port eq $rp ) {
                        $found = $uid;
                        last;
                    }
                }
            }
        }
        close TCP;
    }

    if( $found < 0 ) {
        $this->not_found(@_);

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
# not_found {{{
sub not_found {
    my $this = shift;
    my ($local_addr, $local_port, $rem_addr, $rem_port) = @_;

    $this->log(2, "lookup from $rem_addr for $local_port, $rem_port: not found");
    $this->print_error($local_port, $rem_port, 'n'); # no user for when we find no sockets!
}
# }}}
# alt_lookup {{{
sub alt_lookup {
    return -1;
}
# }}}

# process_request {{{
sub process_request {
    my $this = shift;

    my $master_alarm = alarm ($this->{conf}{server}{timeout}>0 ? $this->{conf}{server}{timeout} : 10);
    local $SIG{ALRM} = sub { die "\n" };
    eval {
        while( my $input = <STDIN> ) {
           $input = "" unless $input; # to deal with stupid undef warning
           $input =~ s/[\r\n]//sg;

            unless( $input =~ m/^\s*(\d+)\s*,\s*(\d+)\s*$/ ) {
                $this->log(3, "Malformated request from $this->{server}{peeraddr}");
                $this->print_error("u");
                return;
            }
            my ($s, $c) = ($1, $2);

            $this->do_lookup($this->{server}{sockaddr}, $s, $this->{server}{peeraddr}, $c);
        }
    };
    alarm $master_alarm;

    if( $@ eq "\n" ) {
        # print "500 too slow...\n";
        # on timeout, ident just closes the connection ...

    } elsif( $@ ) {
        $this->log(3, "ERROR during main while() { do_lookup() } eval: $@");

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

Net::IdentServer is a child of Net::Server to be sure.  If
you wish to override the behaviours of this module, just
inherit it and start re-writing as you go.  

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

=head1 Overridable Functions

=head2 print_response

See the DESCRIPTION for an actual example.  This is the function that
prints the reponse to the client.  As arguments, it receives $local port,
$remote port, result $os_name (in caps) and the extended $info (usually a
username or error).

=head2 alt_lookup

There exists a function that receives $local_addr,
$local_port, $rem_addr, and $rem_port as arguments.
Confusingly, the $local_addr and $rem_addr refer to the
present socket connection, and the $local_port and $rem_port
refer to the ports being queried.

You can do whatever lookups you like on this data and return
a $uid.  If you return a negative $uid, do_lookup will
perform the standard lookup.

The default alt_lookup just returns a -1.

Lastly, if you return a string that matches m/^JP:(.+)/,
then $1 will be printed as the username.

Example:

    sub alt_lookup() {
        my $this = shift;

        # You could use this _instead_ of the
        # print_response() in the DESCRIPTION section.  The
        # advantage of the print_response is that it only
        # returns a "username" when the queried connection
        # actually exists.

        return "JP: " . $this->choice;
    }

=head2 not_found

not_found receives as arguments [see alt_lookup for
description]: $local_addr, $local_port, $rem_addr, $rem_port

by default it logs a level 2 not found message and then
prints the NO-USER error message

[for more info on the log() see the Net::Server docs]

The idea here is that you can do an additional lookup of the
standard TCP lookup fails.  For instance, you could do a lookup 
on a NAT'd machine in the local net.

=head1 print_error

There are only a couple choices of error messages in rfc1413

    $this->print_error($local_port, $rem_port, 'u'); # UNKNOWN-ERROR
    $this->print_error($local_port, $rem_port, 'h'); # HIDDEN-USER
    $this->print_error($local_port, $rem_port, 'n'); # NO-USER
    $this->print_error($local_port, $rem_port, 'i'); # INVALID-PORT

You could, of course, write your own by overriding this
function entirely.  But otherwise picking something besides
the four examples shown will earn you an error and an
exit(1).

=head1 $this->{conf}

The entire ini file is stored in your server object.  Each section is 
it's own hash key and each value is a key of the section.

Example:  $this->{conf}{server}{port} 

This is the port listed under the server section of your ini file.

=head1 AUTHOR

Jettero Heller <japh@voltar-confed.org>

Jet is using this software in his own projects...  If you find
bugs, please please please let him know. :) Actually, let him
know if you find it handy at all.  Half the fun of releasing this
stuff is knowing that people use it.

Additionally, he is aware that the documentation sucks.  Should
you email him for help, he will most likely try to give it.

=head1 COPYRIGHT

GPL!  I included a gpl.txt for your reading enjoyment.

Though, additionally, I will say that I'll be tickled if you
were to include this package in any commercial endeavor.
Also, any thoughts to the effect that using this module will
somehow make your commercial package GPL should be washed
away.

I hereby release you from any such silly conditions.

This package and any modifications you make to it must
remain GPL.  Any programs you (or your company) write shall
remain yours (and under whatever copyright you choose) even
if you use this package's intended and/or exported
interfaces in them.

=head1 SPECIAL THANKS

Holy smokes, Net::Server is the shizzo fo shizzo.  Everyone
send a blessing to this guy, seriously.

Paul T. Seamons <paul at seamons.com>

=head1 SEE ALSO

perl(1), Net::Server

=cut
