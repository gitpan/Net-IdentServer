
use strict;
use Test;
use Net::Telnet;

my $result;
alarm 20;

plan tests => 1;

my $t = new Net::Telnet(port=>64999);

$t->open("localhost");

# tcp        0      0 127.0.0.1:38898         127.0.0.1:64999         ESTABLISHED 4941/perl5.8.4      
my $line = `netstat -np 2>/dev/null | grep ^tcp | grep EST | grep 64999 | grep perl | tail -n 1`; chomp $line;

if( $line =~ m/\:(\d+).*?\:(\d+)/ ) {
    my ($l, $r) = ($1, $2);
    $t->print("$l, $r");
    ($result) = $t->waitfor("/UNIX :/");
    ok( $result , "$l , $r : ");
} else {
    skip( "netstat failed to run or something, skipping the test because it's probably not Net::IdentServer that failed" );
}
