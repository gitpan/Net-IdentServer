
use strict;
use Test;
use Net::Telnet;

my $result;
alarm 20;

plan tests => 2;

my $t = new Net::Telnet(port=>64999);

$t->open("localhost");
$t->print("supz");
($result) = $t->waitfor("/UNKNOWN-ERROR/");
ok( $result , "0 , 0 : ERROR : " );

$t->open("localhost");
$t->print("7, 7");
($result) = $t->waitfor("/NO-USER/");
ok( $result , "7 , 7 : ERROR : " );
