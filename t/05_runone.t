
use strict;
use Test;

plan tests => 1;

my $s = new runone_server(shhh=>1, port=>64999, user=>$<, group=>$();

ok ref $s;

run $s;

package runone_server;

use strict;
use base qw(Net::IdentServer);

1;

sub alt_lookup {
    open OUT, ">alttest.file" or die "alttestfile open: $!";
    close OUT;

    return -1;
}

sub not_found {
    my $this = shift;

    open OUT, ">nftest.file" or die "nftestfile open: $!";
    close OUT;

    $this->SUPER::not_found(@_);
}

sub do_lookup {
    my $this = shift;

    $this->server_close if
    $this->SUPER::do_lookup(@_);
}
