

use strict;
use Test;

plan tests => 2;

ok 1 if unlink "nftest.file";
ok 1 if unlink "alttest.file";
