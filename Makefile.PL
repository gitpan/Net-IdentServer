# vi:set syntax=perl:

use ExtUtils::MakeMaker;

die "this module relies heavily on /proc/net/tcp (probably loonix only)\n"
    unless -r "/proc/net/tcp";

WriteMakefile(
    NAME         => 'Net::IdentServer',
    VERSION_FROM => 'IdentServer.pm',
    AUTHOR       => 'Paul Miller <jettero@cpan.org>',
    PREREQ_PM    => { 
        'Net::Server' => 0,
    },
);
