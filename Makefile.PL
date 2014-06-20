# vi:set syntax=perl:

use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Net::IdentServer',
    VERSION_FROM => 'IdentServer.pm',
    AUTHOR       => 'Paul Miller <jettero@cpan.org>',
    PREREQ_PM    => { 
        'Net::Server' => 0,
    },
);
