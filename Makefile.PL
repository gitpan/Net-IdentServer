# vi:set syntax=perl:

use ExtUtils::MakeMaker;

WriteMakefile(
    'NAME'	     	=> 'Net::IdentServer',
    'VERSION_FROM'	=> 'IdentServer.pm',
    'PREREQ_PM'     => { 
        'Config::IniFiles'   => 2.3,
        'Net::Server::Fork'  => 0.8,
        'Net::Telnet'        => 0,
    },
);
