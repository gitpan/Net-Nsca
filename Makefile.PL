use ExtUtils::MakeMaker;

# $Id: Makefile.PL,v 1.1 2001/12/02 17:59:45 piers Exp $

WriteMakefile(
	AUTHOR		=> 'P Kent (pause@selsyn.co.uk)',
	ABSTRACT	=> 'Send status checks to NetSaint',
	NAME		=> 'Net::Nsca',
	DISTNAME	=> 'Net-Nsca',
	dist		=> {
		COMPRESS	=> 'gzip',
		SUFFIX		=> '.gz',
	},
	VERSION_FROM	=> 'lib/Net/Nsca.pm',
	PREREQ_PM	=> { },
	LIBS		=> [''],
	DEFINE		=> '',
	INC		=> '',
);

