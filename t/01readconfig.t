#!/usr/bin/perl

# $Id: 01readconfig.t,v 1.2 2001/12/13 23:57:13 piers Exp $

use lib qw(../lib ./lib);
use Test;
BEGIN { plan test => 3 }

use Net::Nsca;

ok( $Net::Nsca::VERSION ); # module loaded OK

my ($pass, $method);
if (-e 't/testconfig.cfg' ) {
	($pass, $method) = Net::Nsca::read_config( 't/testconfig.cfg' );
} else {
	($pass, $method) = Net::Nsca::read_config( 'testconfig.cfg' );
}

ok( $pass eq 'satsuma' );
ok( $method eq '1' );
