#!/usr/bin/perl

# $Id: 02localmessage.t,v 1.2 2001/12/14 01:45:12 piers Exp $

use lib qw(../lib ./lib);
use Test;
BEGIN { plan test => 3 }

use Net::Nsca;

ok( $Net::Nsca::VERSION ); # module loaded OK

my $filename;
if ( -d 't' ) {
	$filename = 't/_localtmp.cmd';
} else {
	$filename = './_localtmp.cmd';
}

if ( -e $filename ) {
	unlink( $filename );
}

my $message = {
	host_name => 'www',
	svc_description => 'database',
	return_code => '0',
	plugin_output => 'Database is OK',
};
Net::Nsca::local_message( $message, $filename );
open( IN, $filename ) or die("can't open cmd file for read");
my $line = <IN>;
close( IN );
unlink( $filename );
ok ( $line =~ m/^\[\d+\] PROCESS_SERVICE_CHECK_RESULT;www;database;0;Database is OK\n$/ );


$message = {
	host_name => 'www',
	svc_description => 'database',
	return_code => '-1',
	plugin_output => "what a doozy\ndatabase is down! Status failed; not sure why\n",
};
Net::Nsca::local_message( $message, $filename );
open( IN, $filename ) or die("can't open cmd file for read");
$line = <IN>;
close( IN );
unlink( $filename );
ok ( $line =~ m/^\[\d+\] PROCESS_SERVICE_CHECK_RESULT;www;database;-1;what a doozy-database is down! Status failed- not sure why-$/ );
