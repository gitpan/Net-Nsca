#!/usr/local/bin/perl
# -w
use strict;
use lib qw(./lib ../lib);
use Getopt::Std;
use Net::Nsca;

=pod

=head1 NAME

send_ncsa - a perl implementation of netsaint's send_nsca utility

=head1 DESCRIPTION

This simple utility sends a message over a TCP/IP connection to the Netsaint main server.
It's basically a command line wrapper for Nsca.pm

=head1 SYNOPSIS

	Usage: send_nsca.pl [-p port] [-t to_sec] [-d delim] [-c config_file] [-l] [-x] <host_address> 

	Options:
	 <host_address> = The IP address or name of the host running the NSCA daemon
	 [port]         = The port on which the daemon is running - default is 5667
	 [to_sec]       = Number of seconds before connection attempt times out.
	                  (default timeout is 10 seconds)
	 [delim]        = Delimiter to use when parsing input (defaults to a tab)
	 [config_file]  = Name of config file to use
	 -l             = Use the local_message method to inform a NetSaint on the local
	                  machine (default is to go over the network)
	 -x             = Display internal tracing messages fro debugging
	Then supply one line on standard input, of the format:
	<host_name>[tab]<svc_description>[tab]<return_code>[tab]<plugin_output>[newline]

=head1 COPYRIGHT ETC

This software is a reimplementation of send_nsca by Ethan Galdstd.
Relevant excerpts from the source appear here:

	 *
	 * SEND_NSCA.C - NSCA Client
	 * License: GPL
	 * Copyright (c) 2000-2001 Ethan Galstad (netsaint@netsaint.org)
	 *
	 * Last Modified: 11-19-2001
	 *
	 * Command line: SEND_NSCA <host_address> [-p port] [-to to_sec] [-c config_file]
	 *********************************************************************************/
	/************************************************************************
	 * COMMON.H - NSCA Common Include File
	 * Copyright (c) 1999-2001 Ethan Galstad (netsaint@netsaint.org)
	 * Last Modified: 11-19-2001
	 * License:
	 * This program is free software; you can redistribute it and/or modify
	 * it under the terms of the GNU General Public License as published by
	 * the Free Software Foundation; either version 2 of the License, or
	 * (at your option) any later version.
	 *
	 * This program is distributed in the hope that it will be useful,
	 * but WITHOUT ANY WARRANTY; without even the implied warranty of
	 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	 * GNU General Public License for more details.
	 *
	 * You should have received a copy of the GNU General Public License
	 * along with this program; if not, write to the Free Software
	 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
	 ************************************************************************/

=head1 PERL VERSION

P Kent, Started Nov 2001 $Id: send_nsca.pl,v 1.2 2001/12/14 01:25:15 piers Exp $

=cut

use constant PROGRAM_VERSION => Net::Nsca::PROGRAM_VERSION;
use constant MODIFICATION_DATE => Net::Nsca::MODIFICATION_DATE;

use vars qw/$opt_p $opt_t $opt_d $opt_c $opt_l $opt_x $remote_host $remote_port $delim $configfile/;

################################# Compile-time options done. Begin main

$| = 1;
*Net::Nsca::TRACE = \&TRACE;
getopts('p:t:d:c:lx');

alarm($opt_t or Net::Nsca::DEFAULT_SOCKET_TIMEOUT);

$remote_host = shift || $opt_l || usage();
$remote_port = $opt_p || Net::Nsca::DEFAULT_SERVER_PORT;
$delim = $opt_d || "\t";
$configfile = $opt_c || '/usr/local/netsaint/etc/send_nsca.cfg';

my ($password, $encryption_method) = Net::Nsca::read_config($configfile);

umask(0000);
if ( $opt_l ) {
	Net::Nsca::local_message(get_message_from_stdin($delim));
} else {
	Net::Nsca::send_message(get_message_from_stdin($delim), $remote_host, $configfile, $remote_port);
}

alarm(0);
TRACE("all done");

################################# Subroutines ####################

# parse a line on stdin like <host_name>[tab]<svc_description>[tab]<return_code>[tab]<plugin_output>[newline] 
sub get_message_from_stdin {
	my $delim = shift;
	TRACE("get_message");
	my $in = <STDIN>;
	chomp $in;
	my @field = split(/$delim/, $in);

	my $message = {
		host_name => ($field[0] or usage()),
		svc_description => ($field[1] or 'No Description'),
		return_code => (($field[2] ne '')? $field[2] : Net::Nsca::STATE_UNKNOWN),
		plugin_output => ($field[3] or 'No Message'),
	};
	
	return $message;
}

# URL-encode data - borrowed from CGI.pm
sub escape {
    my($toencode) = @_;
    $toencode=~s/([^a-zA-Z0-9_\-.])/uc sprintf(" %%%02x",ord($1))/eg;
    return $toencode;
}

sub usage {
		printf("NSCA Client %s\n",PROGRAM_VERSION);
		printf("Copyright (c) 2000-2001 Ethan Galstad (netsaint\@netsaint.org)\n");
		printf("Perl Implementation Dec 2001 P Kent (pause\@selsyn.co.uk)\n");
		printf("Last Modified: %s\n",MODIFICATION_DATE);
		printf("License: GPL\n");
		printf("Encryption Routines: ");
		printf("NOT AVAILABLE");
		printf("\n");
		printf("\n");
		printf("Usage: %s [-p port] [-t to_sec] [-d delim] [-c config_file] [-x] [-l] <host_address>\n",$0);
		printf("\n");
		printf("Options:\n");
		printf(" <host_address> = The IP address of the host running the NSCA daemon\n");
		printf(" [port]         = The port on which the daemon is running - default is %d\n",Net::Nsca::DEFAULT_SERVER_PORT);
		printf(" [to_sec]       = Number of seconds before connection attempt times out.\n");
		printf("                  (default timeout is %d seconds)\n",Net::Nsca::DEFAULT_SOCKET_TIMEOUT);
		printf(" [delim]        = Delimiter to use when parsing input (defaults to a tab)\n");
		printf(" [config_file]  = Name of config file to use\n");
		printf(" -l             = Write to the local copy of NetSaint, not over the network\n");
		printf(" -x             = Prints out internal trace messages\n");
		printf("\n");
		printf("Note:\n");
		printf("This utility is used to send passive service check results to the NSCA daemon.\n");
		printf("Servce check data that is to be sent to the NSCA daemon is read from standard\n");
		printf("input. Service check information is in the following format (tab-delimited\n");
		printf("unless overriden with -d command line argument, one entry per line):\n");
		printf("\n");
		printf("<host_name>[tab]<svc_description>[tab]<return_code>[tab]<plugin_output>[newline]\n");
		printf("\n");
		exit;
}

sub TRACE {
	return unless $opt_x;
	my $msg = shift;
	print 'TRACE> ', $msg, "\n";
}