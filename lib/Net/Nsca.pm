package Net::Nsca;

use IO::Socket;

use constant PROGRAM_VERSION => "1.2.0b4-Perl";
use constant MODIFICATION_DATE => "11-22-2001";

use constant OK	=> 0;
use constant ERROR => -1;

use constant TRUE => 1;
use constant FALSE => 0;

use constant STATE_CRITICAL => 	2	; # /* service state return codes */
use constant STATE_WARNING => 	1	;
use constant STATE_OK =>       	0	;
use constant STATE_UNKNOWN =>  	-1	;

use constant DEFAULT_SOCKET_TIMEOUT	=> 10	; # /* timeout after 10 seconds */
use constant DEFAULT_SERVER_PORT =>	5667	; # /* default port to use */

use constant MAX_INPUT_BUFFER =>	2048	; # /* max size of most buffers we use */
use constant MAX_HOST_ADDRESS_LENGTH =>	256	; # /* max size of a host address */
use constant MAX_HOSTNAME_LENGTH =>	64	;
use constant MAX_DESCRIPTION_LENGTH =>	128;
use constant MAX_PLUGINOUTPUT_LENGTH =>	512;
use constant MAX_PASSWORD_LENGTH =>     512;

use constant ENCRYPT_NONE =>            0       ; # /* no encryption */
use constant ENCRYPT_XOR =>             1       ; # /* not really encrypted, just obfuscated */
use constant ENCRYPT_DES =>             2       ; # /* DES */
use constant ENCRYPT_3DES =>            3       ; # /* 3DES or Triple DES */
use constant ENCRYPT_CAST128 =>         4       ; # /* CAST-128 */
use constant ENCRYPT_CAST256 =>         5       ; # /* CAST-256 */
use constant ENCRYPT_XTEA =>            6       ; # /* xTEA */
use constant ENCRYPT_3WAY =>            7       ; # /* 3-WAY */
use constant ENCRYPT_BLOWFISH =>        8       ; # /* SKIPJACK */
use constant ENCRYPT_TWOFISH =>         9       ; # /* TWOFISH */
use constant ENCRYPT_LOKI97 =>          10      ; # /* LOKI97 */
use constant ENCRYPT_RC2 =>             11      ; # /* RC2 */
use constant ENCRYPT_ARCFOUR =>         12      ; # /* RC4 */
use constant ENCRYPT_RC6 =>             13      ; # /* RC6 */            ; # /* UNUSED */
use constant ENCRYPT_RIJNDAEL128 =>     14      ; # /* RIJNDAEL-128 */
use constant ENCRYPT_RIJNDAEL192 =>     15      ; # /* RIJNDAEL-192 */
use constant ENCRYPT_RIJNDAEL256 =>     16      ; # /* RIJNDAEL-256 */
use constant ENCRYPT_MARS =>            17      ; # /* MARS */           ; # /* UNUSED */
use constant ENCRYPT_PANAMA =>          18      ; # /* PANAMA */         ; # /* UNUSED */
use constant ENCRYPT_WAKE =>            19      ; # /* WAKE */
use constant ENCRYPT_SERPENT =>         20      ; # /* SERPENT */
use constant ENCRYPT_IDEA =>            21      ; # /* IDEA */           ; # /* UNUSED */
use constant ENCRYPT_ENIGMA =>          22      ; # /* ENIGMA (Unix crypt) */
use constant ENCRYPT_GOST =>            23      ; # /* GOST */
use constant ENCRYPT_SAFER64 =>         24      ; # /* SAFER-sk64 */
use constant ENCRYPT_SAFER128 =>        25      ; # /* SAFER-sk128 */
use constant ENCRYPT_SAFERPLUS =>       26      ; # /* SAFER+ */

use constant TRANSMITTED_IV_SIZE =>     128     ; # /* size of IV to transmit - must be as big as largest IV needed for any crypto algorithm */

use constant NSCA_PACKET_VERSION_2 =>	2		; # /* packet version identifier */
use constant NSCA_PACKET_VERSION_1 =>	1		; # /* older packet version identifier */

=pod

=head1 NAME

Net::Nsca - a perl way to send status checks to NetSaint, locally and remotely

=head1 SYNOPSIS

	Net::Nsca::local_message($message [, $log_file]);
	Net::Nsca::send_message($message, $remote_host [, $config_file [, $remote_port ]]);
	($password, $encryption_method) = Net::Nsca::read_config( [ $configfile ]);

=head1 DESCRIPTION

This module provides a simple API to allow perl programs to send checks to the
Netsaint server that is monitoring them. This server may be local or remote.
The API has two main methods and one utility method:

=over 4

=item Net::Nsca::local_message($message [, $log_file]);

Pass in a hashref with the message fields in it - the keys are host_name, 
svc_description, return_code, plugin_output -
and optionally the name of the file to append the status check message 
to (the default is /usr/local/netsaint/rw/netsaint.cmd if you don't supply one)
- Dies if anything goes wrong.

=item Net::Nsca::send_message($message, $remote_host [, $config_file [, $remote_port ]]);

Pass in a hashref with the message fields in it - the keys are host_name, 
svc_description, return_code, plugin_output -
the name or address of the Netsaint host, the port number (defaults to 5667), 
and the config file to be read - defaults to /usr/local/netsaint/etc/send_nsca.cfg
- Dies if there's a problem.

=item ($password, $encryption_method) = Net::Nsca::read_config( [ $configfile ]);

You probably won't need to use this, but it's available anyway.
Reads in a config file, default is /usr/local/netsaint/etc/send_nsca.cfg, and returns the password and encryption method. 
Dies if it can't find them.

=back

=head1 MESSAGE OBJECT

The $message referred to loks like this, a simple hashref:

	my $message = {
		host_name => 'www',
		svc_description => 'database',
		return_code => '0',
		plugin_output => 'Database is OK',
	};

=head1 COPYRIGHT

See the LICENSE file. Parts are based on work by Ethan Galstad, the rest is mine.

=head1 PERL IMPLEMENTATION

P Kent, Started Nov 2001 $Id: Nsca.pm,v 1.6 2001/12/14 01:42:11 piers Exp $

=cut

#These constants are defined here, and not in the C
use constant SIZEOF_INIT_PACKET => 132;
use constant SIZEOF_DATA_PACKET => 720; # don't understand why it isn't 716, alignment??

use vars qw($VERSION $AUTHOR $DEFAULT_CONFIG_FILE $DEFAULT_LOG_FILE);

($VERSION) = ('$Revision: 1.6 $' =~ m/([\d\.]+)/);
$AUTHOR = 'P Kent';
$DEFAULT_CONFIG_FILE = '/usr/local/netsaint/etc/send_nsca.cfg';
$DEFAULT_LOG_FILE = '/usr/local/netsaint/var/rw/netsaint.cmd';

### PUBLIC SUBROUTINES ##################################################

# get the two bits of information we need from the config file
sub read_config {
	my $file = shift() || $DEFAULT_CONFIG_FILE;
	TRACE("read_config for $file");
	my ($password, $encryption_method);
	
	local *FILE;
	open(FILE, $file) or die("Net::Nsca - Can't open nsca config file $file for read: $!");

	my $need_pwd = 1;
	my $need_crypt = 1;
	while (<FILE>) {
		chomp;
		if (/password=(\S+)/ && $need_pwd) {
			$password = $1;
			$need_pwd = 0;
		}
		if (/encryption_method=(\S+)/ && $need_crypt) {
			$encryption_method = $1;
			$need_crypt = 0;
		}
		last unless($need_pwd || $need_crypt);
	}
	close FILE;
	
	if ($need_pwd || $need_crypt) {
		die("Net::Nsca - Can't get enough info - need_pwd $need_pwd need_crypt $need_crypt");
	}
	return ($password, $encryption_method);
}

#Send a message to a local instance of netsaint
#[<timestamp>] PROCESS_SERVICE_CHECK_RESULT;<host_name>;<description>;<return_code>;<plugin_output> 
sub local_message {
	my $message_hash = shift;
	my $log_file = shift || $DEFAULT_LOG_FILE;
	
	my @fields = qw/host_name svc_description return_code plugin_output/;

	# truncate the message, filter bad characters
	_correct_message($message_hash);
	foreach my $field (@fields) {
		$message_hash->{$field} =~ s/;/-/g;
		$message_hash->{$field} =~ s/\r/-/g;
		$message_hash->{$field} =~ s/\n/-/g;
	}
	
	# build the status check line to go in the log file
	my $string = '[' . time() . '] PROCESS_SERVICE_CHECK_RESULT;'
	. $message_hash->{'host_name'} . ';'
	. $message_hash->{'svc_description'} . ';'
	. int( $message_hash->{'return_code'} ) . ';'
	. $message_hash->{'plugin_output'} ;
	
	TRACE("Writing <$string> to $log_file");
	
	local *LOG;
	open(LOG, "> $log_file") or die("Net::Nsca - Can't open external command file: $!");
	print LOG $string, "\n";
	close LOG;
	
	TRACE("OK");
}

# Send a messgae to a remote instance of netsaint, via a remote nsca daemon.
sub send_message {
	my ($message, $remote_host, $config_file) = @_;
	my $remote_port = $_[3] || DEFAULT_SERVER_PORT;
	
	my ($password, $encryption_method) = read_config( $config_file );
	
	# truncate bits of the message if needed...
	_correct_message($message);

	# connect to the nsca server, which will almost certainly be the machine on which netsaint is running
	TRACE("Trying to make socket to host <$remote_host> port <$remote_port>");
	my $socket = IO::Socket::INET->new(
		PeerAddr => $remote_host,
		PeerPort => $remote_port,
		Proto => 'tcp',
		Timeout => DEFAULT_SOCKET_TIMEOUT,
	) or die("Net::Nsca - Can't make socket: $!");

	# get init packet that contains the session salt value
	my $init_packet_buf;
	$socket->sysread($init_packet_buf, SIZEOF_INIT_PACKET);

	TRACE("Init packet is " . length($init_packet_buf) . " bytes long");
	die("Net::Nsca - Bad Packet length/Short read") unless (length($init_packet_buf) == SIZEOF_INIT_PACKET);

	my $init_packet = {
		iv => substr($init_packet_buf, 0, TRANSMITTED_IV_SIZE),
		timestamp => substr($init_packet_buf, TRANSMITTED_IV_SIZE, 4),
	};

	# this is here for debugging really, the value should be the number of seconds since the epoch.
	$init_packet->{timestamp_perlish} = unpack('N', $init_packet->{timestamp});

	#TRACE("Init Packet IV Follows:\n" . _escape( $init_packet->{iv} ));
	#TRACE("Init Packet time Follows:\n" . _escape( $init_packet->{timestamp} ));
	#TRACE("Unpacked version is $init_packet->{timestamp_perlish}");

	# assemble our data
	# in two halves
	my $data_packet_string_a = pack('n', NSCA_PACKET_VERSION_2) . "\000\000";

	my $data_packet_string_b = 
		  $init_packet->{'timestamp'}
		. pack('n', $message->{'return_code'})
		. pack(('a'.MAX_HOSTNAME_LENGTH), $message->{'host_name'})
		. pack(('a'.MAX_DESCRIPTION_LENGTH), $message->{'svc_description'})
		. pack(('a'.MAX_PLUGINOUTPUT_LENGTH), $message->{'plugin_output'})
		. "\000\000"
	;

	# now we compute the CRC of the whole string, with NULs in place of the 32 bit CRC
	my $crc = _calculate_crc32( $data_packet_string_a . "\000\000\000\000" . $data_packet_string_b);

	# insert CRC into data string
	my $data_packet_string = ( $data_packet_string_a . pack('N', $crc) . $data_packet_string_b);

	# encrypt data
	my $data_packet_string_crypt = _encrypt($data_packet_string, $encryption_method, $init_packet->{'iv'}, $password);

	# send data
	# TRACE("Packet is " . length( $data_packet_string_crypt ) . " bytes long");
	die("Net::Nsca - Bad packet created, wrong length") unless ( length( $data_packet_string_crypt ) == SIZEOF_DATA_PACKET );
	# TRACE("Sending packet: " .  _escape( $data_packet_string_crypt ));
	$socket->print($data_packet_string_crypt);
	
	# destroy the socket because it now goes out of scope
	TRACE("OK");
}

### PRIVATE SUBROUTINES #################################################

# truncates long fields
sub _correct_message {
	my $message = shift;

	if (length( $message->{'host_name'} ) >= MAX_HOSTNAME_LENGTH) {
		warn("Net::Nsca - Hostname too long - truncated");
		$message->{'host_name'} = substr($message->{'host_name'}, 0, MAX_HOSTNAME_LENGTH-1);
	}
	if (length( $message->{'svc_description'} ) >= MAX_DESCRIPTION_LENGTH) {
		warn("Net::Nsca - Description too long - truncated");
		$message->{'svc_description'} = substr($message->{'svc_description'}, 0, MAX_DESCRIPTION_LENGTH-1);
	}
	if (length( $message->{'plugin_output'} ) >= MAX_PLUGINOUTPUT_LENGTH) {
		warn("Net::Nsca - Plugin Output too long - truncated");
		$message->{'plugin_output'} = substr($message->{'plugin_output'}, 0, MAX_PLUGINOUTPUT_LENGTH-1);
	}
	return $message;
}

# central switchboard for encryption methods.
sub _encrypt {
	my ($data_packet_string, $encryption_method, $iv_salt, $password) = @_;
	TRACE("encrypt method $encryption_method");
	
	my $crypted;
	if ($encryption_method == ENCRYPT_NONE) {
		$crypted = $data_packet_string;
	} elsif ($encryption_method == ENCRYPT_XOR) {
		$crypted = _encrypt_xor($data_packet_string, $iv_salt, $password);
	} else {
		die("Net::Nsca - Don't know how to encrypt that way");
	}
	return $crypted;
}

sub _encrypt_xor {
	my ($data_packet_string, $iv_salt, $password) = @_;

	my @out = split(//, $data_packet_string);
	TRACE("Out buffer is " . scalar(@out) . " items long");
	my @salt_iv = split(//, $iv_salt);
	my @salt_pw = split(//, $password);
	
	my $y = 0;
	my $x = 0;

	#/* rotate over IV we received from the server... */
	while ($y < SIZEOF_DATA_PACKET) {
		#/* keep rotating over IV */
		$out[$y] = $out[$y] ^ $salt_iv[$x % scalar(@salt_iv)];

		$y++;
		$x++;
	}

	#/* rotate over password... */
	$y=0;
	$x=0;
	while ($y < SIZEOF_DATA_PACKET){
		#/* keep rotating over password */
		$out[$y] = $out[$y] ^ $salt_pw[$x % scalar(@salt_pw)];

		$y++;
		$x++;
	}
	return( join('',@out) );
}

#/* calculates the CRC 32 value for a buffer */
sub _calculate_crc32 {
	TRACE("calculate_crc32");
	my $string = shift;

	my $crc32_table = _generate_crc32_table();
	my $crc = 0xFFFFFFFF;

	foreach my $tchar (split(//, $string)) {
		my $char = ord($tchar);
		$crc = (($crc >> 8) & 0x00FFFFFF) ^ $crc32_table->[($crc ^ $char) & 0xFF];
	}

	return ($crc ^ 0xFFFFFFFF);
}

#/* build the crc table - must be called before calculating the crc value */
sub _generate_crc32_table {
	TRACE("generate_crc32_table");
	my $crc32_table = [];
	my $poly = 0xEDB88320;
	
	for (my $i = 0; $i < 256; $i++){
		my $crc = $i;
		for (my $j = 8; $j > 0; $j--) {
			if ($crc & 1) {
				$crc = ($crc >> 1) ^ $poly;
			} else {
				$crc = ($crc >> 1);
			}
		}
		$crc32_table->[$i] = $crc;
 	}
	return $crc32_table;
}

# borrowed from CGI.pm
sub _escape {
    my $toencode = shift;
    $toencode=~s/([^a-zA-Z0-9_\-.])/uc sprintf(" %%%02x",ord($1))/eg;
    return $toencode;
}

sub TRACE {}

1;
