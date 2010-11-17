#!/usr/bin/perl -w
# Youbeda - OVZ complainer (inspired by Yabeda software)
# Copyright (C) 2010 Fedor A. Fetisov <faf@ossg.ru>. All Rights Reserved
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;
use warnings;

# Initially Youbeda needs only standard core modules
use Getopt::Long qw(:config no_ignore_case bundling no_auto_abbrev);
use POSIX;
use Sys::Syslog qw(:standard);

# Path to where OVZ resource counters stored at
my $base = '/proc/bc/';

my $cache = {};
my $options = {};

GetOptions(
    $options, 'help|?', 'config|c=s', 'debug|d', 'quiet|q', 'schema|s'
) or die "For usage information try: \t$0 --help\n";

if ($options->{'help'}) {
    print <<HELP

 Youbeda - Perl OVZ complainer

 Usage: $0 [options] [-c|--config=<file> | --help|-h | --schema|-s]

 --help|-h - print this help and exit

 --schema|-s  - print empty database schema and exit

 Options:
	    --quiet|-q  - run Youbeda in quiet mode
			  (to set this mode you could also use config)

	    --debug|-d	- run Youbeda with maximum verbosity
			  (to set this mode you could also use config)

 Note that command-line options always overriding values in config and
debug mode overrides quiet mode.

 If config file is not specified Youbeda will look for file \'config\'
in current directory.


HELP
;
    exit;
}

if ($options->{'schema'}) {
    print _get_db_schema();
    exit;
}


# Get configuration
my $config = do($options->{'config'} || './config');
if ($@) {
    print STDERR "Bad configuration format: $@\n";
    exit 1;
}
unless ($config) {
    print STDERR "Configuration not found!\n";
    exit 1;
}

# Set debug mode or quiet mode depending on command-line options
# and config settings
my $debug = 0;
my $quiet = 0;
if ($options->{'debug'}) {
    $debug = 1;
}
elsif ($options->{'quiet'}) {
    $quiet = 1;
}
elsif ($config->{'debug'}) {
    $debug = 1;
}
elsif ($config->{'quiet'}) {
    $quiet = 1;
}

# Test all regular expressions in config
debug('Testing regular expressions in configuration');
unless (_test_regex($config->{'disallowed_vps_regex'})) {
    warning('Invalid regex for [ disallowed_vps_regex ]. Using empty value');
    $config->{'disallowed_vps_regex'} = '';
}
else {
    debug('Regex for [ disallowed_vps_regex ] looks good');
}

unless (_test_regex($config->{'complete_hostname_regex'})) {
    warning('Invalid regex for [ complete_hostname_regex ]. Using default: .+');
    $config->{'complete_hostname_regex'} = '.+';
}
else {
    debug('Regex for [ complete_hostname_regex ] looks good');
}

if ($config->{'actions'}->{'adjust'}->{'enabled'}) {
    unless (_test_regex($config->{'actions'}->{'adjust'}->{'allowed_vps_regex'})) {
	warning('Invalid regex for [ actions/adjust/allowed_vps_regex ]. Action disabled');
	$config->{'actions'}->{'adjust'}->{'enabled'} = 0;
    }
    else {
	debug('Regex for [ actions/adjust/allowed_vps_regex ] looks good');
    }
}

# Main workflow
# Get previously saved old data in raw form
my $raw_data = read_old_data($config->{'state_file'});
# Get actual data
my $cur_data = get_cur_data();

if (scalar(@$raw_data)) {
# If there is any old data - test it and tranform to normal form
    my $old_data = get_old_data($raw_data);

# If there are old data and actual data to compare - do it
    if (scalar(keys(%$old_data)) > 0 && scalar(keys(%$cur_data)) > 0) {
	my $results = compare_data($old_data, $cur_data);
	if (@$results) {
# Some failcnt counters changed => make all alert actions
	    alert($results);
	}
    }
}
else {
    debug('Old data not found: save current state and exit');
}

# Save actual data to use it next time
my $res = save_data($config->{'state_file'}, $cur_data);

# Close all opened connections and exit
exit(!($res && _clean_cache()));

################################## Functions ################################

############################### Alert functions #############################

# Core alert function
# Params: reference to array with alert data
#	  each line in array is a reference to array with fields:
#	  0: timestamp (unixtime) of check
#	  1: VEID
#	  2: HN hostname
#	  3: resource
#	  4: actual held value
#	  5: actual maxheld value
#	  6: actual barrier value
#	  7: actual limit value
#	  8: actual failcnt value
#	  9: old failcnt value
# Return: 1
sub alert {
    my $alerts = shift;
    foreach my $line (@$alerts) {

# Write message to console and/or into logfile and/or into syslog
	if ($config->{'output'}->{'log'}->{'enabled'} ||
		$config->{'output'}->{'console'}->{'enabled'} ||
		$config->{'output'}->{'syslog'}->{'enabled'}) {
	    notice(sprintf($config->{'message_format'}, _time($line->[0]), $line->[1], $line->[2], $line->[3], $line->[9], $line->[8]));
	}

# Send email notification
	if ($config->{'actions'}->{'email'}->{'enabled'}) {
	    alert_by_email($line);
	}

# Send jabber notification
	if ($config->{'actions'}->{'jabber'}->{'enabled'}) {
	    alert_by_jabber($line);
	}

# Write statistics into SQL database
	if ($config->{'actions'}->{'db'}->{'enabled'}) {
	    write_to_db($line);
	}

# Write statistics into SQLite database
	if ($config->{'actions'}->{'sqlite'}->{'enabled'}) {
	    write_to_sqlite($line);
	}

# Write SQL requests into file
	if ($config->{'actions'}->{'sqldump'}->{'enabled'}) {
	    write_sql_dump($line);
	}

# Adjust limits
	if ($config->{'actions'}->{'adjust'}->{'enabled'}) {
	    adjust($line);
	}

    }

    return 1;
}


# Send email notification
# Params: reference to array with alert data (see alert function)
# Return: 1 on success, 0 on error
sub alert_by_email {
    my $line = shift;

    debug('Trying to send alert by email');

    unless (defined $cache->{'email_modules'}) {
	debug('Checking for modules needed');
	foreach my $module ('Mail::Mailer', 'MIME::Words', 'MIME::Base64') {

	    eval "use $module;";
    	    if ($@) {
	        warning("Can't use module $module. Email notification disabled");
		$config->{'actions'}->{'email'}->{'enabled'} = 0;
		return 0;
	    }

	}
	$cache->{'email_modules'} = 1;
    }

    debug('Composing headers');
    my $headers = {
		    'Subject'  => sprintf($config->{'subject_format'}, $line->[1], $line->[3]),
		    'From'     => $config->{'actions'}->{'email'}->{'from'},
		    'To'       => join(',', @{_force_array($config->{'actions'}->{'email'}->{'to'})}),
		    'Content-Disposition' 		=> 'inline',
		    'Content-Transfer-Encoding' 	=> 'base64',
		    'Content-Type' 			=> 'text/plain; charset=' . ($config->{'actions'}->{'email'}->{'charset'} || 'ISO-8859-1'),
		    'MIME-Version' 			=> '1.0'
    };

    debug('Sending email');
    my $mailer = new Mail::Mailer;
    $mailer->open($headers);
    print $mailer MIME::Base64::encode_base64(sprintf($config->{'message_format'}, _time($line->[0]), $line->[1], $line->[2], $line->[3], $line->[9], $line->[8]));
    $mailer->epilogue;

    debug('Email sent');

    return 1;
}

# Send jabber notification
# Params: reference to array with alert data (see alert function)
# Return: 1 on success, 0 on error
sub alert_by_jabber {
    my $line = shift;

    debug('Trying to send alert by jabber');

    unless (defined $cache->{'jabber_modules'}) {
	debug('Checking for modules needed');
	foreach my $module ('Net::Jabber', 'IO::Socket::SSL v0.81', 'Encode') {

	    eval "use $module;";
    	    if ($@) {
		warning("Can't use module $module. Jabber notification disabled");
		$config->{'actions'}->{'jabber'}->{'enabled'} = 0;
		return 0;
	    }

	}
	$cache->{'jabber_modules'} = 1;
    }

    my $client;
# Seek for existing Jabber connection in cache
# Establish new one if not found
    unless (defined ($cache->{'jabber_client'})) {

	debug('Initialize jabber client');
	$client = new Net::Jabber::Client();

	debug('Connect to Jabber server');
	unless ($client->Connect(%{$config->{'actions'}->{'jabber'}->{'connection'}})) {
	    warning("Can't connect to Jabber server. Jabber notification disabled");
	    $config->{'actions'}->{'jabber'}->{'enabled'} = 0;
	    return 0;
	}

	debug('Authorizing on Jabber server');
	my @result = $client->AuthSend(%{$config->{'actions'}->{'jabber'}->{'connection'}});
	if ($result[0] ne 'ok') {
	    warning("Authorization on Jabber server failed: $result[0] - $result[1] . Jabber notification disabled");
	    $config->{'actions'}->{'jabber'}->{'enabled'} = 0;
	    return 0;
	}
# Store connection in cache to use next time
	$cache->{'jabber_client'} = \$client;
    }
    else {
	$client = ${$cache->{'jabber_client'}};
    }

    my $message = sprintf($config->{'message_format'}, _time($line->[0]), $line->[1], $line->[2], $line->[3], $line->[9], $line->[8]);
    my $subject = sprintf($config->{'subject_format'}, $line->[1], $line->[3]);
    Encode::_utf8_on($message);
    Encode::_utf8_on($subject);

    foreach my $rcpt (@{_force_array($config->{'actions'}->{'jabber'}->{'to'})}) {
	debug("Sending message to $rcpt");
	$client->MessageSend(
				to	=> $rcpt,
				subject	=> $subject,
				body	=> $message,
				type	=> 'normal'
	);
    }

    return 1;
}

# Write alert data into SQL database
# Params: reference to array with alert data (see alert function)
# Return: 1 on success, 0 on error
sub write_to_db {
    my $line = shift;

    debug('Trying to write alert to SQL database');

    unless (defined $cache->{'db_modules'}) {
	debug('Checking for modules needed');
	foreach my $module ('DBI', 'DBD::' . $config->{'actions'}->{'db'}->{'connection'}->{'driver'}) {

	    eval "use $module;";
    	    if ($@) {
		warning("Can't use module $module. Writing to SQL database disabled");
		$config->{'actions'}->{'db'}->{'enabled'} = 0;
		return 0;
	    }

	}
	$cache->{'db_modules'} = 1;
    }

    my $dbh;
    my $sth;

# Seek for existing SQL database connection and request object in cache
# Make new ones if not found
    unless (defined ($cache->{'dbh'}) && defined ($cache->{'sth'})) {
	debug('Connecting to SQL database');

	$dbh = DBI->connect('dbi:' . $config->{'actions'}->{'db'}->{'connection'}->{'driver'} .
				     ':dbname=' . $config->{'actions'}->{'db'}->{'connection'}->{'database'} .
				     ';host=' . $config->{'actions'}->{'db'}->{'connection'}->{'host'} .
				     ';port=' . $config->{'actions'}->{'db'}->{'connection'}->{'port'},
				     $config->{'actions'}->{'db'}->{'connection'}->{'username'},
				     $config->{'actions'}->{'db'}->{'connection'}->{'password'},
				     {'PrintError' => 0});
	unless ($dbh) {
	    warning('Can\'t connect to SQL database: ' . DBI::errstr() . 'Writing to SQL database disabled');
	    $config->{'actions'}->{'db'}->{'enabled'} = 0;
	    return 0;
	}

# Store connection in cache to use next time
	$cache->{'dbh'} = \$dbh;

	debug('Preparing SQL request to SQL database');
	unless ($sth = $dbh->prepare(_get_db_request_template($config->{'actions'}->{'db'}->{'stats_table'}))) {
	    warning('Can\'t prepare SQL request: ' . $dbh->errstr() . ' . Writing to SQL database disabled');
	    $config->{'actions'}->{'db'}->{'enabled'} = 0;
	    return 0;
	}

# Store request object in cache to use next time
	$cache->{'sth'} = \$sth;

    }
    else {
	$sth = ${$cache->{'sth'}};
    }

    my $res = $sth->execute(strftime('%Y-%m-%d %H:%M:%S', localtime($line->[0])), $line->[2], $line->[1], $line->[3], $line->[4], $line->[5], $line->[6], $line->[7], $line->[8], $line->[9]);

    unless (defined $res) {
	warning('Can\'t write to SQL database: ' . $dbh->errstr() . ' . Writing to SQL database disabled');
	$config->{'actions'}->{'db'}->{'enabled'} = 0;
	return 0;
    }

    return 1;
}

# Write alert data into SQLite database
# Params: reference to array with alert data (see alert function)
# Return: 1 on success, 0 on error

sub write_to_sqlite {
    my $line = shift;

    debug('Trying to write alert to SQLite database');

    unless (defined $cache->{'sqlite_modules'}) {
	debug('Checking for modules needed');
	foreach my $module ('DBI', 'DBD::SQLite') {

	    eval "use $module;";
	    if ($@) {
		warning("Can't use module $module. Writing to SQLite database disabled");
		$config->{'actions'}->{'sqlite'}->{'enabled'} = 0;
		return 0;
	    }

	}
	$cache->{'sqlite_modules'} = 1;
    }


    my $creation_flag = !(-f $config->{'actions'}->{'sqlite'}->{'db'});

    my $dbh;
    my $sth;
    unless ((defined $cache->{'sqlite_dbh'}) && (defined $cache->{'sqlite_sth'})) {
	debug('Connecting to SQLite database');

	$dbh = DBI->connect('dbi:SQLite:' . $config->{'actions'}->{'sqlite'}->{'db'}, '', '', {'PrintError' => 0});

	unless ($dbh) {
	    warning('Can\'t connect to SQLite database: ' . DBI::errstr() . 'Writing to SQLite database disabled');
	    $config->{'actions'}->{'sqlite'}->{'enabled'} = 0;
	    return 0;
	}

# Store connection in cache to use next time
	$cache->{'sqlite_dbh'} = \$dbh;

	if ($creation_flag) {
	    debug('SQLite database not found. Trying to create new');
# Split schema into separate requests and execute them one by one
	    my @schema = split(/;/,_get_db_schema());
	    foreach my $element (@schema) {
		unless ($dbh->do($element)) {
		    warning('Can\'t populate SQLite database with data schema: ' . $dbh->errstr() . ' . Writing to SQLite database disabled');
		    $config->{'actions'}->{'sqlite'}->{'enabled'} = 0;
		    return 0;
		}
	    }
	}

	debug('Preparing SQL request to SQLite database');
	unless ($sth = $dbh->prepare(_get_db_request_template($config->{'actions'}->{'sqlite'}->{'stats_table'}))) {
	    warning('Can\'t prepare SQL request: ' . $dbh->errstr() . ' . Writing to SQLite database disabled');
	    $config->{'actions'}->{'sqlite'}->{'enabled'} = 0;
	    return 0;
	}

# Store request object in cache to use next time
	$cache->{'sqlite_sth'} = \$sth;

    }
    else {
	$sth = ${$cache->{'sqlite_sth'}};
    }

    my $res = $sth->execute(strftime('%Y-%m-%d %H:%M:%S', localtime($line->[0])), $line->[2], $line->[1], $line->[3], $line->[4], $line->[5], $line->[6], $line->[7], $line->[8], $line->[9]);

    unless (defined $res) {
	warning('Can\'t write to SQLite database: ' . $dbh->errstr() . ' . Writing to SQLite database disabled');
	$config->{'actions'}->{'sqlite'}->{'enabled'} = 0;
	return 0;
    }

    return 1;
}

# Write SQL request to file
# Params: reference to array with alert data (see alert function)
# Return: 1 on success, 0 on error
sub write_sql_dump {
    my $line = shift;

    debug('Trying to write alert into SQL dump file or pipe \'' . $config->{'actions'}->{'sqldump'}->{'filename'} . '\'');

    my $string = sprintf(_get_db_request_template($config->{'actions'}->{'sqldump'}->{'stats_table'}, '\'%s\''),
			    strftime('%Y-%m-%d %H:%M:%S', localtime($line->[0])), $line->[2], $line->[1],
			    $line->[3], $line->[4], $line->[5], $line->[6], $line->[7], $line->[8], $line->[9]) . ';';


    my $sqldump;
    unless (defined $cache->{'sqldump'}) {

	if ($config->{'actions'}->{'sqldump'}->{'is_pipe'}) {
	    debug('Open SQL dump pipe');
	    unless (open($sqldump, '| ' . $config->{'actions'}->{'sqldump'}->{'filename'})) {
		error('Can\'t open pipe ' . $config->{'actions'}->{'sqldump'}->{'filename'} . " to print SQL request: $! . Writing to SQL dump pipe disabled.");
	        $config->{'actions'}->{'sqldump'}->{'enabled'} = 0;
		return 0;
	    }
	}
	else {
	    debug('Open SQL dump file');
	    unless (open($sqldump, '>>' . $config->{'actions'}->{'sqldump'}->{'filename'})) {
		error('Can\'t open file ' . $config->{'actions'}->{'sqldump'}->{'filename'} . " to write SQL request: $! . Writing to SQL dump file disabled.");
	        $config->{'actions'}->{'sqldump'}->{'enabled'} = 0;
		return 0;
	    }
	    debug('Lock SQL dump file');
	    unless (flock($sqldump, 2)) {
		error('Can\'t lock file ' . $config->{'actions'}->{'sqldump'}->{'filename'} . " while writing SQL request: $! . Writing to SQL dump file disabled.");
	        $config->{'actions'}->{'sqldump'}->{'enabled'} = 0;
	        return 0;
	    }
	}
	$cache->{'sqldump'} = \$sqldump;
    }
    else {
	$sqldump = ${$cache->{'sqldump'}};
    }

    print $sqldump $string . "\n";
    debug('SQL request written');

    return 1;
}


# Adjust limit values
# Params: reference to array with alert data (see alert function)
# Return: 1 on success, 0 on error
sub adjust {
    my $line = shift;

    debug('Trying to adjust limits');

    debug('Check veid ' . $line->[1] . ' for adjustment permission');

    if (($config->{'actions'}->{'adjust'}->{'allowed_vps_regex'} eq '') ||
	!($line->[1] =~ /$config->{'actions'}->{'adjust'}->{'allowed_vps_regex'}/) ||
	($line->[1] == 0)) {
	debug('Limits for veid ' . $line->[1] . ' should not be adjusted. Skipped');
	return 1;
    }
    else {
	debug('Limits for veid ' . $line->[1] . ' should be adjusted');
    }

    my $max_limits;
    unless (defined $cache->{'max_limits'}) {
	debug('Getting maximum limits as limits for HN (VPS with VEID 0)');
	$max_limits = (defined $cur_data->{0}) ? $cur_data->{0} : get_vps_data_by_veid(0);
	$cache->{'max_limits'} = $max_limits;
    }
    else {
	$max_limits = $cache->{'max_limits'};
    }

    debug('Compare actual barrier for ' . $line->[3] . ' with maximum value of ' . $max_limits->{'resources'}->{$line->[3]}->[2]);
    unless ($line->[6] < $max_limits->{'resources'}->{$line->[3]}->[2]) {
	warning('Can\'t adjust limits of ' . $line->[3] . ' for ' . $line->[1] . ': barrier value already set to maximum limit');
	return 0;
    }

    debug('Calculating new barrier and limit values');
    my $new_barrier = int($line->[6] * (1.0 + $config->{'actions'}->{'adjust'}->{'adjustment'}));
    $new_barrier = ($new_barrier < $max_limits->{'resources'}->{$line->[3]}->[2]) ? $new_barrier : $max_limits->{'resources'}->{$line->[3]}->[2];
    my $new_limit = int($line->[7] * (1.0 + $config->{'actions'}->{'adjust'}->{'adjustment'}));
    $new_limit = ($new_limit < $max_limits->{'resources'}->{$line->[3]}->[3]) ? $new_limit : $max_limits->{'resources'}->{$line->[3]}->[3];

    notice('Adjusting limits of ' . $line->[3] . ' for ' . $line->[1] . ' from ' . $line->[6]. ':' . $line->[7] . ' to ' . $new_barrier . ':' . $new_limit);

    my $command = $config->{'actions'}->{'adjust'}->{'command'} . ' set ' . $line->[1] . ' --' . $line->[3] . ' ' . $new_barrier . ':' . $new_limit .
	($config->{'actions'}->{'adjust'}->{'save_changes'} ? ' --save' : '') . ' 2>&1';

    debug("Executing command $command");
    if (open(SYS, "$command |")) {
	while(<SYS>) {
	    chomp;
	    notice($_);
	}
	return close(SYS);
    }
    else {
	warning("Limits adjustment failed: $!");
	return 0;
    }
}

######################### Data management functions #########################

# Read previously saved old data
# Params: cache filename
# Return: reference to array with old data in raw form
# 	(i.e. one string - one element)
# 	in raw form data stored as: <VEID> <resource> <failcnt>
#	for example: "123456 kmemsize 7"
sub read_old_data {
    my $filename = shift;
    my @res;

    if (-f $filename) {
	debug("Getting old data from file $filename");
	if (open(IN, "<$filename")) {
	    while (<IN>) {
		chomp;
		push(@res, $_);
	    }

	    if (close(IN)) {
		debug('Old data collected');
	    }
	    else {
		error("Can't close file $filename with old data: $!");
		debug('Exit with error');
		exit(1);
	    }
	}
	else {
	    error("Can't open file $filename with old data: $!");
	    debug('Exit with error');
	    exit(1);
	}
    }
    else {
	warning("File $filename with old data not found");
    }

    return \@res;
}

# Transform raw data to normal form
# Params: reference to array with raw data (see read_old_data function)
# Return: reference to hash structure with data in normal form
# in normal form data stored as hash:
# { 'hostname' => 'hostname.domain.tld',
#   <VEID> => { 'time' => <unixtime>,
#		'resources' => { <resource name> => [ <held value>,
#						      <maxheld_value>,
#						      <barrier_value>,
#						      <limit_value>,
#						      <failcnt_value> ],
#				...
#				}
#	      }
# }
sub get_old_data {
    my $data = shift;
    my $res = {};

    debug('Validating data');

    foreach (@$data) {
# Parse data in raw form and transform it to normal form
	if (/^(\d+)\s(\w+)\s(\d+)$/) {
	    $res->{$1}->{'resources'}->{$2} = [];
	    $res->{$1}->{'resources'}->{$2}->[4] = $3;
        }
    }

    warning('Validation for old data failed: valid data not found') unless scalar(keys(%$res));

    return $res;
}

# Read actual data from $base (see below) directory
# Params: none
# Return: actual data in normal form (see get_old_data function)
sub get_cur_data {

    debug('Getting current data');

    my @vps;

    debug("Reading list of VPS to check from $base directory");

    if (opendir(BC, '/proc/bc/')) {
	while(my $veid = readdir(BC)) {
# Skip non-directories as well as non-numeric directories
	    next if (($veid =~ /^\.+$/) || !(-d $base . $veid));
# Also skip disallowed VEIDs (if set)
	    push(@vps, $veid) if (($config->{'disallowed_vps_regex'} eq '') || !($veid =~ /$config->{'disallowed_vps_regex'}/));
	}

	if (closedir(BC)) {
	    debug('List of ' . scalar(@vps) . ' VPS obtained');
	}
	else {
	    error("Can't close $base directory: $!");
	    debug('Exit with error');
	    exit(1);
	}
    }
    else {
	error("Can't open $base directory: $!");
	debug('Exit with error');
	exit(1);
    }

    my $res = { 'hostname' => _get_hostname() };
    debug('Proceeding with list of VPS');
    foreach my $veid (@vps) {
	my $data = get_vps_data_by_veid($veid);
	$res->{$veid} = $data if (defined $data);
    }

    return $res;
}

# Get VPS data by VEID
# Params: veid
# Return: reference to hash with data for given VPS (see get_old_data function)
sub get_vps_data_by_veid {
    my $veid = shift;

    my $res = {};

    debug("Proceeding with VPS $veid");
    if ($veid =~ /^\d+$/) {
	if (open(IN, "<$base$veid/resources")) {
	    my $time = time;
	    while(<IN>) {
		chomp;
		s/^\s+//;
		s/\s+$//;
		if (/^(\w+)((\s+\d+){5})$/) {
# Parse each line of resources "file", place data in array
# and store reference to the array in hash
		    $res->{'time'} ||= $time;
		    my @temp = split(/\s+/, $2);
		    shift(@temp);
		    $res->{'resources'}->{$1} = \@temp;
		}
	    }
	}
	else {
	    warning("Can't open file $base$veid/resources: $!");
	    debug("VPS $veid skipped");
	    return undef;
	}
    }
    else {
        debug("Skipped invalid VPS $veid");
	return undef;
    }

    return $res;
}

# Compare two datasets in normal form (by failcnt values)
# Params: reference to hash with old data, reference to hash with new data
# Return: reference to array with alert data (see alert function)
sub compare_data {
    my $old_data = shift;
    my $new_data = shift;
    my @res;

    debug('Comparing data');

    foreach my $veid (keys(%$new_data)) {
	next unless ($veid =~ /^\d+$/);
	foreach my $resource (keys %{$new_data->{$veid}->{'resources'}}) {
	    if (defined $old_data->{$veid}->{'resources'}->{$resource}) {
		if ($new_data->{$veid}->{'resources'}->{$resource}->[4] != $old_data->{$veid}->{'resources'}->{$resource}->[4]) {
		    push(@res, [$new_data->{$veid}->{'time'}, $veid, $new_data->{'hostname'}, $resource,  @{$new_data->{$veid}->{'resources'}->{$resource}}, $old_data->{$veid}->{'resources'}->{$resource}->[4]]);
		}
	    }
	    else {
		debug("Old failcnt for $veid:$resource not found. Skipped");
	    }
	}
    }

    debug('Total failcnt increments: ' . scalar(@res));

    return \@res;
}

# Save dataset in file as raw data
# Params: filename, reference to hash with data in normal form
#					(see get_old_data function)
# Return: 1 on success, 0 on error
sub save_data {
    my $filename = shift;
    my $data = shift;

    debug("Saving current data to file $filename");
    if (open(FILE, '>' . $filename)) {
	if (flock(FILE, 2)) {
	    foreach my $veid (keys %$data) {
		next unless ($veid =~ /\d+/);
		foreach my $resource (keys %{$data->{$veid}->{'resources'}}) {

		    print FILE $veid . ' ' . $resource . ' ' . $data->{$veid}->{'resources'}->{$resource}->[4] . "\n";
		}
	    }
	}
	else {
	    error("Can't lock file $filename while saving new data: $!");
	    return 0;
	}

	if (close FILE) {
	    debug('New data saved');
	    return 1;
	}
	else {
	    error("Can't close file $filename while saving new data: $!");
	    return 0;
	}
    }
    else {
	error("Can't open file $filename to write while saving new data: $!");
	return 0;
    }
}

############################## Output functions #############################

# Output debug message
# Params: message
# Return: 1 on success, 0 on error
sub debug {
    my $message = shift;
    return $debug ? output($message, 'DEBUG') : 1;
}

# Output error message
# Params: message
# Return: 1 on success, 0 on error
sub error {
    my $message = shift;
    return $quiet ? 1 : output($message, 'ERROR');
}

# Output warning message
# Params: message
# Return: 1 on success, 0 on error
sub warning {
    my $message = shift;
    return $quiet ? 1 : output($message, 'WARN');
}

# Output notice message
# Params: message
# Return: 1 on success, 0 on error
sub notice {
    my $message = shift;
    return $quiet ? 1 : output($message, 'NOTICE');
}

# Output message of given type to STDIN and/or logfile
# Params: message, type (debug / error / warning / notice / ...)
# Return: 1 on success, 0 on error
sub output {
    my $message = shift;
    my $raw_message = $message;
    my $mode = shift;
    $message = '[' . _time() . "] [$mode] $message\n";
    my $res = 1;

    if ($config->{'output'}->{'console'}->{'enabled'}) {
	print $message;
    }

    if ($config->{'output'}->{'log'}->{'enabled'}) {
	$res = _write_to_log($config->{'output'}->{'log'}->{'logfile'}, $message);
    }

    if ($config->{'output'}->{'syslog'}->{'enabled'}) {
	openlog($config->{'output'}->{'syslog'}->{'ident'}, 'ndelay,pid', $config->{'output'}->{'syslog'}->{'facility'});
# Define priority level depending on message type
	my $priority = 'notice';
	$priority = 'err' if ($mode eq 'error');
	$priority = 'debug' if ($mode eq 'debug');
# Write to syslog
	syslog($priority, $raw_message);
	closelog();
    }

    return $res;
}

############################# Service functions #############################

# Test regular expression
# Params: regular expression as string
# Return: 1 if test passed, 0 if failed
sub _test_regex {
    my $regex = shift;
    return eval { '' =~ /$regex/; 1 } || 0;
}

# Transform value to array reference if it's not already array reference
# Params: value
# Return: array reference
sub _force_array {
    my $value = shift;
    return (ref($value) eq 'ARRAY') ? $value : [$value];
}

# Get system hostname
# Params: none
# Return: hostname
sub _get_hostname {

# Get hostname using POSIX function
    my $hostname = (uname)[1];

# Add hostname suffix if hostname is not in complete form
    unless ($hostname =~ /$config->{'complete_hostname_regex'}/) {
	$hostname .= $config->{'hostname_suffix'};
    }
    return $hostname;
}

# Format date and time
# Params: (optional): timestamp (unixtime)
# Return: formatted date and time
sub _time {
    my $time = shift;
    $time ||= time;
    return strftime($config->{'time_format'}, localtime($time));
}

# Write data to file
# Params: filename, data to write
# Return: 1 on success, 0 on error
sub _write_to_log {
    my $filename = shift;
    my $data = shift;

    if (open(FILE, '>>' . $filename)) {
	if (flock(FILE, 2)) {
	    print FILE $data;
	}
	else {
	    print STDERR "Can't lock file $filename : $!\n" unless $quiet;
	    return 0;
	}

	unless (close FILE) {
	    print STDERR "Can't close file $filename : $!\n" unless $quiet;
	    return 0;
	}

    }
    else {
	print STDERR "Can't open file $filename to write: $!\n" unless $quiet;
	return 0;
    }

    return 1;
}

# Clean cache - close all open connections
# Params: none
# Return: 1
sub _clean_cache {

    if (defined $cache->{'jabber_client'}) {
	debug('Disconnecting from Jabber server');
	${$cache->{'jabber_client'}}->Disconnect();
    }

    if (defined $cache->{'dbh'}) {
	if (defined $cache->{'sth'}) {
	    debug('Finishing SQL request to SQL database');
	    ${$cache->{'sth'}}->finish();
	}
	debug('Disconnecting from SQL database');
	${$cache->{'dbh'}}->disconnect();
    }

    if (defined $cache->{'sqlite_dbh'}) {
	if (defined $cache->{'sqlite_sth'}) {
	    debug('Finishing SQL request to SQLite database');
	    ${$cache->{'sqlite_sth'}}->finish();
	}
	debug('Disconnecting from SQLite database');
	${$cache->{'sqlite_dbh'}}->disconnect();
    }

    if (defined $cache->{'sqldump'}) {
	close ${$cache->{'sqldump'}};
    }

    return 1;
}

# Get database schema
# Params: none
# Return: empty database schema as string
sub _get_db_schema {

return <<END
CREATE TABLE stats (
      event_time TIMESTAMP NOT NULL,
      hostname TEXT NOT NULL,
      veid INTEGER NOT NULL,
      resource TEXT NOT NULL,
      held_value BIGINT NOT NULL,
      maxheld_value BIGINT NOT NULL,
      barrier_value BIGINT NOT NULL,
      limit_value BIGINT NOT NULL,
      failcnt_value BIGINT NOT NULL,
      old_failcnt_value BIGINT NOT NULL
);

CREATE INDEX stats_time_idx ON stats (event_time);
END
}

# Get SQL request template
# Params: table name, (optional) placeholder
# default placeholder: '?'
# Return: request as string
sub _get_db_request_template {
    my $table = shift;
    my $placeholder = shift || '?';

    my $placeholders = ($placeholder . ',') x 10;
    chop($placeholders);

    return "INSERT INTO $table (event_time, hostname, veid, resource, held_value, maxheld_value, barrier_value, limit_value, failcnt_value, old_failcnt_value) VALUES ($placeholders)";
}

1;
