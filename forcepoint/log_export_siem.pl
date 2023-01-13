#!/usr/bin/env perl

###########################################################################
# Sample SIEMv2 Logging Download Script v2.0.1
# $Revision: #28 $
#
# Forcepoint LLC provides the sample log download script as a convenience
# to its customers, but does not provide support for customization and will
# not be responsible for any problems that may arise from editing the script.

use strict;
use warnings;

use PAR { file => 'log_export_siem.par', fallback => 1 };

use Getopt::Long;
use Pod::Usage;
use LWP;
use LWP::UserAgent;
use HTTP::Request;
use XML::XPath;
use Digest::MD5;
use JSON;
use Archive::Extract;
use Data::Dumper;
use POSIX;
use Fcntl qw(:DEFAULT :flock );
use Text::CSV_XS;

our $VERSION = '2.0.1';

###############################################################################
# Prototypes
###############################################################################
sub process_filelist;
sub get_file_md5sum;
sub download_file;
sub mark_file_deleted;
sub recordLockPid ($);
sub create_flag_directory ($);
sub remove_flag_directory ($);

###########################################################################
# Process command line options

my $verbose          = undef;
my $service_host     = undef;
my $service_username = undef;
my $service_password = undef;
my $proxy = undef;
my $list_only = undef;
my $dest_dir  = undef;
my $do_md5sum = undef;
my $opt_max_download_children = undef;
my $opt_infinite_loop = undef;
my $pid_file = undef;
my $cfg_file = undef;
my $opt_stream = undef;
my $max_batch_size = undef;
my $help;
my $man;


my %downloading;
my $config;

GetOptions(
    'help'            => \$help,
    'man'             => \$man,
    'v|verbose'       => \$verbose,
    'h|host=s'        => \$service_host,
    'u|username=s'    => \$service_username,
    'p|password=s'    => \$service_password,
    'm|md5sum'        => \$do_md5sum,
    'l|list-only'     => \$list_only,
    'd|destination=s' => \$dest_dir,
    'proxy=s'         => \$proxy,
    'stream=s'         => \$opt_stream,        # 'web', 'email' or 'all'
	'max_download_children=i'	=> \$opt_max_download_children,
	'infinite_loop' => \$opt_infinite_loop,
	'pidfile=s' => \$pid_file,
	'cfgfile=s' => \$cfg_file,
	'max_batch_size=i' => \$max_batch_size,
);


if ( $help ) { pod2usage( verbose => 1 ); }
if ( $man )  { pod2usage( verbose => 2 ); }


if ( $cfg_file ){
	scan_config_file($cfg_file);
}
initialise_missing_arguments();
print_arguments() if $verbose;

if ( !$service_username ) {
	print  "\nUsername must be specified.\n";
	exit 1;
} elsif ( !$service_password ) {
	print "\nPassword must be specified.\n";
	exit 2 ;
}

if ( $opt_max_download_children < 1 || $opt_max_download_children > 10 ) { print  "\nmax_download_children can only take values between 1 and 10\n"; exit 3  }


if( !$pid_file ){
	$pid_file = $dest_dir . '/ftl.pid' ;
}

# Flag directory that is created when all the downloads have been launched
my $download_flag_directory = $dest_dir . '/'. "$$.download";

my $cfgpidfh = undef;
if( $cfg_file ){
	my $cfg_pid_file = $cfg_file . '.pid';
	$cfgpidfh = recordLockPid ($cfg_pid_file);
	if (!$cfgpidfh)
	{
	    print "Another instance of this script is already using the config file $cfg_file\n" if $verbose;
	    exit 4;
	}
}

# check we're not already running
my $ok = recordLockPid ($pid_file);
if (!$ok)
{
    print "Another instance of this script is already using the pid file $pid_file\n" if $verbose;
    exit 5;
}

$opt_stream = 'all' if( !$opt_stream );

if( $opt_stream eq 'all' ){
	foreach my $stream ( 'web', 'email'){
		my $stream_dir = "$dest_dir/$stream";
		if( ! -e $stream_dir ){
			if( ! mkdir $stream_dir ){
				die( "Couldn't create destination directory $stream_dir" );
			}
		}
		remove_downloading_flag_directories($stream_dir);
	}
} else {
	remove_downloading_flag_directories($dest_dir);
}


###########################################################################
# Main program


print "Downloading filelist from $service_host as $service_username\n" if $verbose;

my $ua = new LWP::UserAgent( agent => "SIEMv2_Download/$VERSION", timeout => 900  );

$ua->proxy( ['http','https'], $proxy );

$ua->credentials( "$service_host:443", "hsync", $service_username, $service_password );

my $url_logs  = "https://$service_host";
my $path = '/siem/logs';

if( $opt_stream eq 'web'  ){
	$path = '/siem/logs/web';
} elsif( $opt_stream eq 'email'  ){
	$path = '/siem/logs/email';
}

$url_logs .= $path;

# print "\nURL logs = $url_logs" if $verbose;

download_files($ua, $do_md5sum, $verbose );

# Keep it running untill all the children have finished to avoid another instance to lock the pid file
my ($still_pending_downloads);
do{
	if( !$opt_infinite_loop ){
		$still_pending_downloads = ( ! -e $download_flag_directory );
		# print "Still running processes - Downloading: $still_pending_downloads\n" if ($verbose);
		sleep(3);
	 }
} while ( $still_pending_downloads || $opt_infinite_loop );

remove_flag_directory( $download_flag_directory ) if( $opt_max_download_children );
print "End of process\n" if $verbose;

###########################################################################
# Helper functions

sub process_filelist {
    my $filelist = shift;
    my $xp = new XML::XPath( xml => $filelist );
    my $nodes = $xp->find( '/logs/log' );
    my @result = ();
	map { push @result, { stream => $_->getAttribute('stream') || '', url => $_->getAttribute('url') } } @$nodes;
    return @result;
}

sub get_file_md5sum {
    my $file_name = shift or die "Filename required";

    open my $fh, '<', $file_name or die "Error opening file to calculate MD5";
    binmode $fh;
    my $md5 = new Digest::MD5;
    $md5->addfile( $fh );
    close $fh;
    return $md5->b64digest;
}

sub _check_children
{
    my $processing = shift;
    foreach my $pid (keys %$processing)
    {
        if (waitpid ($pid, WNOHANG) != 0)
        {
        	delete $processing->{$pid};
            if ($? != 0)
            {
                my $signal = $? & 127;
                my $code = $? >> 8;
                print "child $pid exited with " . ($signal ? "signal $signal" : "value $code")."\n"	 if ($verbose);
            }
        }
    }
}


# Returns the subdirectory (/web, /email) where the files are to be downloaded when stream=all is selected
sub get_subdirectory{
	my $stream = shift;
	my $sd = '';
	if( $opt_stream eq 'all' ){
		$sd = '/'.$stream;
	}
	return $sd;
}

# Returns a 'true' value if one particular file is being downloaded or was already downloaded
# based on the existance of the destination file or the flag file *.donwloading in case the
# file is being downloaded.
# If the 'false' case, it creates the a .downloading flag file to avoid other processes to
# start downloading it in parallel
sub file_download_processed{
	my $file = shift;

	my $sd = get_subdirectory( $file->{stream} );

	(my $file_without_path = $file->{url}) =~ s/.*\///;
	my $found = grep { $downloading{$_} eq $file_without_path } keys %downloading;
	if( !$found && -e "$dest_dir$sd/$file_without_path" ){
	   	# Destination file already exists
		$found = 1;
	}
	$found = create_flag_directory( "$dest_dir$sd/$file_without_path.downloading" ) if( !$found );
	return $found;
}

# Forks a process for each file to download, keeping count of the maximum number of children allowed.
sub download_files{
    my $ua        = shift or die "LWP::UserAgent required";
    my $do_md5sum = shift;
    my $verbose   = shift;

    my $file_url;
    my $file_name ;
    print "Starting files download\n" if $verbose;

	my $oneoff = !$opt_infinite_loop;
	while($opt_infinite_loop || $oneoff){
		$oneoff = 0;
		my $listing = $ua->get( $url_logs );
		if ( not $listing->is_success ) {
		    print  "Could not download filelist: " . $listing->status_line . "\n";
		    sleep(60);
		    next;
		}
		# download and process files from the hsync server
		my @files = process_filelist( $listing->decoded_content );
		if ( @files ) {
			if( $max_batch_size ){
				splice (@files, $max_batch_size);
			}

		    if ( $list_only ) {
		        printf "Files available for download:\n%s\n", join( "\n", map {$_->{url}} sort {$a->{stream} cmp $b->{stream}} @files );
		    }
		    else {

		        foreach my $file ( @files ) {
					my $sd = get_subdirectory( $file->{stream} );
					my $url = $file->{url};
		            $file->{url} =~ s{^.*/}{};
					my $path = "$dest_dir$sd/".$file->{url};
		      		if( file_download_processed($file) ){
		      			print "Skipping already downloaded file $url \n";
		      			mark_file_deleted( $ua, $url, $verbose );
		      			next;
		      		}

			        while (1) {
			            # check for completed child processes and wait for one to terminate if we're at the limit of child processes.
			            _check_children(\%downloading);
			            my $running = scalar (keys %downloading);
			            last if $running < $opt_max_download_children;
			            sleep 5;
			        }


					my $pid = fork();
					if (!defined $pid)
					{
						print "error - Couldn't fork: $! \n";
					}

					if ($pid == 0)
					{
						# child process.
						eval{
				            my ( $protocol, $file_host ) = ( $url =~ m{^(https?)://([-A-Z0-9.]+)/}i );
				            my $port = ( $protocol eq 'https' ) ? 443 : 80;
				            $ua->credentials( "$file_host:$port", "hsync", $service_username, $service_password );
				            download_file( $ua, $url, $path, $do_md5sum, $verbose );
						};
						if( $@ ){
							print "\ndownload_files child exited with error: $@";
						}
			            exit(0);
					} else {
						# parent process
						$downloading{$pid} = $file;
					}
		        }
		    }
		}
		else {
		    print "No new files available to download\n" if $verbose;
		}

		if($opt_infinite_loop){
			print "Sleeping for 30 seconds....\n" if $verbose;
			sleep(30) ;
		}
	}
	create_flag_directory( $download_flag_directory );

}

sub download_file {
    my $ua        = shift or die "LWP::UserAgent required";
    my $file_url  = shift or die "File URL required";
    my $file_name = shift or die "Filename required";
    my $do_md5sum = shift;
    my $verbose   = shift;

    print "Downloading $file_url to $file_name\n" if $verbose;

	(my $file_without_path = $file_name) =~ s/.*\///;
    my $attempts = 0;
    while ( $attempts < 3 ) {
        $attempts++;
        my $response = $ua->get( $file_url, ':content_file' => $file_name );

        if ( $response->is_success ) {
            if ( $do_md5sum ) {
                my $response_md5sum = $response->header( 'Content-MD5' );
                $response_md5sum =~ s/=*$//;
                my $file_md5sum = get_file_md5sum( $file_name );

                if ( $response_md5sum eq $file_md5sum ) {
                    print "$file_name saved and md5sum validated\n" if $verbose;
	                remove_flag_directory( "$file_name.downloading" );
                    mark_file_deleted( $ua, $file_url, $verbose );
                    return;
                }
                else {
                    print STDERR "Warning: md5sum check failed for $file_url\n";
                }
            }
            else {
                print "$file_name saved\n" if $verbose;
                remove_flag_directory( "$file_name.downloading" );
                mark_file_deleted( $ua, $file_url, $verbose );
                return;    # No md5sum check requested
            }
        }
        elsif ($response->code == 400)
        {
            # bad request, no point repeating.
            print STDERR "Invalid request for $file_url: " . $response->status_line . "\n" . $response->content . "\n";
            remove_flag_directory( "$dest_dir/$file_without_path.downloading" );
            return;
        }
        else {
            print STDERR "Warning: Error whilst downloading $file_url: " . $response->status_line . "\n";

        }
    }    # END while

	remove_flag_directory( "$dest_dir/$file_without_path.downloading" );
    print STDERR "Error: Could not download $file_url, skipping\n";
}

sub mark_file_deleted {
    my $ua       = shift or die "LWP::UserAgent required";
    my $file_url = shift or die "File URL required";
    my $verbose  = shift;

	my $max_attempts = 3;
    my $attempts = 0;
    while ( $attempts < $max_attempts ) {
        $attempts++;
	    my $response = $ua->request( new HTTP::Request( DELETE => $file_url ) );
	    if ( $response->is_success ) {
	        print "$file_url marked for deletion on server\n" if $verbose;
	        return;
	    }
	    else {
	    	my $severity = ( $attempts == $max_attempts ? 'Error' : 'Warning' );
	        print STDERR "$severity: could not mark $file_url for deletion: " . $response->status_line . "\n";
	    }
	}
}

sub  trim { my $s = shift; $s =~ s/^\s+|\s+$//g; return $s };


sub create_flag_directory ($)
{
    my $file = shift;
    return ! mkdir $file;
}

sub remove_flag_directory ($)
{
	my $directory = shift;
	rmdir "$directory" || die( " unable to delete $directory : $! " );
}

sub recordLockPid ($) {
    my $pid_file = shift;
    my $pid_fh;

    # Open the pid file
    # sysopen here to prevent a second process from trashing the file contents
    print "Opening pid file: $pid_file\n" if $verbose;
    if (!sysopen $pid_fh, $pid_file, O_RDWR | O_CREAT) {
        print "Cannot open $pid_file - returning 0: $!\n";
        return 0;
    }

    # Try to lock the pid file
    print "Trying to Lock: $pid_file\n" if $verbose;
    if (!flock($pid_fh, LOCK_EX|LOCK_NB)) {
        print "Cannot lock $pid_file - returning 0: $!\n";
        return 0;
    }

    # Now we have the lock, truncate the file and write the pid into the file
    # Need to select and autoflush to force it to write into the file
    $pid_fh->autoflush(1);
    truncate $pid_fh, 0;
    print $pid_fh $$;

    print "Pid file $pid_file Locked OK\n" if $verbose;
    return $pid_fh;
}

# Reads the aruguments from the config file and set the values only for those
# variables that are not overridden in the command line.
sub scan_config_file {
    my $file_name = shift or die "Filename required";
    open my $fh, '<', $file_name or die "Error opening config file $file_name";

	 while (my $line = <$fh>) {
	 	chomp $line;
	 	if( $line =~ /([^=]*)=(.*)/){
	 		my $var = trim($1);
	 		my $val = trim($2);
	 		if( defined($config->{$var}) ){
				print "Variable $var appears more than once in the config file $file_name\n";
				exit 6;
			} else {
				$config->{$var} = trim($val);
			}
	  	}
	}
	close $fh;

	$service_username ||= $config->{username};
	$service_password ||= $config->{password};
	$service_host ||= $config->{host};
	$opt_max_download_children ||= $config->{max_download_children};
	$opt_infinite_loop = (defined($opt_infinite_loop) ? $opt_infinite_loop : ( $config->{infinite_loop} =~ /true/i ));
	$verbose ||= ( $config->{verbose} =~ /true/i );
	$proxy ||= $config->{proxy};
	$do_md5sum ||= ( $config->{md5sum} =~ /true/i );
	$list_only ||= ( $config->{list_only} =~ /true/i );
	$dest_dir ||= $config->{destination};
	$opt_stream ||= $config->{stream};
	$pid_file ||= $config->{pidfile};
	$cfg_file ||= $config->{cfgfile};
	$max_batch_size = ( defined($max_batch_size) ? $max_batch_size : $config->{max_batch_size} );

	# print "Config = \n".Dumper($config)."\n" if $verbose;

}

# Set default values for those parameters that are not set in either the config file and the command line
sub initialise_missing_arguments {

	$verbose = ( defined($verbose) ? $verbose : 0 );
	$service_username ||= '';
	$service_password ||= '';
	$service_host ||= 'sync-web.mailcontrol.com';
	$list_only = ( defined($list_only) ? $list_only : 0 );
	$dest_dir  ||= '.';
	$do_md5sum = ( defined($do_md5sum) ? $do_md5sum : 0 );
	$opt_max_download_children ||= 5;
	$opt_infinite_loop = ( defined($opt_infinite_loop) ? $opt_infinite_loop : 0 );
	$pid_file ||= '';
	$cfg_file ||= 'log_export_siem.cfg';
	$opt_stream ||= 'all';
	$max_batch_size = ( defined($max_batch_size) ? $max_batch_size : 0 );
	$proxy ||= '';

}

sub print_arguments{

	print "Arguments:\n";
	print "service_username = $service_username\n";
	print "service_host = $service_host\n";
	print "max_download_children = $opt_max_download_children\n";
	print "infinite_loop = $opt_infinite_loop\n";
	print "verbose = $verbose\n";
	print "proxy = $proxy\n";
	print "do_md5sum = $do_md5sum\n";
	print "list_only = $list_only\n";
	print "dest_dir = $dest_dir\n";
	print "opt_stream = $opt_stream\n";
	print "pid_file = $pid_file\n";
	print "cfg_file = $cfg_file\n";
	print "max_batch_size = $max_batch_size\n";
	print "\n\n\n";

}

sub remove_downloading_flag_directories{
	my $dirpath = shift;

	opendir my $dir, $dirpath or die "Cannot open directory [$dirpath]: $!";
	my @files = readdir $dir;
	closedir $dir;

	for my $file ( @files ){
		if( $file =~ /\.downloading$/ ){
			remove_flag_directory( $dirpath.'/'.$file );
		}
	}
}


exit 0;

__END__

=pod

=head1 NAME

log_export_siem_v2_0_1.pl - Fetches SIEMv2 traffic log files

=head1 SYNOPSIS

log_export_siem_v2_0_1.pl  [-u username -p password | --cfgfile=<FILE>] [OPTIONS]

=head1 OPTIONS AND ARGUMENTS

=over 4

=item * -v, --verbose

displays progress messages

=item * -h, --host

specifies the service hostname to use

=item * -u, --username

specifies the login username

=item * -p, --password

specifies the login password

=item * --cfgfile

specifies the location of the config file, which can include values for the other parameters.

Example:
username=admin@company.com
password=password1
host=sync-web.mailcontrol.com
infinite_loop=false
verbose=true
max_download_children=3
md5sum=false
list_only=true
destination=/tmp
proxy=http://user2@company.com:password2@myproxy.com:8081/
pidfile=/var/tmp/ftl.pid
stream=web
max_batch_size=2


=item * -d, --destination

specifies the destination directory, defaults to the current directory

=item * -m, --md5sum

turns on md5sum checking for downloaded files

=item * -l, --list-only

displays a list of logfiles without downloading them

=item * --proxy

specifies a HTTP proxy server to use

=item * --max_download_children

maximum number of downloading processes running in parallel. Defaults to 1. Maximum 10.

=item * --infinite_loop

runs the download and reformat processes in an infinite loop. If not specified,
only the files available at the time the script runs are generated and the
files already downloaded are reformatted, so that files that become available in the server
during the script run are not downloaded.

=item * --stream

Type of files to be downloaded. Possible values: "web", "email" and "all".
If "all" is specified, then subdirectories /web and /email will be created under the destination directory
and the files downloaded into their corresponding subdirectory.

=item * --max_batch_size

Specifies the maximum size of the list of files to download, so that it permits downloading the <max_batch_size> newest files everytime the script is run.


=item * --man

displays the man page

=item * --help

displays usage information

=back

=head1 DESCRIPTION

This program will connect to the Forcepoint Cloud Service
and download SIEM logfiles to the local system. It
optionally checks the md5sum before marking the log files to
be deleted on the service.

=head1 ABOUT

This script has been provided by Forcepoint LLC for use by customers who
have subscribed to the Cloud Service.


Please report bugs to Forcepoint Technical Support.

=cut
