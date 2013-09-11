#!/usr/bin/perl
# opennap_config.pl
# 
# Author: Erick Bourgeois <erick@jeb.ca> Copyright 2002-2003
# Description: A (hopefully) firendly interface to administering
# 	       an opennap-ng server configuration file. 
# 
# NOTE: Some of the variables used by this script are
# opennap-ng compatible ONLY. Please see
# http://opennap-ng.org/ for more details
# on their newly added server variables.
#
# Although, with a bit of modification to the `section' arrays
# and the __DATA__ section, it may be adapted to any opennap
# configuration. (Actually, it could probably be altered so 
# that it could be used for configuring anything.)
# 
# This program is free software; you can redistribute
# it and/or modify it under the same terms as Perl itself.
#

use strict;
use warnings;

use Getopt::Std;
use File::Copy;

my $VERSION = '0.1.1';

# Signal Catching
$SIG{INT} = sub { &int_caught() };

# Some variables
my %options;
getopt("f:o:", \%options);

my $INFILE = $options{f};
my $OUTFILE = $options{o};
&usage() unless (defined $INFILE);

if (!defined $OUTFILE)
{
	$OUTFILE = $INFILE;
	print "No output file specified, using $INFILE\n";
	print "Backing up $INFILE to $INFILE.bak...\n";
	copy("$INFILE","$INFILE.bak") or die "Can not copy $INFILE to $INFILE.bak: $!";
	print "Press enter to continue";
	my $tmp = <>;
}
my $MODIFIED = 0;
my @SECTIONS = ("Basic", "Search/Browse", "File Indexing", "Napigator Listing", "Ejection", "Abuse", "Advanced", "UNIX Only");
my @BASIC = qw(auto_link auto_register ghost_kill allow_dynamic_ghosts 
		irc_channels listen_addr login_interval login_timeout
		max_channel_length max_client_string max_clones max_hotlist 
		max_ignore max_nick_length max_reason max_topic max_user_channels
		min_read ping_interval register_interval registered_only 
		restrict_registration remote_config server_alias server_name
		server_ports strict_channels);

my @SEARCH_BROWSE = qw(max_results max_shared max_browse_result 
		max_searches search_timeout remote_browse);

my @FILE_INDEXING = qw(allow_share min_file_size index_ignore_suffix 
		index_path_depth file_count_threshold search_max_cache_entries);

my @NAPIGATOR_LISTING = qw(report_name report_ip report_port stat_server_host 
		stat_server_pass stat_server_port stat_server_user stats_port);

my @EJECTION = qw(eject_after eject_leeches eject_nochannels eject_when_full 
		eject_limit_files eject_limit_libsize eject_also_bans eject_ban_ttl 
		eject_grace_time);
	
my @ABUSE = qw(ibl_ttl notify_mod_abuse notify_mod_abuse_frequency notify_user_abuse 
		notify_user_abuse_frequency evaluate_search_abuse_after_secs
		evaluate_search_abuse_after_tags max_searches_per_minute 
		break_mx_queue discipline_ignorers discipline_ignorers_ban_ttl
		discipline_block discipline_block_ban_ttl discipline_block_mod 
		notify_mod_block no_mod_annoying max_tags_per_minute);

my @ADVANCED = qw(block_winmx compression_level log_level log_mode log_stdout 
		max_new_users_per_minute level_to_set_flags server_queue_length
		client_queue_length flood_commands flood_time invalid_clients 
		invalid_nicks max_command_length max_connections warn_time_delta
		max_time_delta nick_expire protnet server_chunk set_server_nicks 
		stat_click user_db_interval usermode who_was_time);

my @UNIX_ONLY = qw(connection_hard_limit max_data_size max_rss_size lock_memory);

my $line_num = 0;
# Retrieve the config vars, their, types, and descriptions from __DATA__
my %CONFIG_DEFAULT = ();
while (<DATA>)
{
	$line_num++;
	chomp;
	s/^(\s*)(#.*)//;
	s/^\s+//;
	s/\s+$//;
	next unless length;
	my ($var, $type, $default, $description) = split /<:>/;
	die "Can not parse the `variable name' field in the __DATA__ section at line $line_num\n" unless (defined $var);
	die "Can not parse the `type' field in the __DATA__ section at line $line_num\n" unless (defined $type);
	die "Can not parse the `default' field in the __DATA__ section at line $line_num\n" unless (defined $default);
	die "Can not parse the `description' field in the __DATA__ section at line $line_num\n" unless (defined $description);
	$CONFIG_DEFAULT{$var}->{type} = $type;
	$CONFIG_DEFAULT{$var}->{default} = $default;
	$description =~ s/\\n/\n/g;
	$CONFIG_DEFAULT{$var}->{description} = $description;
}

# Retrieve the config vars from user defined file
my %CONFIG_CURRENT = ();
$line_num = 0;
open(FILE, "$INFILE") or die "Can not open $INFILE: $!";
while (<FILE>)
{
	$line_num++;
	chomp;
	s/^(\s*)(#.*)//;
	s/^\s+//;
	s/\s+$//;
	next unless length;
	my ($key, $value);
	/(.+)\s*=\s*(.+)/;
	if ($1)
	{ ($key, $value) = ($1, $2) }
	else
	{ ($key, $value) = split /\s+/ }
	die "Can not parse the variable at line $line_num\n" unless ($key);
	$CONFIG_CURRENT{$key} = $value;
}
close(FILE);

# Ok, we have all the info we need, jump on in
# allow a maximum of 5 tries before we quit

# I know, I know...
system("cls"); system("clear");
my $is_main = 1;
my $is_section = 0;
my $is_var = 0;
my $section = '';
my $section_name = '';
my $var = '';
my $section_next = 1;
my $var_next = 1;
my $last_index_of_section_array = 0;
my @section_array = ();
my $times = 0;
my ($b, $c, $n, $p, $q)  = (98, 99, 110, 112, 113);
&display('main');
while (1)
{
	my $usr_cmd = &get_input(1);
	my $ord = ord($usr_cmd);
	
	if ($ord == $q)
	{ &write_config(1) }
	elsif ($times > 4)
	{
		print "\nYou are obviously having problems, i'm outa here!\n";
	        &write_config(1);
	}
	elsif ($is_main)
	{
		# back at the main????
		if ($ord == $b) { print "Can not go any further back!\nPlease choose again: " }
		elsif ($ord == $c) { print "Can not change anything here!\nPlease choose again: " }
		elsif ($ord == $n) { print "Please choose a section first: " }
		elsif ($ord == $p) { print "Please choose a section first: " }
		elsif ($usr_cmd >= 0 && $usr_cmd <= $#SECTIONS)
		{
			$section_next = $usr_cmd + 1;
			&display_section($usr_cmd);
		}
		else
		{ print "Invalid input, please choose again: "; $times++; next }
	}
	elsif ($is_section)
	{
		if ($ord == $b)
		{
			$is_main = 1;
			$is_section = 0;
			system("cls");system("clear");
			&display('main');
		}
		elsif ($ord == $c) { print "Can not change anything here!\nPlease choose again: " }
		elsif ($ord == $n)
		{
			$section_next = 0 if ($section_next > $#SECTIONS);
			&display_section($section_next++);
		}
		elsif ($ord == $p)
		{
			$section_next--;
			$section_next = $#SECTIONS + ++$section_next if ($section_next < 0);
			&display_section($section_next - 1);
		}
		elsif ($usr_cmd >= 0 && $usr_cmd <= $last_index_of_section_array)
		{
			$var_next = $usr_cmd + 1;
			&display_var($usr_cmd);
		}
		else
		{ print "Invalid input, please choose again: "; $times++; next }
	}
	elsif ($is_var)
	{
		if ($ord == $b)
		{
			$is_section = 1;
			$is_var = 0;
			$is_main = 0;
			system("cls");system("clear");
			&display('section', $section_name, $section);
		}
		elsif ($ord == $n)
		{
			if ($var_next > $last_index_of_section_array)
			{
				$var_next = 0;
				&display_section($section_next++);
			}
			else
			{ &display_var($var_next++) }
		}
		elsif ($ord == $p)
		{
			$var_next--;
			$var_next = $last_index_of_section_array + ++$var_next if ($var_next < 0);
			&display_var($var_next - 1);
		}
		elsif ($ord == $c)
		{
			print "New value: ";
			my $new_value = &get_input(0);
			print "main: CONFIG_DEFAULT{$var}->{type}: ",$CONFIG_DEFAULT{$var}->{type},"\n";
			system("cls");system("clear");
			my $gstars = '*' x (length(" $var MODIFIED ") + 4);
			my $bstars = '*' x (length(" $var NOT MODIFIED ") + 4);
			if ($CONFIG_DEFAULT{$var}->{type} =~ /^boolean/i)
			{
				if ($new_value eq 'on' || $new_value eq 'off')
				{
					$CONFIG_CURRENT{$var} = $new_value;
					print "$gstars\n";
					print "** $var MODIFIED **\n";
					print "$gstars\n";
					$MODIFIED = 1;
					$is_section = 1;
					$is_var = 0;
					$is_main = 0;
					&display('section', $section_name, $section);
				}
				else
				{
					print "$bstars\n";
					print "** $var NOT MODIFIED **\n";
					print "$bstars\n";
					print "Invalid value for boolean variable!\n\n";
					&display('variable', $section_name, $var);
				}
			}
			# do integer test
			elsif ($CONFIG_DEFAULT{$var}->{type} =~ /^integer/i)
			{
				if ($new_value =~ /[[:alpha:]|[:punct:]]/)
				{
					print "$bstars\n";
					print "** $var NOT MODIFIED **\n";
					print "$bstars\n";
					print "Invalid value for integer variable!\n\n";
					&display('variable', $section_name, $var);
				}
				else
				{
					$CONFIG_CURRENT{$var} = $new_value;
					print "$gstars\n";
					print "** $var MODIFIED **\n";
					print "$gstars\n";
					$MODIFIED = 1;
					$is_section = 1;
					$is_var = 0;
					$is_main = 0;
					&display('section', $section_name, $section);
				}
			}
		}
		else
		{ print "Invalid input, please choose again here: "; $times++; next }
	}
	else
	{ print "Invalid input, please choose again: "; $times++; next }
	$times = 0;
}

# Exit cleanly
exit(0);

sub get_input
{
	my $care_about_input = shift;
	my $input;
	my $times = 0;
	while ($times <= 4)
	{
		$input = <STDIN>;
		$input =~ s/^\s+//;
		$input =~ s/\s+$//;
		#return $input if ($input  eq '' && !$care_about_input);
		chomp($input);
		$input = lc($input);
		return $input if (ord($input) == 48);
		if (!$input || ($care_about_input && $input =~ /[ad-mor-z[:punct:]]/gi))
		{
			$times++;
			print "Invalid input, please choose again: ";
		}
		else 
		{ return $input }
	}
	print "\nYou are obviously having problems, i'm outa here!\n";
	&write_config(1)
}
sub display_section
{
	my $index = shift;
	$is_main = 0;
	$is_section = 1;
	$is_var = 0;
	$section_name = $SECTIONS[$index];
	$section = uc($section_name);
	$section =~ s/ /_/g;
	$section =~ s/\//_/g;
	@section_array = eval '@'.$section;
	$last_index_of_section_array = $#section_array;
	system("cls");system("clear");
	&display('section', $section_name, $section);
}
sub display_var
{
	my $index = shift;
	$is_main = 0;
	$is_section = 0;
	$is_var = 1;
	$var = $section_array[$index];
	system("cls");system("clear");
	&display('variable', $section_name, $var);
}

sub display
{
	my $what = shift;
	my $section_desc = shift;
	my $value = shift;

	print ".:: Opennap-ng Configuration $VERSION ::.\n\n";
	if ($what eq 'main')
	{
		#print "\n.:: Opennap-ng Configuration $VERSION ::.\n\n";
		print "Sections:\n\n";
		&display_array(@SECTIONS);
		print "\n(Q/q) Quit\n";
	}
	elsif ($what eq 'section')
	{
		print "Section: $section_desc\n\n";
		my $str = "&display_array(@".$value.")";
		eval $str;
		print "\n(Q/q) Quit (N/n) next (P/p) previous (B/b) Back\n";
	}
	elsif ($what eq 'variable')
	{
		print "Section: $section_desc\n\n";
		print "Variable Name: $value\n";
		if (exists $CONFIG_CURRENT{$value})
		{ print "Current Value: $CONFIG_CURRENT{$value}\n" }
		else
		{ print "Current Value: not in config\n" }
		print "Type: ",$CONFIG_DEFAULT{$value}->{type},"\n";
		print "Default: ",$CONFIG_DEFAULT{$value}->{default},"\n";
		print "Description: ",$CONFIG_DEFAULT{$value}->{description},"\n";
		print "\n(Q/q) Quit (N/n) next (P/p) previous (B/b) Back (C/c) Change\n";
	}
	print "Choose an option: ";
}

sub display_array
{
	my @array = @_;
	my $longest = &get_longest_value(@array);
	for (my $i = 0; $i <= $#array; $i++)
	{
		my $len = length($array[$i]);
		print "($i)$array[$i]", ' ' x  ($longest - $len);
		if (defined $array[$i + 1])
		{
			print "  (",$i + 1,")",$array[$i + 1];
			$i++;
		}
		print "\n";
	}
}

sub get_longest_value
{
	my @array = @_;
	my $longest = 0;
	foreach (@array)
	{
		my $len = length($_);
		$longest = $len if ($len > $longest);
	}
	return $longest;
}	

sub write_config
{
	my $is_exit = shift;
	if ($MODIFIED)
	{
		print "\nSome variables in memory have been modified. Should I write them to the file $OUTFILE? (Y/n): ";
		my $answer = &get_input(0);
		if (ord($answer) != 110)
		{
			open(CONFIG, ">$OUTFILE") or die "Can not open $OUTFILE for writting: $!\n";
			print CONFIG <<EOF;
# .:: Opennap-ng Configuration $VERSION ::.
# This file was automatically generated by 
# opennap_config.pl. Only modify it
# if and ONLY IF, you know what you are doing.
# You have been warned.

EOF
			print CONFIG "# Basic Server Configuration Section\n";
			foreach my $var (@BASIC)
			{ &print_var_value(*CONFIG, $var) }

			print CONFIG "\n# Search and Browse Section\n";
			foreach my $var (@SEARCH_BROWSE)
			{ &print_var_value(*CONFIG, $var) }

			print CONFIG "\n# File Indexing Section\n";
			foreach my $var (@FILE_INDEXING)
			{ &print_var_value(*CONFIG, $var) }

			print CONFIG "\n# Napigator Listing Section\n";
			foreach my $var (@NAPIGATOR_LISTING)
			{ &print_var_value(*CONFIG, $var) }

			print CONFIG "\n# Ejection Section\n";
			foreach my $var (@EJECTION)
			{ &print_var_value(*CONFIG, $var) }

			print CONFIG "\n# Abuse Section\n";
			foreach my $var (@ABUSE)
			{ &print_var_value(*CONFIG, $var) }

			print CONFIG "\n# Advanced Section\n";
			foreach my $var (@ADVANCED)
			{ &print_var_value(*CONFIG, $var) }

			print CONFIG "\n# UNIX Only Section\n";
			foreach my $var (@UNIX_ONLY)
			{ &print_var_value(*CONFIG, $var) }
			
			print "File $OUTFILE contains your new configuration.\n";
			$MODIFIED = 0;
		}
		else
		{ print "No configuration has been updated\n" }
	}
	else
	{ print "\nThe configuration in memory has not been modified, no writting will occur.\n" }
	
	exit(0) if ($is_exit);
}

sub print_var_value
{
	*FH = shift;
	my $var = shift;
	die "\n**intenal error, please email erick\@jeb.ca**\n" if (!defined $var);
	$CONFIG_CURRENT{$var} = '' if ($CONFIG_CURRENT{$var} =~ /null/i);
	if (exists $CONFIG_CURRENT{$var})
	{ #print "print_var_value: CONFIG_DEFAULT{$var}->{type}: ",$CONFIG_DEFAULT{$var}->{type},"\n";
		if ($CONFIG_DEFAULT{$var}->{type} =~ /^string/i)
		{
			$CONFIG_CURRENT{$var} =~ s/"//g;
			print FH "$var \"",$CONFIG_CURRENT{$var},"\"\n";
		}
		else
		{ print FH "$var $CONFIG_CURRENT{$var}\n" }
	}
	else
	{
		if ($CONFIG_DEFAULT{$var}->{type} =~ /^string/i)
		{ print FH "$var \"",$CONFIG_DEFAULT{$var}->{default},"\"\n" }
		elsif ($CONFIG_DEFAULT{$var}->{type} =~ /null/i || $CONFIG_DEFAULT{$var}->{type} =~ /depends/i)
		{ print FH "$var \n" }
		else		
		{ print FH "$var ",$CONFIG_DEFAULT{$var}->{default},"\n" }
	}
}

sub int_caught
{
	&write_config(1) if ($MODIFIED);
	print "\nCaught SIGINT\n";
	exit(0);
}

sub usage
{
	print <<EOF;
Usage: $0 -f <config_file> [-o <output_file>]

config_file is not optional, however output_file
is an optional filename to output the new configuration.
EOF
	exit(-1);
}	

# This part of the file holds all the variables<:>type<:>default<:>description
# Don NOT place anything past the __DATA__ mark, however it can be edited to your
# heart's content :\

__DATA__
protnet<:>String list<:>*<:>Protnet is a set of protections granted to an Elite user on\nthe defined IP or list of IPs.  The elite is protected from\nbeing killed, mkilled, their password changed, or account\nnuked, and their server killed, by someone NOT on the protnet,\neven if they are elite.  The default setting works like normal,\nany elite can kill other elites, etc.  Note, the protection only\nworks on your own server, it can't protect you on another server,\netc.\n\nExample:  protnet 128.1.128.1,192.168.0.*

invalid_clients<:>String list<:>(null)<:>invalid_clients is a string list of clients that are not\nallowed on your server.  Some clients can't/don't share,\nsome clients are broken, etc.\n\nExample:  invalid_clients *floodster*,*mp3rage*,*rapigator*

invalid_nicks<:>String list<:>(null)<:>invalid_nicks is a list of invalid client nicks, ones which\nyou do not want on your network for some reason or another.\n\nExample:  invalid_nicks joey2cool,*trade*

set_server_nicks<:>String list<:>(null)<:>set_server_nicks is a list of names of users who are allowed\naccess to raw 9998 and 9999.  The users must still be elite,\nthis adds another layer of security to restrict exactly who\nis allowed access.  I suggest not doing wildcards in this\nlist.\n\nExample:  set_server_nicks Khaytsus,ShadoeMynx

eject_also_bans<:>Integer<:>0<:>Should a eject of a client also result in a timed ban of the nick?\nThe default value is 0 so no bans will occur

eject_ban_ttl<:>Integer<:>1800<:>If eject also bans - how long should the ttl of the nonsharing client be?\nThe default value is 1800 seconds.

ibl_ttl<:>Integer<:>0<:>The Internal Ban List is used to control the connecting of excessive clients.\nIf a client reconnects too fast, keeps using an invalid nick or an invalid\nclient, then the ip of this user is banned for ibl_ttl seconds. A value of\n0 disables this feature.

search_max_cache_entries<:>Integer<:>500<:>To give the hub in a distributed network some relief and to speed up repeated\nsearches an internal cache is maintained. How many searches should be cached?\nThe default value is 500 searches.\nYou can query the cache stats using /raw 10116\nThe format of the output is:\nCounter Rank Usage Starttime LastUsedTime SearchString

eject_limit_libsize<:>Integer<:>0<:>set the min amount of Kilobytes a user has to share in order to be exempt\nfrom 'eject_when_full'. Any client that shares either eject_limit_files+1 files\nor 'eject_limit_libsize+1 Kilobytes will not be disconnected.

eject_limit_files<:>Integer<:>0<:>set the min amount of files a user has to share in order to be exempt\nfrom 'eject_when_full'. Any client that shares either eject_limit_files+1 files\nor 'eject_limit_libsize+1 Kilobytes will not be disconnected.

eject_grace_time<:>eject_grace_time<:>eject_grace_time<:>The default value is ten minutes ( 600 seconds ).

eject_nochannels<:>eject_nochannels<:>eject_nochannels<:>eject_nochannels set to 1 only ejects users who\nare not in a channel and not sharing enough.

min_file_size<:>Integer<:>0<:>Set the lower limit of filesize which a single file must at least have to be shared.\nIf the min_file_size is 0 then there is no checking on this parameter.

max_tags_per_minute<:>max_tags_per_minute<:>max_tags_per_minute<:>some buggy clients. When the client has more than max_tags_per_minute tags\nthe request is simply ignored.

max_searches_per_minute<:>max_searches_per_minute<:>max_searches_per_minute<:>This limit is calculated by using: ( count200 - evaluate_search_abuse_after_tags ) / onlinetime\nSo a value of 2 searches should be sufficient.

evaluate_search_abuse_after_secs<:>evaluate_search_abuse_after_secs<:>evaluate_search_abuse_after_secs<:>searching all of his incompletes.

evaluate_search_abuse_after_tags<:>Integer<:>100<:>After how many tags in total should max_searches_per_minute be evaluated? This is to\nprevent that a freshly connected user will be prosecuted because he is initally\nsearching all of his incompletes. After 100 requests\nthe counter starts counting.

break_mx_queue<:>Integer<:>0<:>Some buggy clients send a lot of privmsgs containing //WantQueue. If\nthis value is set to 1 then these privmsgs will be blocked on the\nserver this user is connected to.\nTo get a picture what a waste of bandwidth occures when not switching\nthis to 1 grep your opennap-ng logfile for "privmsg".\nIt should display something like:\nprivmsg: all 205: 43000 705596 Bytes - 205WQ: 39096 (90.9%) 431382 Bytes (61.1%)\nprivmsg: all 205: 44000 720813 Bytes - 205WQ: 40030 (91.0%) 441662 Bytes (61.3%)\nafter only some hours of uptime. 205WQ is the count and the size of privmsgs\ncontaining a queueing message.

notify_mod_abuse<:>Integer<:>1<:>When set to 0 the abuse of the tags mentioned above is not reported\nto the mod+ users on your system.

notify_mod_abuse_frequency<:>Integer<:>100<:>When "notify_mod_abuse" is set to 1 then this following var\nreports the frequency of notifications which are sent.\nA notify-mod_abuse_frequency of 100 means that every 100th\nabuse per user is reported via notify_mods().

notify_user_abuse<:>Integer<:>0<:>When set to 1 the abuse of the tags mentioned above is reported to\nthe user issueing the tag via a privmsg.

notify_user_abuse_frequency<:>Integer<:>1000<:>When "notify_user_abuse" is set to 1 then this following var\nreports the frequency of notifications which are sent.\nA notify_user_abuse_frequency of 1000 means that every 1000th\nabuse per user is reported via privmsg to the user.

no_mod_annoying<:>Integer<:>0<:>When set to 1 mod+ are exempt from the notification of tag abuse.\nThis only affects mod+ who are on a server where "notify_user_abuse"\nis set to 1.

discipline_ignorers<:>Integer<:>1<:>When a user ignores a mod+ this is annoying enough.\nBut when the mod killbans the user just to have the\nuser relogging in with another nick this hits the spot\nmultiplied by -1. If you declare "discipline_ignorers 1" then the ignoring\nuser will be kicked.

discipline_ignorers_ban_ttl<:>Integer<:>2592000<:>The vars "discipline_ignorers" and "discipline_ignorers_ban_ttl"\ntake some care of these cases. If you additionally specify\n"discipline_ignorers_ban_ttl" > 0 then these users will be banned\nin addition to that for the ammount of seconds specified.\nIf you set the latter value to 0 then no banning will occur.\nBoth default values seem reasonable enough. ( 1 and 2592000 )

discipline_block<:>Integer<:>0<:>The vars "discipline_block" and "discipline_block_ban_ttl"\nwill configure if this behavior is done and for how long\nto set the ban.  If you define "discipline_block 1"\nthe users who are sharing blocked files will be immediately\nbanned and killed. The default value is to not kill and\nban users who have blocked files. Keep in mind that this\nbehavior even would kick ELITE when they share suspect material\non the network. The mechanism of this is like follows\nA user shares a file which matches one of the patterns in the\nblock file. After that point every file he gets a flag "CRIMINAL"\nset which is queryable by "/raw 10050" or a "/msg operserv ...".\nA user with this flag set is handled like follows:\nEvery file he tries to share is logged via a mod+ notify.\nIf he finished sharing the user account is nuked and the\nnickname is banned. Note that this even affects MOD+.\nIf you want to protect your MOD+ by setting\ndiscipline_block_mod to 0 they won't get nuked but they\nstill have the CRIMINAL flag set.

discipline_block_ban_ttl<:>Integer<:>259200<:>See discipline_block.

discipline_block_mod<:>Integer<:>1<:>See discipline_block.

no_mod_annoying<:>Integer<:>0<:>When set to 1 mod+ are exempt from the notification of tag abuse.\nThis only affects mod+ who are on a server where "notify_user_abuse"\nis set to 1.

allow_share<:>Boolean<:>on<:>Controls whether or not clients are allowed to share files via the server.

auto_link<:>Boolean<:>off<:>When set to on, opennap-ng will automatically attempt to link to all\nservers listed in the servers file when it starts up\nfor the first time.

auto_register<:>Boolean<:>off<:>When set to on, the server will automatically register a nickname the\nfirst time it is used.  When off, nicknames will only be registered\nwhen the client explicitly requests it.  Also see\nregistered_only,\nregister_interval.

client_queue_length<:>Integer<:>102400<:>Sets the maximum number of bytes that can be queued for a client connection.\nIf this threshold is reached, it is assumed that the client is either dead,\nor the network link can not sustain the level of output, and the server\nautomatically closes down the client connection.  This is necessary so that\ndead clients don't consume all of the servers memory.

compression_level<:>Integer<:>1<:>The zlib compression level to use when compressing server to server\nconnections. 0 means no compression, 1 is least effort, 9 is best\ncompression. The higher the number, the more cpu it will consume.  Level 1\ncompresses text by about 50%, which is good enough for most applications.

eject_after<:>Integer<:>120<:>Specifies the number of seconds after initial login to the server for which\nthe client is exempt from being killed for not sharing enough when the\nserver is full (see eject_limit).  This should\nbe large enough to allow a client to start sharing files before getting\nkilled.

eject_leeches<:>Integer<:>0<:>When eject_when_full is set, kill leeches\nto allow another user to login, even if they are sharing over the\nrequired amount of files.

eject_when_full<:>Boolean<:>off<:>If set to on, the server will disconnect the longest connected client\nwhich is not sharing any files when the server is full (eg., when it has\nreached max_connections clients).  This\nallows room to be made for those clients which are sharing files.  Also see\neject_leeches, eject_limit_libsize,\nand eject_limit_files\nNote: mods+ and Friends are exempt and can always log in\neven if they are sharing no files.

file_count_threshold<:>Integer<:>5000<:>When a indexed file search token (one word) contains more than this number\nof matching files, the server will warn in its log output.  This gives the\nability to add this term to the list of filtered\nwords.

flood_commands<:>Integer<:>0<:>This variable, along with flood_time, allow for\nserver-side flood protection.  When set to a value greater than zero, the\nserver will not allow clients to issue more than this number of commands in\nflood_time seconds.  Any client attempting to send\ncommands faster than the allowed limit is throttled back.

flood_time<:>Integer<:>100<:>See flood_commands.

ghost_kill<:>Boolean<:>on<:>When enabled, opennap-ng will automatically kill an existing connection if the\nsame user logs in from the same IP address.

index_ignore_suffix<:>Boolean<:>true<:>Controls whether or not the filename extensions of shared files are included\nin the searchable index.\nAlso see index_path_depth.

index_path_depth<:>Integer<:>2<:>Controls how many levels of directory are included when adding shared files\nto the searchable index.  Often times the leading parts of the path are\ncompletely useless for searching (eg., C:\Program Files\My Music\Rock\)\nand just consumes a lot of memory.  This variable counts from the end\nof the path backwards, so the higher the value, the more of the beginning of\nthe path it will include.\nAlso see index_ignore_suffix.

irc_channels<:>Boolean<:>on<:>When set, opennap-ng requires all channel names to begin with\n# or &.

listen_addr<:>String<:>0.0.0.0<:>By default, the server will listen on all interfaces on the system.  You can\nforce it to listen only on a single interface by specifying the ip address\nof the interface in this option.

log_mode<:>Boolean<:>off<:>When set to on, opennap-ng will log changes in user levels to a file.

log_level<:>Bitflag<:>399<:>This is a bitflag word to determine what is is that you want logged.  That said,\nwhat that means is you look at the following list, and add together the values\nof the log levels you want to see in your server log (or output) and in the &LOG channel.\nServer  :    1\nClient  :    2\nLogin   :    4\nFiles   :    8\nShare   :   16\nSearch  :   32\nDebug   :   64\nError   :  128\nSecurity:  256\nChannel :  512\nStats   : 1024\nIf you want Server (1), Client (2), and Files (8), you set log_level to 1+2+8 = 11\nAnother example, Server, Client, Files, Share, Debug = 1 + 2 + 8 + 32 + 64 = 107

login_interval<:>Integer<:>0<:>Specifies how often (in seconds) clients from the same IP address are\nallowed to connect to the server.  This allows you to ignore clients which\nare reconnecting too fast.  A value of 0 disables the check.\nAlso see register_interval.

login_timeout<:>Integer<:>60<:>If a client has not completed the login process after this number of\nseconds, it will be disconnected.  This is to prevent malicious parties from\ntrying to open up many sockets to the server.

max_browse_result<:>Integer<:>500<:>Because of the limit imposed by client_queue_length, the number of files\nreturned by a browse command is limited to this number.  If this is too\nlarge, clients will be disconnected when they browse a user with many files.\nThere is also a consideration of bandwidth, a high browse limit imposes a\nlarge amount of uplink bandwidth.  Mod+ are exempt from this limit, however\nthey are still limited by the max_shared value.

max_channel_length<:>Integer<:>32<:>Specifies the max number of characters allowed in a channel name.

max_client_string<:>Integer<:>32<:>Specifies the max number of characters allowed in the client version string.

max_clones<:>Integer<:>0<:>When set to a value greater than 0, the server will only allow this many\nconnections from the same ip address.  Also see\nlogin_interval.

max_command_length<:>Integer<:>2048<:>When set to a value greater than 0, the server will disconnect any client\nthat sends a command longer than this value.  Clients that trigger this are\neither attempting to flood the server or are out of sync.

max_connections<:>Integer<:>0<:>When set to a value greater than 0, the server will only allow this many\nclients to log into the server.

max_new_users_per_minute<:>Integer<:>0<:>Maximum number of new users which are able to login per minute\nright after a serverstart. This is to avoid splits and timeouts\ndue to the fact that 2000 users who want to connect to the\nfreshly advertised server simultaneously produce a pretty nice\nbandwidth peak. Default value is 0. If set to 0 then no checking\non the user/time ratio takes place. A good value for DSL-lines\nis 90 users per minute.

max_hotlist<:>Integer<:>32<:>When set to a value greater than 0, the server will only allow each user to\nhave this many entries on their hotlist.

max_ignore<:>Integer<:>32<:>When set to a value greater than 0, this server will only allow each user to\nhave this many entries on their ignore list.

max_nick_length<:>Integer<:>19<:>If set to a value greater than 0, this specifies the max number of\ncharacters allowed in a nickname.

max_reason<:>Integer<:>96<:>If set to a value greater than 0, this specifies the max number of\ncharacters allowed in the "reason" strings for such commands as ban, kick\nand kill.

max_results<:>Integer<:>100<:>If set to a value greater than 0, this specifies the max number of search\nresults that are returned to a client.

max_searches<:>Integer<:>3<:>Specifies the maximum number of pending searches a user is allowed to have.\nOnce this threshold is reached, no more searches can be issued until one of\nthe others has completed.

max_shared<:>Integer<:>5000<:>If set to a value greater than 0, this specifies the max number of files\nthat any client may share.  This also affects the maximum number of browse\nresults for mod+ as they are exempt from the normal max_browse_result

max_time_delta<:>Integer<:>90<:>Specifies the maximum number of seconds of difference in clock time between\ntwo servers in order for them to be able to link.  Note that if this value\nis set too large, users can gain ops in channels even if they were not the\nfirst user to join the channel.\n\nA value of 0 will turn off this check completely.

max_topic<:>Integer<:>64<:>If set to a value greater than 0, this specifies the max number of\ncharacters allowed in a channel topic.

max_user_channels<:>Integer<:>5<:>If set to a value greater than 0, this specifies the max number of channels\na user is allowed to join.

nick_expire<:>Integer<:>2678400<:>Specifies the time in seconds of after which unused accounts are expired and\nreturned to the pool of available nicknames.

ping_interval<:>Integer<:>600<:>Specifies the interval (in seconds) of how often to sping peer (linked) servers.

register_interval<:>Integer<:>0<:>Specifices how often (in seconds) clients from the same IP address are\nallowed to register new nicknames.  This can be used in conjunction with\nauto_register to block web/clone clients which\nattempt to log in with random nicknames.

registered_only<:>Boolean<:>off<:>When set to on, the server only allows logins from registered\nclients.  Also see auto_register,\nregister_interval.

remote_browse<:>Boolean<:>on<:>This variable controls whether or not the server supports remote browsing\n(where the client being browsed is not on the same server).  In large\nnetworks, remote browsing can account for significant cross server traffic,\nincreasing lag.  Lopster or TekNap support´s for clients to directly browse\neachother outside of the servers, which is the recommended approach.\n\nNapigator support - you should only need to set stat_server_user and\nstat_server_pass at the minimum.  If you have used your correct DNS\nname for server_name above, then you don't need to use any of the\nreport_* variables. If opennap-ng has trouble detecting the proper values\nto send to napigator, then you should set the report_* variables\nappropriately.

report_ip<:>String<:>value of server_name<:>Sets the IP address this server listens on to be reported to Napigator.

report_name<:>String<:>value of server_name<:>Sets the name of the server reported to Napigator.

report_port<:>String<:>value of server_ports<:>Sets the TCP port this server listens on to be reported to Napigator.

restrict_registration<:>Boolean<:>off<:>If set, disallow the automatic registration of new nicknames by clients as\nthey log in for the first time.  The only way to create new nicknames\n(accounts) is then to use the administrator commands to register, or by\nediting the users file directly (when the server is\nnot running).  This option is typically used with the\nregistered_only option to run a private,\naccess-controlled server where users need accounts before they can log in.

search_timeout<:>Integer<:>180<:>When servers are linked, searches will be timed out if no response has been\nreceived after this many seconds.  This forces the server to send the final\nack to the client.

server_alias<:>String<:>none<:>Allows you to specify an alternate name by which the server refers to\nitself.  This is useful for connecting a "hidden" hub (routing-only) server,\nor if you just want to use a shortcut for the full dns name.

server_name<:>String<:>depends on hostname<:>Specifies the server's DNS name.

server_ports<:>Integer<:>server_ports<:>This option specifies a list of TCP ports which the server should listen on\nfor client connections.  Each port number should be separated by whitespace.

server_queue_length<:>Integer<:>1024000<:>Specifies the maximum number of bytes that can be queued for a server\nconnection before it is considered dead.

stat_click<:>Integer<:>60<:>Specifies how often (in seconds) the server should send updates about server\nstatistics (users/files/gigs) to the clients.

stats_port<:>Integer<:>8888<:>Specifies the TCP port on which the server should listen to reports stats.\nTypically used by Napigator.  If this\nport is set to -1, the server will not listen for stats reporting at\nall.

stat_server<:>String<:>stats.napigator.com<:>Sets the DNS/IP address of the Napigator server to report stats.\n\nAlso see\nreport_name,\nreport_ip,\nreport_port,\nstat_server_port,\nstat_server_user,\nstat_server_pass.

stat_server_pass<:>String<:>none<:>Sets the password for your napigator\naccount to list live server stats.

stat_server_user<:>String<:>none<:>Sets the username for your napigator account to list live server stats.

strict_channels<:>Boolean<:>off<:>When set to on, the server will only allow privileged users to create\nnew channels.

user_db_interval<:>Integer<:>1800<:>Specifies the interval in seconds of how often the server should write out\nits database files to disk.  This is important in case the server crashes\nprematurely, so that data loss is minimal.

usermode<:>String<:>ALL<:>Sets the default usermode for mods+ users.

warn_time_delta<:>Integer<:>30<:>If the clock on a remote server is more than this many seconds out of sync,\nopennap-ng will print a warning message. Also see max_time_delta.\n\nA value of 0 turns off the warning completely.

who_was_time<:>Integer<:>300<:>Specifies the number of seconds after a user logs out that information on\nthe client's ip address and server is kept in cache, so that mods+ may\nperform a whowas command. Note: this only\ncontrols how often the cache is purged, so some nicks may appear to be older\nthan this amount.

connection_hard_limit<:>Integer<:>Depends on OS<:>Sets the maximum number of file descriptors available to the server process.\nGenerally this is used to increase the default number availble.  Note that\nin order to increase the default maximum, the server needs to be run as\nroot (OpenNap-NG will drop privileges and run as the uid/gid specified\nby the configure arguments).

lock_memory<:>Boolean<:>off<:>On supported systems, this will cause the server to lock all of its memory\npages into real memory, thus avoiding swapping to disk.

max_data_size<:>Integer<:>Depends on OS<:>Sets the maximum amount of memory the process may consume.  Also see max_rss_size.

max_rss_size<:>Integer<:>Depends on OS<:>Sets the maxiumum amount of real memory a process is allowed to consume.\nAny excess will be swapped to disk.  Also see max_data_size.

allow_dynamic_ghosts<:>Integer<:>0<:>If a client was disconnected by his ISP and tries to relogin\nusing his new IP address he will receive the message\n"<nickname> is already active" for a certain ammount of time.\nThis is because ghosting is allowed for the same ip address\nin the first place and this is the default value of this var.If you want to allow that ghosting is allowed\nregardless of the ip address then set this value to 1.

stat_server_host<:>String<:>stat.napigator.com<:>A string representing the Napigator statistic server.

stat_server_port<:>Integer<:>8890<:>The port to which the string in stat_server_host may be connected to.

min_read<:>Integer<:>0<:>Allow a low-watermark log message when less than this many bytes are read from a server link.\nUseful for detecting slow servers.

block_winmx<:>Integer<:>0<:>A value of 0 does not block the WinMX client; a value of 1 leeches them;\na value of 2 kills them.

log_stdout<:>Boolean<:>on<:>A value of 'on' logs everything going to stdout; conversely for off.

level_to_set_flags<:>Integer<:>2<:>Minimum level to make users Friend status, where they can login\nany time regardless of max_connections or bans.

server_chunk<:>Integer<:>0<:>The size of each packet to be sent.

remote_config<:>Boolean<:>on<:>Set this to `off', if you wish to disable remote configuration of the server.\nOnly the rehash function will cause the\nexisting configuration to change; one of the server variables can be\nqueried or changed when in this mode.

notify_mod_block<:>Integer<:>0<:>You can distinguish the innocent user from the mean ones\nby broadcasting the files shared by users flagged as criminal\nvia notify_mod(). Any MOD+ on your server then will see all\nfiles shared by a suspect after and including the first\nfile which matches any pattern in the block file.\nThe default value is not to notify mod+ of the incidental files.Please note that the opennap.log ( if you use one ) still will\ncontain the information when you set this to 0.
