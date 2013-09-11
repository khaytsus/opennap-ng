#!/usr/bin/perl -w
#
# This script checks the output of the kaenguru fork of opennap-ng 0.45
# for users who can't read ban messages ( mostly winMX though )
#
#
# Imagine 2000 users who are banned and of whom every second tries to 
# connect at least 3 times per minute for 24/7 ...
#
# Every connect/disconnect is about 200 bytes of bandwidth.
#
# So you have 3000 connects with 200 Bytes per minute.
#
# Or in other words: There are 600 k/min (or 10 k per sec) 
# of bandwidth lost just for rejecting users you don't want to have.
#
# This bandwidth would be sufficient for roughly 300 users
# you probably *want* to have.
#
# Another nice sideeffect is that winmx obviously stops
# autoconnect to a server which does not answer at all.
# In this way the server thrashing feature is stopped, too.
#
# In any case the lag of a peer server will be reduced when
# using this script as after a certain ammount of reconnects
# the source IP will be dropped at your firewall without any
# secondary traffic.
#
# This script does two things to your firewall:
# First it checks for and creates a chain named "denyall".
# ( you might configure the name of the chain later )
# This chain is up to "max_chain_entries" entries long.
#
# If the chain is not there the script ensures that this 
# chain will be created and that it's the first one to 
# be evaluated in your "INPUT" chain.
#
# After that a list of IP-Adresses is read which are never being
# DROPed at all to prevent DOS-Attacks.
#
# Then it starts to read the opennap logfile and parses the 
# "check_ban" logmessages. ( These are available in the kaenguru network
# version - so please join #kaenguru to obtain one )
# 
# After parsing the logfile the number of reconnects is taken in account
# to fire up an iptables command to drop all traffic from and to this
# IP-Adress which is mentioned in the "check_ban" message.
# This is done by doing a "iptables -I $DENYCHAIN --source $IPADDR -j DROP"
#
# If the length of the "denyall" chain reaches "max_drop_entries" the
# last IP address is deleted from the "denyall" chain".
#
# This script has to be run as root. Please do your own security check on this 
# script before even thinking of running it.
# 
# ##################################################################
# configuration follows:
# ##################################################################

# ##################################################################
# #### System specific stuff ( external commands used by this script )
# Where is your "tail" command located?
$TAIL="/usr/bin/tail";

# Where is your "iptables" command located?
$IPTABLES="/usr/sbin/iptables";

# #### Opennap specific stuff
# Where is your logfile of the opennap server located?
$LOGFILE="/var/log/opennap.log";

# Should wildcard bans be dropped also?
# Use with caution as a wildcard ban might quickly fill up 
# your chain and you might set the MAXENTRIES to higher values.
# ( in my testsetup 100 additional entries were quite sufficient )
# On the other hand the drop list revolves more quickly 
# thus causing reused ip addresses to be allowed sooner.
# 
# The Default value is 0 on this behalf.
$DROPWILDCARDBANS=1;


# Should "reconnecting too fast" also be concerned when developing rules
# for the firewall? The same consideration is for the banned users here.
# If the chain expires an ip address too quickly the effect is nearly 
# neglectable. If the chain is too long you might piss off users who
# really mean it man to connect to your network.
$CHECK_RECONNECT=1;

# After how many reconnects should the firewall start to deny packets from this ip?
$RECONNECT_COUNT=5;

# By which factor should MAXENTRIES grow when having CHECK_RECONNECT=1?
$GROW_WHEN_RECONNECT=1.25;

# #################################################################
# #### The list of ip addresses which are exempt from the rules
$POSITIVE_IP=<<EOF;
0.0.0.0
127.0.0.1
194.25.2.129
192.53.103.103
192.53.103.104
192.168.101.254
192.168.100.254
192.168.100.1
EOF

# #################################################################
# #### Firewall specific stuff ... handle with care for not reaping security holes in
# #### your existing firewall (e.g. if you already have a chain named "denyall")
# What's the name of the "denyall" chain ( to prevent name collisions with other firewalls)
$CHAINNAME="denyall";

# How many entries are allowed in the deny chain?
# As the DROP action of the firewall uses the timeout of the clients IP stack
# to slow down the reconnection rate, this chain could be quite short.
# The last entry of the chain is purged, as soon as a new entry is 
# to be inserted.
$MAXENTRIES=300;
if ( $CHECK_RECONNECT ) {
	$MAXENTRIES=$MAXENTRIES * $GROW_WHEN_RECONNECT;
}

# What's the maximum number of connects which are allowed when banned?
# One should assume that 10 messages of the kind "You are banned:" 
# are sufficient information.
$MAXCONNECTS=5;

# Which action should apply to the connections from banned users?
# Possible actions are DROP and REJECT
# Attention: Some braindead clients just fire more reconnects per second
# when DENYRULE is set to REJECT. So you should probably leave this
# to the default which is "DROP".
$DENYRULE="DROP";

# Just a counter var ... 
$ALLTRAFFIC=0;

# ##################################################################
# This sub checks for existence and creates the chain to deny the 
# certain ip addresses. If the chain does not exist as a target 
# in the INPUT chain it will also be created.
sub check_and_create_chain() {
	my $iptablescmd;
	my $chainpresent;
	my $chaininserted;
	# First we check for the presence of the denyall chain ...
	$iptablescmd="$IPTABLES -L -nv |";
	$chainpresent=0;
	open(FH,$iptablescmd);
	while (<FH>) {
		if (/$CHAINNAME/) {
			$chainpresent=1;
		}
	}
	close FH;
	
	# Then the INPUT chain is checked for the presence of the denyall chain.
	$chaininserted=0;
	$iptablescmd="$IPTABLES -L INPUT -nv |";
	open(FH,$iptablescmd);
	while (<FH>) {
		if (/$CHAINNAME/) {
			$chaininserted=1;
		}
	}
	close FH;
	
	# If the denyall chain does not exist - create it.
	if ( ! $chainpresent ) {
		$iptablescmd="$IPTABLES -N $CHAINNAME";
		`$iptablescmd`;
	}
	
	# If the denyall chain is not in the INPUT chain - insert it.
	if ( ! $chaininserted ) {
		$iptablescmd="$IPTABLES -I INPUT -j $CHAINNAME";
		`$iptablescmd`;
	}
	
};


# ##################################################################
# This sub checks for the existence of an entry in the denyall chain.
# If there are entries to be purged it will be done here.
sub check_and_create_entry {
	my $iptablescmd;
	my $entries;
	my $hasentry;
	my $ipaddr;
	my $fill;
	my $pkts;
	my $bytes;
	my $rulenum;
	my $alreadydropped;
	
	$ipaddr=$_[0];
	
	# Check the ip address against the positive list
	# and exit without any action.
	if ( $POSITIVE_IP =~ m/$ipaddr/ ) {
		printf "$ipaddr is an exempt address. No action taken\n";
		return
	}
	
	# List of the entries in the chain $CHAINNAME
	$iptablescmd="$IPTABLES -L $CHAINNAME --line-numbers -nvx |";
	
	open(FH, $iptablescmd);
	$entries=0;
	$hasentry=0;
	
	# Initialize the statistics
	$sumpkts=0;
	$sumbytes=0;
	
	$alreadydropped=0;
	
	while (<FH>) {
		if (/^[0-9]/) {
			($rulenum, $pkts,$bytes,$fill,$fill,$fill,$fill,$fill,$target)=split;
			$sumpkts+=$pkts;
			$sumbytes+=$bytes;
			$entries++;
			if ( "$target" eq "$ipaddr") { 
				$alreadydropped=1;
			}
		}
	}
	close FH;
	
	if ($alreadydropped ) { 
		printf "$ipaddr is already in the $CHAINNAME chain!\n";
		return 
	}
	
	# Assume that every packet has 200 Bytes as overhead.
	# This is just a rough assumtion as a banned user 
	# will get a message stating that he is banned.
	# As the firewall silently drops the request the message ist not sent.
	# In addition to that this assumption does not take account that
	# the reconnect frequency is slowed down by dropping packets.
	# The real figures should by considerably higher.
	$prevented=$sumpkts*200;

	# The last entry of the chain is purged when the chain is longer than $MAXENTRIES
	if ($entries >= $MAXENTRIES) {
		if ( $ALLTRAFFIC==0 ) {
			$ALLTRAFFIC=$prevented + ( $pkts * 200 );
		} else {
			$ALLTRAFFIC+=( $pkts * 200 );
		};
		printf "Purging entry $MAXENTRIES\n";
		$iptablescmd="$IPTABLES -D $CHAINNAME $MAXENTRIES";
		`$iptablescmd`;
	}
	
	# and finally insert the new chain entry into the chain ...
	$iptablescmd="$IPTABLES -I $CHAINNAME --source $ipaddr -j $DENYRULE";
	`$iptablescmd`;
	printf "DENYALL has $entries entries, blocked $sumpkts packets and $sumbytes bytes. This prevented $ALLTRAFFIC bytes of traffic.\n";
};


# ##################################################################
# This sub checks for violations of reconnect attempts
#
sub check_for_violation {
	my $ipaddr;
	$ipaddr=$_[0];
	
	if ( $rp = $byip{"$ipaddr"} ) {
		# If found then increase counter.
		$byip{"$ipaddr"}->{counter}++;
		printf "$ipaddr has counter " . $byip{"$ipaddr"}->{counter} . "\n";
	
	} else {
		# Initialize a new record ...
		# printf "Created a new record for $ipaddr\n";
		$byip{"$ipaddr"}={ "ipaddr" => $ipaddr, "counter" => 0 };
	}
	#finally check counter and return value ...
	
	return ( $byip{"$ipaddr"}->{counter} >= $RECONNECT_COUNT );
}


# ##################################################################
# This sub parses the logfile and calls the other subs accordingly.
#
sub parse_logfile() {
	my $tailcmd;
	my $fill0;
	my $cnick;
	my $target;
	my $ipaddr;
	my $conncnt;
	my $targetnick;
	my $targetip;
	$tailcmd=$TAIL . " -f " . $LOGFILE . " | ";
	open(STDIN, $tailcmd);
	while (<STDIN>) {
		if (/^check_ban:/) {
			# Break up the logfile lines according to the rules.
			($fill0,$cnick,$fill0,$target,$fill0,$fill0,$ipaddr,$fill0,$conncnt) = split;
			($targetnick,$targetip)=split(/!/,$target);
			#
			# Ensure the correct case of the nicks and the mask
			$targetnick=lc($targetnick);
			$cnick=lc($cnick);
			if ("$cnick" eq "$targetnick" || $DROPWILDCARDBANS ) {
				if ($conncnt >= $MAXCONNECTS) {
					# And now do something pretty for the eyes...
					printf "$cnick -> $targetnick from $ipaddr ($conncnt times)\n";

					# Ensure that the chains are set up properly ...
					check_and_create_chain();

					# Now pass the IP to the check_and_create()
					check_and_create_entry($ipaddr);
				}
			}
		} else {
			if (/is reconnecting too fast/ && $CHECK_RECONNECT) {
				# break up the logfile lines according to the rules ---
				($fill0, $ipaddr)=split;
				if ( check_for_violation($ipaddr) ) {
					check_and_create_chain();
					check_and_create_entry($ipaddr);
				}
			}
		}
		
		
	}
	close(STDIN);
};

# ##################################################################
parse_logfile();
