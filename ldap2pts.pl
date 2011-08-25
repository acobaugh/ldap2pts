#!/usr/bin/env perl

use strict;
use warnings;

use Getopt::Long;
use Net::LDAP;
use Config::General;

my $verbose = 0;
my $pretend = 0;
my $debug = 0;
my %opt = ();
Getopt::Long::Configure('bundling');
GetOptions(\%opt,
	'h|help',
	'config=s',
	'v|verbose' => \$verbose,
	'd|debug' => \$debug,
	'p|pretend' => \$pretend
);

my $conf;
if (defined $opt{'config'} and $opt{'config'} ne '') {
	$conf = new Config::General (
		-AutoTrue => 1,
		-MergeDuplicateOptions => 1,
		-MergeDuplicateBlocks => 1,
		-ConfigFile => $opt{'config'}
	);
} else {
	print "ERROR: Must specify --config <file>\n";
	exit 1;
}

# read the config file
my %c = $conf->getall;

# pts user and group variables
my (%pts_users, %pts_users_by_name, $pts_user_name, $pts_user_id, @pts_users_add, @pts_users_remove);
my (%pts_groups, %pts_groups_by_name, $pts_group_name, $pts_group_id, %pts_group_members);

# ldap user and group variables
my (%ldap_users, %ldap_groups, $ldap_gidnumber, $ldap_uidnumber, %ldap_group_members); 

# temporary test variables
my ($test_group_id, $test_user);

# find a suitable pts
# can be overriden with pts_set_executable()
my ($PTS) = grep { -x $_ } qw(/usr/bin/pts /opt/local/bin/pts /opt/bx/bin/pts);
$PTS ||= 'pts';

# let the config file override the location of pts
if (defined $c{'pts'}{'pts_command'}) {
	my $PTS = $c{'pts'}{'pts_command'};
}
my $PTS_OPTIONS = $c{'pts'}{'pts_options'};

# connect to ldap
if ($verbose) {
	printf "Connecting to LDAP server %s\n", $c{'ldap'}{'server'};
}
my $ldap = Net::LDAP->new($c{'ldap'}{'server'}) or die "$@";
$ldap->bind;

# sync
bulk_sync_users();
bulk_sync_groups();

# unbind
$ldap->unbind();

##
## PTS Functions
##

# accepts: group name or id
# returns: array of group members
sub pts_group_expand {
	my ($group) = @_;
	if (($group * 1) eq $group) {
		$group = "-$group";
	}
	if ($debug) {
		printf "pts_group_expand(): expanding pts group %s\n", $group;
	}
	my @output = execute("$PTS membership $group 2>/dev/null $PTS_OPTIONS");
	if ($? == 0) {
		shift @output;
		for (@output) {
			s/^\s*//; # remove leading spaces
			s/\s*$//; # remove lines with any spaces
		}
		return @output;
	} else {
		return 0;
	}
}

# accepts: group name
# returns: negated pts group id or 0 if the group doesn't exist
sub pts_group_id {
	my ($group) = @_;
	
	if ($debug) {
		printf "pts_group_id(): obtaining group id for %s\n", $group;
	}
	my ($output) = execute("$PTS examine $group 2>/dev/null $PTS_OPTIONS");
	
	if ($? == 0) {
		$output =~ s/.+id: -(.+?),.+//;
		return $1;
	} else {
		return 0;
	}
}

# accepts: user name
# returns: user id or 0 if the user doesn't exist
sub pts_user_id {
	my ($user) = @_;
	
	if ($debug) {
		printf "pts_user_id(): obtaining pts user id for %s\n", $user;
	}
	my ($output) = execute("$PTS examine $user 2>/dev/null $PTS_OPTIONS");

	if ($? == 0) {
		$output =~ s/.+id: (.+?),+//;
		return $1;
	} else {
		return 0;
	}
}

# accepts: nothing
# returns: hash of users, keyed off id
sub pts_get_users {
	if ($verbose) {
		print "Getting list of all pts users\n";
	}
	my @output = execute("$PTS listentries 2>/dev/null $PTS_OPTIONS");
	if ($? == 0) {
		my %users;
		shift @output;
		for (@output) {
			s/(.+?) +(.+?) .+//;
			$users{$2} = $1;
		}
		
		if ($debug) {
			printf "pts_get_users(): found %n users\n", keys(%users);
		}

		return %users;
	} else {
		die "$PTS returned $?. Perhaps you don't have permission?";
	}
}

# accepts: nothing
# returns: hash of groups, keyed by |id|
sub pts_get_groups {
	if ($verbose) {
		print "Getting list of all pts groups\n";
	}
	my @output = `$PTS listentries -g 2>/dev/null $PTS_OPTIONS`;
	if ($? == 0) {
		my %groups;
		shift @output;
		for (@output) {
			s/(.+?) +-(.+?) .+//;
			$groups{$2} = $1;
		}
		return %groups;
	} else {
		# this shouldn't happen
		print "$PTS listentries returned 0 entries\n";
	}
}

# accepts: pts name
# returns: 1 if we should ignore it, 0 if we shouldn't
sub pts_ignore {
	my ($match) = @_;
	if ($match =~ '^system:.+') {
		if ($verbose >= 1) {
			printf "Ignoring PTS entry: %s\n", $match;
		}
		return 1;
	} else {
		return 0;
	}
}

# accepts: old and new name 
# returns: nothing
sub pts_rename {
	my ($old, $new) = @_;
	printf "Renaming PTS entry from %s to %s\n", $old, $new;
	
	pexecute("$PTS rename $old $new $PTS_OPTIONS");
}

# accepts: user and group
# returns: nothing
sub pts_adduser {
	my ($group, $user) = @_;
	if (pts_user_id($user) > 0) {
		printf "Adding user %s to group %s\n", $user, $group;
		pexecute("$PTS adduser -user $user -group $group $PTS_OPTIONS");
	} elsif ($verbose) {
		printf "WARNING: User %s does not exist in PTS, so not adding to group %s", $user, $group;
	}
}

# accepts: user and group
# returns: nothing
sub pts_removeuser {
	my ($group, $user) = @_;
	printf "Removing user %s from group %s\n", $user, $group;

	pexecute("$PTS removeuser -user $user -group $group $PTS_OPTIONS");
}

# accepts: group and id 
# returns: nothing
sub pts_creategroup {
	my ($name, $id) = @_;
	if ($id !~ s/^-.+//) {
		$id = "-$id";
	}
	printf "Creating PTS group named %s with id %s\n", $name, $id;

	pexecute("$PTS creategroup -name $name -id $id $PTS_OPTIONS");
}

# accepts: name OR id to delete
# returns: nothing
sub pts_delete {
	my ($nameorid) = @_;
	printf "Deleting PTS entry with nameorid %s\n", $nameorid;
	
	pexecute("$PTS delete -nameorid $nameorid");
}

# accepts: name and id
# returns: nothing
sub pts_createuser {
	my ($name, $id) = @_;
	printf "Creating PTS user named %s with id %s\n", $name, $id;

	pexecute("$PTS createuser -name $name -id $id $PTS_OPTIONS");
}

##
## LDAP Functions
##

# accepts: ldap user name
# returns: 1 if we should ignore it, 0 if we shouldn't
sub ldap_user_ignore {
	my ($u) = @_;

	if ($u 
			eq 'K/M'
			or $u =~ 'afs/.+'
			or $u =~ 'kadmin/.+'
			or $u =~ 'krbtgt/.+'
	) { 
		if ($verbose >= 1) {
			printf "Ignoring LDAP user with uid %s\n", $u;
		}
		return 1; 
	}

	return 0;
}


# accepts: uid or uidnumber
# returns: uidnumber or 0
sub ldap_uidnumber {
	my ($search) = @_;
	if ($verbose >= 1) {
		printf "Searching for LDAP uidNumber for %s\n", $search;
	}
	my $mesg;
	$mesg = $ldap->search(
		base => $c{'ldap'}{'base'},
		filter => "(&(objectclass=posixAccount)(|(uidnumber=$search)(uid=$search)))",
		attrs => [ 'uidNumber' ]
	);
	$mesg->code && die $mesg->error;

	if ($mesg->count() != 0) {
		return $mesg->entry(0)->get_value('uidnumber');
	} else {
		return 0;
	}

}

# accepts: group name
# returns: gidnumber or 0
sub ldap_gidnumber {
	my ($search) = @_;
	if ($verbose >= 1) {
		printf "Searching for LDAP gidNumber for %s\n", $search;
	}
	
	my $mesg;
	$mesg = $ldap->search(
		base => $c{'ldap'}{'base'},
		filter => "(&(objectclass=bxAFSGroup)(cn=$search))",
		attrs => [ 'bxAFSGroupId' ]
	);
	$mesg->code && die $mesg->error;

	if ($mesg->count() != 0) {
		return $mesg->entry(0)->get_value('bxAFSGroupId');
	} else {
		return 0;
	}

}

# accepts: nothing
# returns: array of users keyed by uidnumber
sub ldap_get_users {
	my ($search) = @_;
	my ($mesg, $uid, $uidnumber);
	my %users;
	
	if ($verbose) {
		print "Getting list of all LDAP users\n";
	}

	$mesg = $ldap->search(
		base => $c{'ldap'}{'base'},
		filter => "(objectclass=posixAccount)",
		attrs => [ 'uidNumber', 'uid' ]
	);
	
	$mesg->code && die $mesg->error;

	if ($mesg->count() != 0) {
		for (my $i = 0; $i < $mesg->count(); $i++) {
			$uid = $mesg->entry($i)->get_value('uid');
			$uidnumber = $mesg->entry($i)->get_value('uidNumber');
		
			$users{$uidnumber} = $uid;
		}
		if ($debug) {
			printf "ldap_get_users(): found %n users\n", $mesg->count();
		}
		return %users;
	} else {
		return 0;
	}
}

# accepts: nothing
# returns: hash of users keyed by uidnumber
sub ldap_get_groups {
	my ($search) = @_;
	my ($mesg, $cn, $gidnumber);
	my %groups;

	if ($verbose) {
		print "Getting list of all LDAP groups\n";
	}

	$mesg = $ldap->search(
		base => $c{'ldap'}{'base'},
		filter => "(objectClass=bxAFSGroup)",
		attrs => [ 'bxAFSGroupId', 'cn' ]
	);
	
	$mesg->code && die $mesg->error;

	if ($mesg->count() != 0) {
		for (my $i = 0; $i < $mesg->count(); $i++) {
			$cn = $mesg->entry($i)->get_value('cn');
			$gidnumber = $mesg->entry($i)->get_value('bxAFSGroupId');
		
			$groups{$gidnumber} = $cn;
		}
		if ($debug) {
			printf "ldap_get_groups(): found %n groups\n", $mesg->count();
		}
		return %groups;
	} else {
		return 0;
	}
}

# accepts: cn or gidnumber
# returns: array of members (memberUid) or 0
sub ldap_group_expand {
	my ($group) = @_;
	my $mesg;
	
	if ($debug) {
		printf "ldap_group_expand(): expanding LDAP group %s\n", $group;
	}

	$mesg = $ldap->search(
		base => $c{'ldap'}{'base'},
		filter => "(&(objectClass=bxAFSGroup)(|(cn=$group)(bxAFSGroupId=$group)))",
		attrs => [ 'member' ]
	);
	
	$mesg->code && die $mesg->error;

## Use this block if using memberUid	
#	if ($mesg->count() != 0) {
#		return $mesg->entry(0)->get_value('member');
#	} else {
#		return 0;
#	}

## Use this block if using member, where member contains a DN
	my @members;
	if ($mesg->count() != 0) {
		foreach my $member ($mesg->entry(0)->get_value('member')) {
			$mesg = $ldap->search(
				base => "$member",
				filter => "(objectClass=*)",
				attrs => [ 'uid' ]
			);
		
			#$mesg->code && die $mesg->error;

			if ($mesg->count() != 0) {
				push @members, pts_translate_username($mesg->entry(0)->get_value('uid'));
			} else {
				printf "WARNING: Could not determine PTS name for %s, not adding to group %s\n", $member, $group;
			}
		}
		return @members;
	} else {
		return 0;
	}
}

# accepts: username
# returns: translated pts username
sub pts_translate_username {
	my ($username) = @_;
	
	if ($debug) {
		print "translate_username(): Translating username %s", $username;
	}
	
	$username =~ s/^host\/(.+?).bx.psu.edu/rcmd.$1/;
	$username =~ s/\//./g;
	
	if ($debug) {
		print " ..translated username to %s\n", $username;
	}

	return $username;
}

sub execute {
	my ($command) = @_;
	my (@output, $exit);

	if ($debug) {
		printf "execute(): %s\n", $command;
		@output = `$command`;
		$exit = $?;
		foreach (@output) {
			printf "\t%s", $_;
		}
	} else {
		@output = `$command`;
		$exit = $?
	}
	if ($exit != 0 ) {
		printf "ERROR: Command \"%s\" returned %s\n", $command, $exit;
	}
	return @output;
}

sub pexecute {
	my ($command) = @_;

	if (!$pretend) {
		execute($command);
	} else {
		printf "PRETEND: %s\n", $command;
	}
}

##
## Synchronize Users en masse
##
sub bulk_sync_users {
	if ($verbose) {
		print "= Synchronizing all users =\n\n";
	}

	%ldap_users = ldap_get_users();
	%pts_users = pts_get_users();
	%pts_groups = pts_get_groups();

	# convert %pts_groups to be keyed by name instead of id
	foreach $pts_group_id (keys %pts_groups) {
		$pts_group_name = $pts_groups{$pts_group_id};
		$pts_groups_by_name{$pts_group_name} = $pts_group_id;
	}

	# translate ldap usernames to pts usernames
	foreach $ldap_uidnumber (keys %ldap_users) {
		$ldap_users{$ldap_uidnumber} = pts_translate_username($ldap_users{$ldap_uidnumber});
	}

	# rename users with same IDs and create users that don't exist
	# also, deletes groups with same name so the user can be created
	foreach $ldap_uidnumber (keys %ldap_users) {
		if ( defined $pts_users{$ldap_uidnumber} ) {
			if ($pts_users{$ldap_uidnumber} ne $ldap_users{$ldap_uidnumber}) {
				pts_rename($pts_users{$ldap_uidnumber}, $ldap_users{$ldap_uidnumber});
			}
		} else {
			if ( defined $pts_groups_by_name{$ldap_users{$ldap_uidnumber}} ) {
				if ($verbose >= 1) {
					printf "Group with same name as user %s already exists, deleting group.\n", $ldap_users{$ldap_uidnumber};
				}
				pts_delete($ldap_users{$ldap_uidnumber});
			}
			pts_createuser($ldap_users{$ldap_uidnumber}, $ldap_uidnumber);
		}
	}

# delete users from pts that no longer exist in ldap
	foreach $pts_user_id (keys %pts_users) {
		if ( ! pts_ignore($pts_users{$pts_user_id}) ) {
			if ( ! defined $ldap_users{$pts_user_id} ) {
					pts_delete($pts_user_id);
			}
		}
	}
}

##
## Synchronize Groups en masse
##
sub bulk_sync_groups {
	if ($verbose) {
		print "= Synchronizing all groups =\n\n";
	}
	# we get these each time
	%ldap_groups = ldap_get_groups();
	%pts_groups = pts_get_groups();
	%pts_users = pts_get_users(); # get new list of users

# transform hash of users so it's keyed by name instead of id
	foreach $pts_user_id (keys %pts_users) {
		$pts_user_name = $pts_users{$pts_user_id};
		$pts_users_by_name{$pts_user_name} = $pts_user_id;
	}

# remove groups from %ldap_groups if there is a corresponding username in %pts_users_by_name
	foreach $test_group_id (keys %ldap_groups) {
			if ( defined $pts_users_by_name{$ldap_groups{$test_group_id}} ) {
				delete( $ldap_groups{$test_group_id} );
			}
	}

# rename groups with same IDs and create groups that don't exist
	foreach $ldap_gidnumber (keys %ldap_groups) {
		if ( defined $pts_groups{$ldap_gidnumber} ) {
			if ($pts_groups{$ldap_gidnumber} ne $ldap_groups{$ldap_gidnumber}) {
				pts_rename($pts_groups{$ldap_gidnumber}, $ldap_groups{$ldap_gidnumber});
			}
			# get hash of ldap group members keyed by member
			%ldap_group_members = ();
			foreach (ldap_group_expand($ldap_gidnumber)) {
				$ldap_group_members{$_} = 1;
			}
			# get hash of pts group members keyed by member
			%pts_group_members = ();
			foreach (pts_group_expand($ldap_gidnumber)) {
				$pts_group_members{$_} = 1;
			}
			# build array of users to add to group
			@pts_users_add = ();
			foreach $test_user (keys %ldap_group_members) {
				if ( ! defined $pts_group_members{$test_user} ) {
					push(@pts_users_add, $test_user);
				}
			}
			# build array of users to remove from group
			@pts_users_remove = ();
			foreach $test_user (keys %pts_group_members) {
				if ( ! defined $ldap_group_members{$test_user} ) {
					push(@pts_users_remove, $test_user);
				}
			}

			foreach (@pts_users_add) {
				pts_adduser($pts_groups{$ldap_gidnumber}, $_);
				print "\n";
			}
			foreach (@pts_users_remove) {
				pts_removeuser($pts_groups{$ldap_gidnumber}, $_);
				print "\n";
			}
		} else {
			pts_creategroup($ldap_groups{$ldap_gidnumber}, $ldap_gidnumber);
			foreach (ldap_group_expand($ldap_groups{$ldap_gidnumber})) {
					pts_adduser($ldap_groups{$ldap_gidnumber}, $_);
			}
			print "\n";
		}
	}

# delete users from pts that no longer exist in ldap
	foreach $pts_group_id (keys %pts_groups) {
		if ( ! pts_ignore($pts_groups{$pts_group_id}) ) {
			if ( ! defined $ldap_groups{$pts_group_id} ) {
				pts_delete($pts_groups{$pts_group_id});
			}
		}
	}
}

##
## main
##

