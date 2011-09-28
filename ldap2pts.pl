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

# initialize this at the start 
#%ldap_users = ldap_get_users();
#%ldap_groups = ldap_get_groups();
#%pts_users = pts_get_users();
#%pts_groups = pts_get_groups();

# sync
bulk_sync_users();

# this might have changed, do it again
#%ldap_users = ldap_get_users();

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
sub pts_get_users_by_id {
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
			printf "pts_get_users(): found %i users\n", scalar keys(%users);
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
	my @output = execute("$PTS listentries -g 2>/dev/null $PTS_OPTIONS");
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
		die "$PTS returned $?. Perhaps you don't have permission?";
	}
}

# accepts: pts name
# returns: 1 if we should ignore it, 0 if we shouldn't
sub pts_ignore {
	my ($match) = @_;
	if ($match =~ '^system:.+') {
		if ($debug) {
			printf "pts_ignore(): Ignoring PTS entry: %s\n", $match;
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
		printf "WARNING: User %s does not exist in PTS, so not adding to group %s\n", $user, $group;
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
	my ($name, $id, $owner) = @_;
	if ($id !~ s/^-.+//) {
		$id = "-$id";
	}

	if (!defined $owner or $owner eq '') {
		$owner = $c{'pts'}{'default_group_owner'};
	} else {
		$owner = $owner;
	}

	printf "Creating PTS group named %s with id %s and owner %s\n", $name, $id, $owner;

	pexecute("$PTS creategroup -name $name -id $id -owner $owner $PTS_OPTIONS");
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

	if ($u =~ $c{'ldap'}{'ignore'}) {
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
sub ldap_get_users_by_id {
	my ($search) = @_;
	my ($mesg, $name, $id);
	my %users;
	
	if ($verbose) {
		print "Getting list of all LDAP users\n";
	}

	$mesg = $ldap->search(
		base => $c{'ldap'}{'base'},
		filter => "(objectclass=posixAccount)",
		attrs => [ $c{'ldap'}{'attr'}{'user_id'}, $c{'ldap'}{'attr'}{'user_name'} ]
	);
	
	$mesg->code && die $mesg->error;

	if ($mesg->count() != 0) {
		for (my $i = 0; $i < $mesg->count(); $i++) {
			$name = $mesg->entry($i)->get_value($c{'ldap'}{'attr'}{'user_name'});
			$id = $mesg->entry($i)->get_value($c{'ldap'}{'attr'}{'user_id'});
			if (defined $name and $name ne '') {	
				$users{$id} = $name;
			} else {
				printf "Could not lookup LDAP user_name = %s and user_id = %s for entry %s\n", 
					$c{'ldap'}{'attr'}{'user_name'}, 
					$c{'ldap'}{'attr'}{'user_id'},
					$mesg->entry($i)->dn();
			}
		}
		if ($debug) {
			printf "ldap_get_users(): found %i users\n", $mesg->count();
		}
		return %users;
	} else {
		return 0;
	}
}

# accepts: nothing
# returns: hash of users keyed by gidnumber
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
			printf "ldap_get_groups(): found %i groups\n", $mesg->count();
		}
		return %groups;
	} else {
		return 0;
	}
}

# accepts: cn or gidnumber
# returns: array of members from attribute $c{'ldap'}{'attr'}{'member'} or 0
sub ldap_group_expand {
	my ($group) = @_;
	my $mesg;
	
	if ($debug) {
		printf "ldap_group_expand(): expanding LDAP group %s\n", $group;
	}

	$mesg = $ldap->search(
		base => $c{'ldap'}{'group_base'},
		filter => "(&(objectClass=bxAFSGroup)(|(cn=$group)(bxAFSGroupId=$group)))",
		attrs => [ $c{'ldap'}{'attr'}{'group_member'} ]
	);

	$mesg->code && die $mesg->error;

	my @members;
	if ($mesg->count() != 0) {
		foreach my $member ($mesg->entry(0)->get_value($c{'ldap'}{'attr'}{'group_member'})) {
			if (!ldap_user_ignore($member)) {
				# if group_member_is dn, DN is a special case, where it becomes the search base
			}
		}
		return @members;
	} else {
		return 0;
	}
}

sub ldap_group_owner {
	my ($group) = @_;
	my $mesg;
	
	if ($debug) {
		printf "ldap_group_owner(): looking for owner of LDAP group %s\n", $group;
	}

	$mesg = $ldap->search(
		base => $c{'ldap'}{'base'},
		filter => "(&(objectClass=$c{'ldap'}{'attr'}{'group_class'})(|(cn=$group)(bxAFSGroupId=$group)))",
		attrs => [ $c{'ldap'}{'attr'}{'group_owner'} ]
	);

	$mesg->code && die $mesg->error;

	if ($mesg->count() != 0) {
		my $owner = $mesg->entry(0)->get_value($c{'ldap'}{'attr'}{'group_owner'});
		if ($owner ne '') { 
			return $owner;
		} else {
			return 0;
		}
	} else {
		return 0;
	}
}

# accepts: ldap user as used for the owner/member attr
# returns: pts name, translated
sub ldap_user_to_pts_user {
	my ($ldap_username) = @_;
	
	my $mesg;

	if ($c{'ldap'}{'member_is'} eq 'dn') {
		# look up user_name by DN
		$mesg = $ldap->search(
			base => $ldap_username,
			filter => "(objectClass=$c{'ldap'}{'attr'}{'user_class'})",
			attrs => [ $c{'ldap'}{'attr'}{'user_name'} ]
		);
		if ($mesg->code == 32) {
			printf "WARNING: dn: %s does not exist!\n", $ldap_username;
			next;
		} else {
			$mesg->code && die $mesg->error . " $ldap_username";
		}

	} else {
		# lookup user name by attr
		$mesg = $ldap->search(
			base => $c{'ldap'}{'user_base'},
			filter => "(&($c{'ldap'}{'member_is'}=$ldap_username)(objectClass=$c{'ldap'}{'attr'}{'user_class'}))",
			attrs => [ $c{'ldap'}{'attr'}{'user_name'} ]
		);
		if ($mesg->code == 32) {
			printf "WARNING: %s = %s does not exist!\n", $c{'ldap'}{'attr'}{'user_name'}, $ldap_username;
			next;
		} else {
			$mesg->code && die $mesg->error;
		}

	}
	if ($mesg->count() != 0) {
		my $pts_username = $mesg->entry(0)->get_value($c{'ldap'}{'attr'}{'user_name'});
		if (defined $pts_username and $pts_username ne '') {
			return pts_translate_username($ldap_username);
		} else {
			return 0;
		}
	} else {
		printf "WARNING: Could not determine PTS name for LDAP user %s = %s in group %s\n", 
			$ldap_username;
	}
}

# accepts: username
# returns: translated pts username
sub pts_translate_username {
	my ($username) = @_;
	
	if ($debug) {
		printf "pts_translate_username(): Translating username %s", $username;
	}

	# these are the afs rules for going from krb5 to afs krb4
	$username =~ s/^host\/(.+?)\..+/rcmd.$1/;
	$username =~ s/\//./g;
	
	if ($debug) {
		printf " ... %s\n", $username;
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

	my %ldap_users_by_id = ldap_get_users_by_id();
	my %pts_users_by_id = pts_get_users_by_id();
	my %pts_groups_by_id = ldap_get_groups();

	# convert %pts_groups to be keyed by name instead of id
	my %pts_groups_by_name = ();
	foreach my $pts_group_id (keys %pts_groups_by_id) {
		$pts_groups_by_name{$pts_groups_by_id{$pts_group_id}} = $pts_group_id;
	}

	# translate ldap usernames to pts usernames
	foreach my $ldap_user_id (keys %ldap_users_by_id) {
		$ldap_users_by_id{$ldap_user_id} = pts_translate_username($ldap_users_by_id{$ldap_user_id});
	}

	# rename users with same IDs and create users that don't exist
	# also, deletes groups with same name so the user can be created
	foreach my $ldap_user_id (keys %ldap_users_by_id) {
		if ( defined $pts_users_by_id{$ldap_user_id} ) {
			if ($pts_users_by_id{$ldap_user_id} ne $ldap_users_by_id{$ldap_user_id}) {
				pts_rename($pts_users_by_id{$ldap_user_id}, $ldap_users_by_id{$ldap_user_id});
			}
		} else {
			if ( defined $pts_groups_by_name{$ldap_users_by_id{$ldap_user_id}} ) {
				if ($verbose >= 1) {
					printf "Group with same name as user %s already exists, deleting group.\n", $ldap_users_by_id{$ldap_user_id};
				}
				pts_delete($ldap_users_by_id{$ldap_user_id});
			}
			pts_createuser($ldap_users_by_id{$ldap_user_id}, $ldap_user_id);
		}
	}

# delete users from pts that no longer exist in ldap
	foreach $pts_user_id (keys %pts_users_by_id) {
		if ( ! pts_ignore($pts_users_by_id{$pts_user_id}) ) {
			if ( ! defined $ldap_users_by_id{$pts_user_id} ) {
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
			}
			foreach (@pts_users_remove) {
				pts_removeuser($pts_groups{$ldap_gidnumber}, $_);
			}
		} else {
			pts_creategroup($ldap_groups{$ldap_gidnumber}, $ldap_gidnumber, ldap_group_owner($ldap_gidnumber));
			foreach (ldap_group_expand($ldap_groups{$ldap_gidnumber})) {
					pts_adduser($ldap_groups{$ldap_gidnumber}, $_);
			}
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
