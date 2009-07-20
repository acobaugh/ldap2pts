
package ldap2pts;

use strict;
use warnings;

use base 'Exporter';

use Net::LDAP;

our @EXPORT = (
	'pts_set_options',
	'pts_set_executable',
	'ldap_connect',
	'bulk_sync_users',
	'bulk_sync_groups',
	'set_execute_verbose'
);
=a
	'pts_group_expand',
	'pts_group_id',
	'pts_user_id',
	'pts_get_users',
	'pts_get_groups',
	'pts_ignore',
	'pts_rename',
	'pts_adduser',
	'pts_removeuser',
	'pts_creategroup',
	'pts_delete',
	'pts_createuser',
	'ldap_connect',
	'ldap_user_ignore',
	'ldap_uidnumber',
	'ldap_gidnumber',
	'ldap_get_users',
	'ldap_get_groups',
	'ldap_group_expand',
	'translate_username'
);
=cut

my ($ldap_base, $ldap_server, $ldap, $PTS_OPTIONS, $PTS);

my (%pts_users, %pts_users_by_name, $pts_user_name, $pts_user_id, @pts_users_add, @pts_users_remove);
my (%pts_groups, %pts_groups_by_name, $pts_group_name, $pts_group_id, %pts_group_members);

my (%ldap_users, %ldap_groups, $ldap_gidnumber, $ldap_uidnumber, %ldap_group_members); 

my ($test_group_id, $test_user);

my $execute_verbose = 0;
my $pretend = 0;

($PTS) = grep { -x $_ } qw(/usr/bin/pts /opt/local/bin/pts /opt/bx/bin/pts);
$PTS ||= 'pts';

##
## PTS Functions
##

# accepts: options to always pass to pts
# returns: nothing
sub pts_set_options {
	($PTS_OPTIONS) = @_;
}

# accepts: pts executable path
# returns: nothing
sub pts_set_executable {
	($PTS) = @_;
}

# accepts: group name or id
# returns: array of group members
sub pts_group_expand {
	my ($group) = @_;
	if (($group * 1) eq $group) {
		$group = "-$group";
	}
	my @output = `$PTS membership $group 2>/dev/null $PTS_OPTIONS`;
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
	my $output = `$PTS examine $group 2>/dev/null $PTS_OPTIONS`;
	
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
	my $output = `$PTS examine $user 2>/dev/null $PTS_OPTIONS`;

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
	my @output = `$PTS listentries 2>/dev/null $PTS_OPTIONS`;
	if ($? == 0) {
		my %users;
		shift @output;
		for (@output) {
			s/(.+?) +(.+?) .+//;
			$users{$2} = $1;
		}
		return %users;
	} else {
		print "no users found";
	}
}

# accepts: nothing
# returns: hash of groups, keyed by |id|
sub pts_get_groups {
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
		print "no groups found";
	}
}

# accepts: pts name
# returns: 1 if we should ignore it, 0 if we shouldn't
sub pts_ignore {
	my ($match) = @_;
	if ($match =~ '^system:.+') {
		printf "Ignoring PTS entry: %s\n", $match;
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
	if ($pretend != 1) {
		execute("$PTS rename $old $new $PTS_OPTIONS");
	}
}

# accepts: user and group
# returns: nothing
sub pts_adduser {
	my ($group, $user) = @_;
	if (pts_user_id($user) > 0) {
		printf "Adding user %s to group %s\n", $user, $group;
		if ($pretend != 1) {
			execute("$PTS adduser -user $user -group $group $PTS_OPTIONS");
		}
	} else {
		printf "User %s does not exist in PTS, so not adding to group %s", $user, $group;
	}
}

# accepts: user and group
# returns: nothing
sub pts_removeuser {
	my ($group, $user) = @_;
	printf "Removing user %s from group %s\n", $user, $group;
	if ($pretend != 1) {
		execute("$PTS removeuser -user $user -group $group $PTS_OPTIONS");
	}
}

# accepts: group and id 
# returns: nothing
sub pts_creategroup {
	my ($name, $id) = @_;
	if ($id !~ s/^-.+//) {
		$id = "-$id";
	}
	printf "Creating PTS group named %s with id %s\n", $name, $id;
	if ($pretend != 1) {
		execute("$PTS creategroup -name $name -id $id $PTS_OPTIONS");
	}
}

# accepts: name OR id to delete
# returns: nothing
sub pts_delete {
	my ($nameorid) = @_;
	printf "Deleting PTS entry with nameorid %s\n", $nameorid;
	if ($pretend != 1) {
		execute("$PTS delete -nameorid $nameorid");
	}
}

# accepts: name and id
# returns: nothing
sub pts_createuser {
	my ($name, $id) = @_;
	printf "Creating PTS user named %s with id %s\n", $name, $id;
	if ($pretend != 1) {
		execute("$PTS createuser -name $name -id $id $PTS_OPTIONS");
	}
}

##
## LDAP Functions
##

# accepts: ldap user name
# returns: 1 if we should ignore it, 0 if we shouldn't
sub ldap_user_ignore {
	my ($u) = @_;

	if ($u eq 'K/M') { return 1; }
	if ($u =~ 'afs/.+') { return 1; }
	if ($u =~ 'kadmin/.+') { return 1; }
	if ($u =~ 'krbtgt/.+') { return 1; }

	return 0;
}

# accepts: nothing
# returns: Net::LDAP object
sub ldap_connect {
	($ldap_server, $ldap_base) = @_;
	$ldap = Net::LDAP->new("$ldap_server") or die "$@";
	$ldap->bind;
}

# accepts: uid or uidnumber
# returns: uidnumber or 0
sub ldap_uidnumber {
	my ($search) = @_;
	my $mesg;
	$mesg = $ldap->search(
		base => "$ldap_base",
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
	my $mesg;
	$mesg = $ldap->search(
		base => "$ldap_base",
		filter => "(&(objectclass=posixGroup)(cn=$search))",
		attrs => [ 'gidNumber' ]
	);
	$mesg->code && die $mesg->error;

	if ($mesg->count() != 0) {
		return $mesg->entry(0)->get_value('gidnumber');
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

	$mesg = $ldap->search(
		base => "$ldap_base",
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

	$mesg = $ldap->search(
		base => "$ldap_base",
		filter => "(objectClass=posixGroup)",
		attrs => [ 'gidNumber', 'cn' ]
	);
	
	$mesg->code && die $mesg->error;

	if ($mesg->count() != 0) {
		for (my $i = 0; $i < $mesg->count(); $i++) {
			$cn = $mesg->entry($i)->get_value('cn');
			$gidnumber = $mesg->entry($i)->get_value('gidNumber');
		
			$groups{$gidnumber} = $cn;
		}
		return %groups;
	} else {
		return 0;
	}
}

# accepts: cn or gidnumber
# returns: array of members (memberUid) or 0
sub ldap_group_expand {
	my ($search) = @_;
	my $mesg;

	$mesg = $ldap->search(
		base => "$ldap_base",
		filter => "(&(objectClass=posixGroup)(|(cn=$search)(gidNumber=$search)))",
		attrs => [ 'memberUid' ]
	);
	
	$mesg->code && die $mesg->error;

	if ($mesg->count() != 0) {
		return $mesg->entry(0)->get_value('memberUid');
	} else {
		return 0;
	}
}

# accepts: username
# returns: translated pts username
sub translate_username {
	my ($username) = @_;
	
	$username =~ s/^host\/(.+?).bx.psu.edu/rcmd.$1/;
	$username =~ s/\//./g;

	return $username;
}

sub execute {
	my ($command) = @_;
	
	if ($execute_verbose == 1)	{
		printf "Executing: %s\n", $command;
		my @output = `$command`;
		foreach (@output) {
			printf "\t%s\n", $_;
		}
	} else {
		`$command`;
	}
}

sub set_execute_verbose {
	if ($_[0] == 1) {
		$execute_verbose = 1;
	} else {
		$execute_verbose = 0;
	}
}

##
## Synchronize Users en masse
##
sub bulk_sync_users {
	if ($_[0] eq 'pretend') {
		print "PRETENDING\n";
		$pretend = 1;
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
		$ldap_users{$ldap_uidnumber} = translate_username($ldap_users{$ldap_uidnumber});
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
				printf "Group with same name as user %s already exists, deleting group.\n", $ldap_users{$ldap_uidnumber};
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
	$pretend = 0;
}

##
## Synchronize Groups en masse
##
sub bulk_sync_groups {
	if ($_[0] eq 'pretend') {
		print "PRETENDING\n\n";
		$pretend = 1;
	}

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
	$pretend = 0;
}


END {
	$ldap->unbind();
}

1;
