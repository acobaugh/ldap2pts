# $Id$
#!/usr/bin/perl -w

use strict;

# change this to location of ldap2pts.pm
use lib '/afs/bx.psu.edu/service/ldap2pts/';
use ldap2pts;

# connect to ldap
ldap_connect("ldap://ldap.bx.psu.edu", "dc=bx,dc=psu,dc=edu");

# this sets options to be passed always to pts, such as -localauth
pts_set_options("");

# this explicitly sets pts executable path, rather than letting the 
# moduel search for it
#pts_set_executable(""\t\" pts");

# this tells the module to print the commands it will run 
# and display the output of each command
set_execute_verbose(1);

print "Synchronizing all users\n\n";
bulk_sync_users('');
print "\n\n";

print "Synchronizing all groups\n\n";
bulk_sync_groups('');
print "\n\n";

# NOTE: bulk_sync_[users|groups] can be passed 'pretend' to only tell
# you what it will do
