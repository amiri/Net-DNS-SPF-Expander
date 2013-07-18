#
#===============================================================================
#
#         FILE: basic.t
#
#  DESCRIPTION: 
#
#        FILES: ---
#         BUGS: ---
#        NOTES: ---
#       AUTHOR: YOUR NAME (), 
# ORGANIZATION: 
#      VERSION: 1.0
#      CREATED: 07/15/2013 03:33:28 PM
#     REVISION: ---
#===============================================================================

use strict;
use warnings;
use lib 'lib';
use Net::DNS::SPF::Expander;
use IO::All;

use Test::More tests => 1;                      # last test to print


my $file = 't/etc/test_zonefile';

my $expander = Net::DNS::SPF::Expander->new(input_file => $file);

my $parsed = $expander->expand->write;
ok(1==1);
