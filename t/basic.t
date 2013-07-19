use strict;
use warnings;
use lib 'lib';

use Net::DNS::SPF::Expander;
use IO::All;

use Test::More tests => 1;


my $file = 't/etc/test_zonefile';

my $expander = Net::DNS::SPF::Expander->new(input_file => $file);

my $parsed = $expander->expand;

ok(1==1);
