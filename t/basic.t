use strict;
use warnings;
use lib 'lib';

use Net::DNS::SPF::Expander;
use IO::All;
use Data::Printer;

use Test::More tests => 1;

my $file = 't/etc/test_zonefile';

my $expander = Net::DNS::SPF::Expander->new(input_file => $file);

my $expansions = $expander->expansions;
diag p $expansions;

ok(1==1);
