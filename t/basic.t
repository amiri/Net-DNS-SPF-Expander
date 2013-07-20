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
#my $length = $expander->lengths_of_expansions;
my $new_records = $expander->new_spf_records;
#diag p $expansions;
#diag p $length;
diag p $new_records;

ok(1==1);
#     *   {
#         ~all                      undef,
#         include:_spf.google.com   [
#             [0]  "ip4:216.239.32.0/19",
#             [1]  "ip4:64.233.160.0/19",
#             [2]  "ip4:66.249.80.0/20",
#             [3]  "ip4:72.14.192.0/18",
#             [4]  "ip4:209.85.128.0/17",
#             [5]  "ip4:66.102.0.0/20",
#             [6]  "ip4:74.125.0.0/16",
#             [7]  "ip4:64.18.0.0/20",
#             [8]  "ip4:207.126.144.0/20",
#             [9]  "ip4:173.194.0.0/16",
#             [10] "ip6:2001:4860:4000::/36",
#             [11] "ip6:2404:6800:4000::/36",
#             [12] "ip6:2607:f8b0:4000::/36",
#             [13] "ip6:2800:3f0:4000::/36",
#             [14] "ip6:2a00:1450:4000::/36",
#             [15] "ip6:2c0f:fb50:4000::/36"
#         ],
#         ip4:96.43.144.0/20        [
#             [0] "ip4:96.43.144.0/20"
#         ],
#         v=spf1                    undef
#     }
