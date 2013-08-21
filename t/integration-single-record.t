use strict;
use warnings;
use lib 'lib';

use Net::DNS::SPF::Expander;
use IO::All -utf8;

use Test::More tests => 7;
use Test::Exception;
use Test::Differences;

my $backup_file  = 't/etc/test_zonefile_single.bak';
my $new_file     = 't/etc/test_zonefile_single.new';
my @output_files = ( $backup_file, $new_file );
for my $deletion (@output_files) {
    if ( -e $deletion ) {
        lives_ok { unlink $deletion } "I am deleting $deletion";
    } else {
        ok( 1 == 1, "$deletion was already deleted" );
    }
}

my $file_to_expand = 't/etc/test_zonefile_single';

my $expander;
lives_ok {
    $expander = Net::DNS::SPF::Expander->new(
        input_file => $file_to_expand,
    );
}
"I can make a new expander";

my $string;
lives_ok { $string = $expander->write } "I can call write on my expander";

my $expected_file_content = <<EOM;
\$ORIGIN test_zone.com.

yo      CNAME   111.222.333.4.
mama    CNAME   222.333.444.5.

;@               SPF     "v=spf1 include:sendgrid.biz ~all"
;*               TXT     "v=spf1 include:sendgrid.biz ~all"
*    600    IN    TXT    "v=spf1 ip4:173.193.132.0/24 ip4:173.193.133.0/24 ip4:192.254.112.0/20 ip4:198.21.0.0/21 ip4:198.37.144.0/20 ip4:208.115.235.0/24 ip4:208.115.239.0/24 ip4:208.117.48.0/20 ip4:50.31.32.0/19 ip4:74.63.231.0/24 ip4:74.63.236.0/24 ip4:74.63.247.0/24 ~all"
*    600    IN    SPF    "v=spf1 ip4:173.193.132.0/24 ip4:173.193.133.0/24 ip4:192.254.112.0/20 ip4:198.21.0.0/21 ip4:198.37.144.0/20 ip4:208.115.235.0/24 ip4:208.115.239.0/24 ip4:208.117.48.0/20 ip4:50.31.32.0/19 ip4:74.63.231.0/24 ip4:74.63.236.0/24 ip4:74.63.247.0/24 ~all"
@    600    IN    TXT    "v=spf1 ip4:173.193.132.0/24 ip4:173.193.133.0/24 ip4:192.254.112.0/20 ip4:198.21.0.0/21 ip4:198.37.144.0/20 ip4:208.115.235.0/24 ip4:208.115.239.0/24 ip4:208.117.48.0/20 ip4:50.31.32.0/19 ip4:74.63.231.0/24 ip4:74.63.236.0/24 ip4:74.63.247.0/24 ~all"
@    600    IN    SPF    "v=spf1 ip4:173.193.132.0/24 ip4:173.193.133.0/24 ip4:192.254.112.0/20 ip4:198.21.0.0/21 ip4:198.37.144.0/20 ip4:208.115.235.0/24 ip4:208.115.239.0/24 ip4:208.117.48.0/20 ip4:50.31.32.0/19 ip4:74.63.231.0/24 ip4:74.63.236.0/24 ip4:74.63.247.0/24 ~all"

greasy  CNAME   333.444.555.6.
granny  CNAME   666.777.888.9.
EOM

ok( -e $_, "File $_ was created" ) for @output_files;

eq_or_diff( $string, $expected_file_content,
"The text of the new file is what I expected" );
