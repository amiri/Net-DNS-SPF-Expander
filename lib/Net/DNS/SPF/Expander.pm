package Net::DNS::SPF::Expander;

use Moose;
use IO::All -utf8;
use Net::DNS::ZoneFile;
use Net::DNS::Resolver;
use MooseX::Types::IO::All 'IO_All';
use List::AllUtils qw(sum any part first uniq);
use Scalar::Util ();

# ABSTRACT: Expands DNS SPF records, so you don't have to.
# The problem is that you only get 10 per SPF records,
# and recursions count against you. Your record won't
# validate.

has 'input_file' => (
    is       => 'ro',
    isa      => IO_All,
    required => 1,
    coerce   => 1,
);
has 'output_file' => (
    is         => 'ro',
    isa        => IO_All,
    lazy_build => 1,
    coerce     => 1,
);
has 'backup_file' => (
    is         => 'ro',
    isa        => IO_All,
    lazy_build => 1,
    coerce     => 1,

);
has 'parsed_file' => (
    is         => 'ro',
    isa        => 'Net::DNS::ZoneFile',
    lazy_build => 1,
);
has 'resource_records' => (
    is         => 'ro',
    isa        => 'Maybe[ArrayRef[Net::DNS::RR]]',
    lazy_build => 1,
);
has 'spf_records' => (
    is         => 'ro',
    isa        => 'Maybe[ArrayRef[Net::DNS::RR]]',
    lazy_build => 1,
);
has 'resolver' => (
    is         => 'ro',
    isa        => 'Net::DNS::Resolver',
    lazy_build => 1,
);

has 'to_expand' => (
    is      => 'ro',
    isa     => 'ArrayRef[RegexpRef]',
    default => sub {
        [ qr/^a:/, qr/^mx/, qr/^include/, qr/^redirect/, ];
    },
);

has 'to_copy' => (
    is      => 'ro',
    isa     => 'ArrayRef[RegexpRef]',
    default => sub {
        [ qr/v=spf1/, qr/^ip4/, qr/^ip6/, qr/^ptr/, qr/^exists/, ];
    },
);

has 'to_ignore' => (
    is      => 'ro',
    isa     => 'ArrayRef[RegexpRef]',
    default => sub {
        [ qr/^v=spf1/, qr/^(\??)all/, qr/^exp/, qr/^~all/ ];
    },
);

has 'expansions' => (
    is         => 'ro',
    isa        => 'HashRef',
    lazy_build => 1,
);

has 'lengths_of_expansions' => (
    is         => 'ro',
    isa        => 'HashRef',
    lazy_build => 1,
);

has 'maximum_record_length' => (
    is      => 'ro',
    isa     => 'Int',
    default => sub {
        256 - length('v=spf1 ') + length(' ~all');
    },
);

has 'ttl' => (
    is      => 'ro',
    isa     => 'Str',
    default => sub {
        '10M',;
    },
);

has 'record_class' => (
    is      => 'ro',
    isa     => 'Str',
    default => sub {
        'IN',;
    },
);

has 'origin' => (
    is         => 'ro',
    isa        => 'Str',
    lazy_build => 1,
);

sub _build_resolver {
    my $self = shift;
    return Net::DNS::Resolver->new( recurse => 1, );
}

sub _build_origin {
    my $self = shift;
    return $self->parsed_file->origin;
}

sub _build_expansions {
    my $self = shift;
    return $self->_expand;
}

sub _build_backup_file {
    my $self = shift;
    my $path = $self->input_file->filepath;
    my $name = $self->input_file->filename;
    return "${path}${name}.bak";

}

sub _build_output_file {
    my $self = shift;
    my $path = $self->input_file->filepath;
    my $name = $self->input_file->filename;
    return "${path}${name}.new";
}

sub _build_parsed_file {
    my $self = shift;
    my $path = $self->input_file->filepath;
    my $name = $self->input_file->filename;
    return Net::DNS::ZoneFile->new("${path}${name}");
}

sub _build_resource_records {
    my $self             = shift;
    my @resource_records = $self->parsed_file->read;
    return \@resource_records;
}

sub _build_spf_records {
    my $self = shift;

    # This is crude but correct: SPF records can be both TXT and SPF.
    my @spf_records =
      grep { $_->txtdata =~ /v=spf1/ }
      grep { $_->can('txtdata') } @{ $self->resource_records };
    return \@spf_records;
}

sub _build_lengths_of_expansions {
    my $self              = shift;
    my $expansions        = $self->expansions;
    my $length_per_domain = {};
    for my $domain ( keys %$expansions ) {
        my $record_string = join( ' ', @{ $expansions->{$domain}{elements} } );
        $length_per_domain->{$domain} = length($record_string);
    }
    return $length_per_domain;
}

sub _normalize_component {
    my ( $self, $component ) = @_;
    my $return = $component;
    $return =~ s/^.+?://g;
    return $return;
}

sub _perform_expansion {
    my ( $self, $component ) = @_;
    $component = $self->_normalize_component($component);
    my $packet = $self->resolver->search( $component, 'TXT', 'IN' );
    return unless ($packet) && $packet->isa('Net::DNS::Packet');
    my ($answer) = $packet->answer;
    return unless ($answer) && $answer->isa('Net::DNS::RR::TXT');
    my $data = $answer->txtdata;
    return $data;
}

sub _expand_spf_component {
    my ( $self, $component, $expansions ) = @_;

    $expansions ||= [];

    return unless $component;

    if ( scalar( split( ' ', $component ) ) > 1 ) {
        my @components = split( ' ', $component );
        for my $component (@components) {
            $self->_expand_spf_component( $component, $expansions );
        }
    }
    else {
        if ( ( any { $component =~ $_ } @{ $self->to_ignore } ) ) {
            return $component;
        }
        elsif ( ( any { $component =~ $_ } @{ $self->to_copy } ) ) {
            push @{$expansions}, $component;
        }
        elsif ( ( any { $component =~ $_ } @{ $self->to_expand } ) ) {
            my $new_component = $self->_perform_expansion($component);
            $self->_expand_spf_component( $new_component, $expansions );
        }
        else {
            return $component;
        }
    }
    return ( $component, $expansions );
}

sub _expand {
    my $self     = shift;
    my %spf_hash = ();
    for my $spf_record ( @{ $self->spf_records } ) {
        my @spf_components = split( ' ', $spf_record->txtdata );
        for my $spf_component (@spf_components) {
            my ( $comp, $expansions ) =
              $self->_expand_spf_component($spf_component);
            $spf_hash{ $spf_record->name }{$spf_component} = $expansions;
        }
        my $expansion_elements =
          $self->_extract_expansion_elements( $spf_hash{ $spf_record->name } );
        $spf_hash{ $spf_record->name }{elements} = $expansion_elements;
    }
    return \%spf_hash;
}

sub _extract_expansion_elements {
    my ( $self, $expansions ) = @_;
    my @elements = ();
    my @leading  = ();
    my @trailing = ();
  KEY: for my $key ( keys %$expansions ) {
        if ( any { $key =~ $_ } @{ $self->to_ignore } ) {
            next KEY;
        }
        if ( ref( $expansions->{$key} ) eq 'ARRAY' ) {
            for my $expansion ( @{ $expansions->{$key} } ) {
                push @elements, $expansion;
            }
        }
    }
    my @return = ( @leading, @elements, @trailing );
    return \@return;
}

sub new_spf_records {
    my $self       = shift;
    my $lengths    = $self->lengths_of_expansions;
    my $expansions = $self->expansions;

    my %new_spf_records = ();

    for my $domain ( keys %$lengths ) {
        my $new_records = [];

        # We need to make sure the SPF record is less than 256 chars,
        # including the spf version and trailing ~all.
        if ( $lengths->{$domain} > $self->maximum_record_length ) {
            $new_records =
              $self->new_records_from_partition( $domain,
                $expansions->{$domain}{elements} );
        }
        else {
            $new_records =
              $self->new_records_from_arrayref( $domain,
                $expansions->{$domain}{elements} );
        }
        $new_spf_records{$domain} = $new_records;
    }
    return \%new_spf_records;
}

sub new_records_from_arrayref {
    my ( $self, $domain, $expansions ) = @_;

    my @new_records = ();
    for my $type ( 'TXT', 'SPF' ) {
        push @new_records, new Net::DNS::RR(
            type    => $type,
            name    => $domain,
            class   => $self->record_class,
            ttl     => $self->ttl,
            txtdata => join( ' ', @$expansions ),
        );
    }
    return \@new_records;
}

sub new_records_from_partition {
    my ( $self, $domain, $elements ) = @_;
    my $record_string = join( ' ', @$elements );
    my $record_length = length($record_string);
    my $max_length    = $self->maximum_record_length;
    my $offset        = 0;
    my $result        = index( $record_string, ' ', $offset );
    my @space_indices = ();

    while ( $result != -1 ) {
        push @space_indices, $result if $result;
        $offset = $result + 1;
        $result = index( $record_string, ' ', $offset );
    }

    my $number_of_partitions =
      int( $record_length / $max_length ) +
      ( ( $record_length % $max_length ) ? 1 : 0 );

    my @partitions       = ();
    my $partition_offset = 0;

    for my $part ( 1 .. $number_of_partitions ) {
        my $split_point =
          first { $_ < $max_length * $part } reverse @space_indices;
        my $substring =
          substr( $record_string, $partition_offset, $split_point );
        push @partitions, [ split( ' ', $substring ) ];
        $partition_offset = $split_point;
    }

    my @return = ();

    for my $partition (@partitions) {
        my $result = $self->new_records_from_arrayref( $domain, $partition );
        push @return, $result;
    }
    return \@return;
}

sub _get_single_record_string {
    my ( $self, $domain, $record_set ) = @_;
    my $origin = $self->origin;

    #my $name           = $self->_normalize_record_name($domain);
    my @record_strings = ();

    for my $record (@$record_set) {

        #$record->name($name);
        $record->name($domain);
        $record->txtdata( 'v=spf1 ' . $record->txtdata . ' ~all' );

        #. "\n";
        push @record_strings,
          $self->_normalize_record_name( $record->string ) . "\n";
    }
    return \@record_strings;
}

sub _normalize_record_name {
    my ( $self, $record ) = @_;

    $record =~ /(.+?)\s/;
    my $original_name = $1;
    my $origin        = $self->origin;

    my $name;

    if ( $original_name =~ /^$origin(.?)$/ ) {
        $name = '@';
    }
    elsif ( $original_name =~ /^\.$/ ) {
        $name = '@';
    }
    elsif ( $original_name =~ /^\*/ ) {
        $name = '*';
    }
    else {
        $name = $original_name;
    }
    $record =~ s/\Q$original_name\E/$name/g;
    return $record;
}

sub _get_multiple_record_strings {
    my ( $self, $values ) = @_;
    my $origin = $self->origin;

    my @record_strings = ();

    my @containing_records = ();

    for my $type ( 'TXT', 'SPF' ) {
        my $i = 1;
        for my $value (@$values) {
            push @containing_records, new Net::DNS::RR(
                type    => $type,
                name    => "_spf$i.$origin",
                class   => $self->record_class,
                ttl     => $self->ttl,
                txtdata => $value,
            );
            $i++;
        }
    }

    @record_strings = map { $_->string . "\n" } @containing_records;
    return \@record_strings;
}

sub _get_master_record_strings {
    my ( $self, $values, $domains ) = @_;

    my $origin         = $self->origin;
    my @record_strings = ();

    my @containing_records = ();
    for my $type ( 'TXT', 'SPF' ) {
        for my $domain (@$domains) {

            #my $name = $self->_normalize_record_name($domain);
            push @containing_records, new Net::DNS::RR(
                type => $type,

                #name    => $name,
                name    => $domain,
                class   => $self->record_class,
                ttl     => $self->ttl,
                txtdata => 'v=spf1 '
                  . (
                    join( ' ',
                        ( map { "_spf$_.$origin" } ( 1 .. scalar(@$values) ) ) )
                  )
                  . ' ~all',
            );
        }
    }
    @record_strings =
      map { $self->_normalize_record_name( $_->string ) . "\n" }
      @containing_records;
    return \@record_strings;
}

sub _new_records_lines {
    my $self           = shift;
    my %new_records    = %{ $self->new_spf_records || {} };
    my @record_strings = ();

    # Make a list of the unique records in case we need it.
    my @autosplit = ();
    for my $domain ( keys %new_records ) {
        for my $record_set ( @{ $new_records{$domain} } ) {
            if ( ref($record_set) eq 'ARRAY' ) {
                for my $record (@$record_set) {
                    push @autosplit, $record->txtdata;
                }
            }
            else {
                push @autosplit, $record_set->txtdata;
            }
        }
    }
    @autosplit = uniq @autosplit;

    # If there are any autosplit SPF records, we just do that right away.
    # This test is kind of nasty.
    my $make_autosplit_records = grep {
        defined( ${ $new_records{$_} }[0] )
          && ref( ${ $new_records{$_} }[0] ) eq 'ARRAY'
    } keys %new_records;
    if ($make_autosplit_records) {
        my $master_record_strings =
          $self->_get_master_record_strings( \@autosplit,
            [ keys %new_records ] );
        my $record_strings = $self->_get_multiple_record_strings( \@autosplit );
        push @record_strings, @$master_record_strings;
        push @record_strings, @$record_strings;
    }
    else {
        for my $domain ( keys %new_records ) {
            my $record_string =
              $self->_get_single_record_string( $domain,
                $new_records{$domain} );
            push @record_strings, @$record_string;
        }
    }
    my @original_lines = $self->input_file->slurp;
    my @new_lines      = ();
    my @spf_indices;
    my $i = 0;
  LINE: for my $line (@original_lines) {
        if ( $line =~ /^[^;].+?v=spf1/ ) {
            push @spf_indices, $i;
            $line = ";" . $line;
        }
        push @new_lines, $line;
        $i++;
    }
    my @first_segment = @new_lines[ 0 .. $spf_indices[-1] ];
    my @last_segment  = @new_lines[ $spf_indices[-1] + 1 .. $#new_lines ];
    my @final_lines   = ( @first_segment, @record_strings, @last_segment );

    return \@final_lines;
}

sub write {
    my $self  = shift;
    my $lines = $self->_new_records_lines;
    my $path  = $self->input_file->filepath;
    my $name  = $self->input_file->filename;
    io( $self->backup_file )->print( $self->input_file->all );
    io( $self->output_file )->print(@$lines);
    return 1;
}

1;
