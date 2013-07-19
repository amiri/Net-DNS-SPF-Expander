package Net::DNS::SPF::Expander;

use Moose;
use Net::DNS::ZoneFile;
use Net::DNS::Resolver;
use MooseX::Types::IO::All 'IO_All';
use List::MoreUtils qw(any);
use Scalar::Util ();
use Data::Printer;

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
    is         => 'rw',
    isa        => 'HashRef',
    lazy_build => 1,
);

sub _build_resolver {
    my $self = shift;
    return Net::DNS::Resolver->new( recurse => 1, );
}

sub _build_expansions {
    my $self = shift;
    return $self->_expand;
}

sub _build_destination_file {
    my $self = shift;
    return $self->input_file;
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

sub write {
    my $self = shift;
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
    }
    return \%spf_hash;
}

1;
