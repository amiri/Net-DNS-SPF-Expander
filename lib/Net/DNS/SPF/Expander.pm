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
    is      => 'rw',
    isa     => 'HashRef',
    default => sub { {} },
);

sub _build_resolver {
    my $self = shift;
    return Net::DNS::Resolver->new(
        recurse => 1,
        #debug => 1,
    );
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
    my $self = shift;

    #warn p $self->parsed_file;
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

    #warn "Return for $component is $return";
    return $return;
}

sub _perform_expansion {
    my ( $self, $component ) = @_;

    #warn "My component in expansion is: ", p $component;
    $component = $self->_normalize_component($component);
    my $packet = $self->resolver->search( $component, 'TXT', 'IN' );
    my ($answer) = $packet->answer;

    #warn p $answer;
    #warn "Is my answer blessed? ", Scalar::Util::blessed($answer);
    my $data = $answer->txtdata;

    #warn "Data: $data";
    return $data;
}

sub _expand_spf_component {
    my ( $self, $component, $expansions ) = @_;
    warn "Expansions upon entering sub: ", p $expansions;
    $expansions ||= [];
    return unless $component;
    if ( scalar( split( ' ', $component ) ) > 1 ) {

        #warn "The number of components I split are "
        #. scalar( split( ' ', $component ) );
        #warn "In first if for $component";
        my @components = split( ' ', $component );
        for my $component (@components) {
            $self->_expand_spf_component( $component, $expansions );
        }
    }
    else {

        #warn "In else for $component";

        if ( ( any { $component =~ $_ } @{ $self->to_ignore } ) ) {
            return;
        }
        if ( ( any { $component =~ $_ } @{ $self->to_copy } ) ) {

            #warn "Pushing $component onto expansions";
            push @{$expansions}, $component;

            #warn "Expansions after pushing: ", p $expansions;

        }
        else {
            my $new_component = $self->_perform_expansion($component);
            $self->_expand_spf_component( $new_component, $expansions );
        }

#push @{$expansions}, $component if any { $component =~ $_ } @{ $self->to_ignore };
#push @{$expansions}, $component if any { $component =~ $_ } @{ $self->to_copy };
#$return->{$component} = $component
#if any { $component =~ $_ } @{ $self->to_ignore };
#$return->{$component} = $component
#if any { $component =~ $_ } @{ $self->to_copy };
    }
    warn "Expansions for $component before returning: ", p $expansions;
    return ( $component, $expansions );
}

sub expand {
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
    warn p %spf_hash;
}

1;
