#!/usr/bin/perl -sw
##
## Crypt::RSA::Key::Public
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: Public.pm,v 1.7 2001/06/11 13:41:56 vipul Exp $

package Crypt::RSA::Key::Public;
use lib '../../../lib', 'lib';
use strict; 
use vars qw($AUTOLOAD);
use Crypt::RSA;
use Carp;
use Data::Dumper;
use Crypt::RSA::Errorhandler;
use Math::Pari qw(PARI pari2pv);
use vars qw(@ISA);
@ISA = qw(Crypt::RSA::Errorhandler);

sub new { 

    my ($class, %params) = @_; 
    my $self    = { Version => $Crypt::RSA::Key::VERSION };
    if ($params{Filename}) { 
        bless $self, $class;
        $self = $self->read (%params);
        return bless $self, $class; 
    } else { 
        return bless $self, $class;
    } 

} 


sub AUTOLOAD { 
    my ($self, $value) = @_;
    my $key = $AUTOLOAD; $key =~ s/.*:://;
    if ($key =~ /^n|e$/) { 
        if (ref $value eq 'Math::Pari') { 
            $self->{$key} = pari2pv($value)
        } elsif ($value && !(ref $value)) { 
            if ($value =~ /^0x/) { 
                $self->{$key} = pari2pv(Math::Pari::_hex_cvt($value));
            } else { $self->{$key} = $value } 
        }
        my $return  = $self->{$key} || "";
        $return = PARI("$return") if $return =~ /^\d+$/;
        return $return;
    } elsif ($key =~ /^Identity$/) { 
        $self->{$key} = $value if $value;
        return $self->{$key};
    }
        
} 


sub DESTROY { 

    my $self = shift; 
    undef $self;

}


sub check { 

    my $self = shift;
    return $self->error ("Incomplete key.") unless $self->n && $self->e;
    return 1;

}


sub write { 

    my ($self, %params) = @_; 
    $self->hide();
    my $string = $self->serialize (%params); 
    open DISK, ">$params{Filename}" || 
        croak "Can't open $params{Filename} for writing.";
    print DISK $string;
    close DISK;

} 


sub read { 
    my ($self, %params) = @_;
    open DISK, $params{Filename} or
        croak "Can't open $params{Filename} to read.";
    my @key = <DISK>; 
    close DISK;
    $self = $self->deserialize (String => \@key);
    return $self;
}


sub serialize { 

    my ($self, %params) = @_;
    return Dumper $self; 

} 


sub deserialize { 

    my ($self, %params) = @_; 
    my $string = join'', @{$params{String}}; 
    $string =~ s/\$VAR1 =//;
    $self = eval $string;
    return $self;

}

    
1;

=head1 NAME

Crypt::RSA::Key::Public -- RSA Public Key Management.

=head1 SYNOPSIS

    $key = new Crypt::RSA::Key::Public; 
    $key->write ( Filename => 'rsakeys/banquo.public' );

    $akey = new Crypt::RSA::Public (
                Filename => 'rsakeys/banquo.public' 
            );


=head1 DESCRIPTION

[coming soon]

=head1 AUTHOR

Vipul Ved Prakash, E<lt>mail@vipul.netE<gt>

=head1 SEE ALSO

Crypt::RSA::Key(3), Crypt::RSA::Private(3)

=cut


