#!/usr/bin/perl -sw
##
## Crypt::RSA::Key::Private 
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: Private.pm,v 1.7 2001/04/07 12:46:19 vipul Exp $

package Crypt::RSA::Key::Private;
use lib '../../../../lib', 'lib';
use strict; 
use vars qw($AUTOLOAD);
use Crypt::RSA;
use Tie::EncryptedHash; 
use Data::Dumper;
use Math::Pari qw(PARI pari2pv);
use Carp;

sub new { 

    my ($class, %params) = @_; 
    my $self    = { Version => $Crypt::RSA::Key::VERSION };
    my $cipher  = $params{Cipher} || "Blowfish"; 
    if ($params{Filename}) { 
        bless $self, $class;
        $self = $self->read (%params);
        return bless $self, $class; 
    } else { 
        $self->{private} = new Tie::EncryptedHash 
                            __password => $params{Password}, 
                            __cipher   => $cipher;
        bless $self, $class;
        $self->Identity ($params{Identity}) if $params{Identity};
        return $self;
    } 

} 


sub AUTOLOAD { 
    my ($self, $value) = @_;
    my $key = $AUTOLOAD; $key =~ s/.*:://;
    if ($key =~ /^(n|d|p|q|dp|dq|qinv|phi)$/) { 
        if (ref $value eq 'Math::Pari') { 
            $self->{private}{"_$key"} = pari2pv($value)
        } elsif ($value && !(ref $value)) { 
            if ($value =~ /^0x/) { 
                $self->{private}->{"_$key"} = 
                    pari2pv(Math::Pari::_hex_cvt($value));
            } else { $self->{private}{"_$key"} = $value } 
        }
        my $return  = $self->{private}{"_$key"} || "";
        $return = PARI("$return") if $return =~ /^\d+$/;
        return $return;
    } elsif ($key =~ /^Identity$/) { 
        $self->{$key} = $value if $value; 
        return $self->{$key};
    }
} 

sub hide { 

    my ($self) = @_; 
    my $private = $self->{private};
    delete $self->{private}{__password};

} 

sub reveal { 

    my ($self, %params) = @_; 
    $$self{private}{__password} = $params{Password};

}


sub DESTROY { 

    my $self = shift; 
    delete $$self{private}{__password}; 
    delete $$self{private};
    undef $self;

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
    open DISK, $params{Filename} || 
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
    my $private = new Tie::EncryptedHash; 
    %$private = %{$$self{private}};
    $self->{private} = $private;
    return $self;

}
    
1;

=head1 NAME

Crypt::RSA::Key::Private -- RSA Private Key Management.

=head1 SYNOPSIS

    $key = new Crypt::RSA::Private::Key (
                Identity => 'Lord Banquo <banquo@lochaber.com>',
                Password => 'The earth hath bubbles',
           );

    $key->hide ();

    $key->write  ( Filename => 'rsakeys/banquo.private'  );

    $akey = new Crypt::RSA::Private::Key (
                 Filename => 'rsakeys/banquo.private'
                );   

    $akey->reveal ( Password => 'The earth hath bubbles' );

=head1 DESCRIPTION

[coming soon]

=head1 AUTHOR

Vipul Ved Prakash, E<lt>mail@vipul.netE<gt>

=head1 SEE ALSO

Crypt::RSA::Key(3), Crypt::RSA::Public(3)

=cut


