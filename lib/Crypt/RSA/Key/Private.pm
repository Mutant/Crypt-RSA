#!/usr/bin/perl -sw
##
## Crypt::RSA::Key::Private 
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: Private.pm,v 1.12 2001/05/23 22:31:50 vipul Exp $

package Crypt::RSA::Key::Private;
use lib '../../../../lib', 'lib', '../lib';
use strict; 
use vars qw($AUTOLOAD $VERSION);
use Crypt::RSA::Errorhandler;
use Crypt::RSA;
use Tie::EncryptedHash; 
use Data::Dumper;
use Math::Pari qw(PARI pari2pv Mod isprime lcm lift);
use Carp;
use vars qw(@ISA);

($VERSION) = '$Revision: 1.12 $' =~ /\s(\d+\.\d+)\s/; 
@ISA       = qw(Crypt::RSA::Errorhandler);


sub new { 

    my ($class, %params) = @_; 
    my $self    = { Version => $Crypt::RSA::Key::VERSION };
    if ($params{Filename}) { 
        bless $self, $class;
        $self = $self->read (%params);
        return bless $self, $class; 
    } else { 
        bless $self, $class;
        $self->Identity ($params{Identity}) if $params{Identity};
        $self->Cipher   ($params{Cipher}||"Blowfish");
        $self->Password ($params{Password}) if $params{Password};
        return $self;
    } 

} 


sub AUTOLOAD { 

    my ($self, $value) = @_;
    my $key = $AUTOLOAD; $key =~ s/.*:://;
    if ($key =~ /^(e|n|d|p|q|dp|dq|u|phi)$/) { 
        if (ref $value eq 'Math::Pari') { 
            $self->{private}{"_$key"} = $value;
            $self->{Checked} = 0;
        } elsif ($value && !(ref $value)) { 
            if ($value =~ /^0x/) { 
                $self->{private}->{"_$key"} = 
                $self->{Checked} = 0;
                    Math::Pari::_hex_cvt($value);
            } else { $self->{private}{"_$key"} = PARI($value) } 
        }
        return $self->{private}{"_$key"} || 
               $self->{private_encrypted}{"_$key"} || 
               "";
    } elsif ($key =~ /^Identity|Cipher|Password$/) { 
        $self->{$key} = $value if $value; 
        return $self->{$key};
    } elsif ($key =~ /^Checked$/) { 
        my ($package) = caller();
        $self->{Checked} = $value if ($value && $package eq "Crypt::RSA::Key::Private") ;
        return $self->{Checked};
    }
} 


sub hide { 

    my ($self) = @_; 

    return undef unless $$self{Password};

    $self->{private_encrypted} = new Tie::EncryptedHash 
            __password => $self->{Password},
            __cipher   => $self->{Cipher};

    for (keys %{$$self{private}}) { 
        $$self{private_encrypted}{$_} = pari2pv($$self{private}{$_});
    }

    my $private = $self->{private_encrypted};
    delete $private->{__password};
    delete $$self{private};
    delete $$self{Password};

} 


sub reveal { 

    my ($self, %params) = @_; 
    $$self{Password} = $params{Password} if $params{Password};
    return undef unless $$self{Password};
    $$self{private_encrypted}{__password} = $params{Password};
    for (keys %{$$self{private_encrypted}}) { 
        $$self{private}{$_} = PARI($$self{private_encrypted}{$_});
    }
 
}


sub check { 

    my ($self) = @_;

    return 1 if $self->{Checked};

    return $self->error ("Incomplete key.") unless 
        ($self->n && $self->d) || ($self->n && $self->p && $self->q);

    if ($self->p && $self->q) { 
        return $self->error ("n is not p*q."  ) unless $self->n == $self->p * $self->q;
        return $self->error ("p is not prime.") unless isprime($self->p);
        return $self->error ("q is not prime.") unless isprime($self->q);
    }

    if ($self->e) { 
        # d * e == 1 mod lcm(p-1, q-1)
        my $k = lcm (($self->p -1), ($self->q -1));
        my $K = Mod (1, $k); my $KI = lift($K * $self->d * $self->e);
        return $self->error ("Bad `d'.") unless $KI == 1;
    }

    if ($self->dp) {
        # dp == d mod (p-1)
        return $self->error ("Bad `dp'.") unless $self->dp == $self->d % ($self->p - 1);
    }

    if ($self->dq) {
        # dq == d mod (q-1)
        return $self->error ("Bad `dq'.") unless $self->dq == $self->d % ($self->q - 1);
    }

    if ($self->u && $self->q && $self->p) { 
        my $m =  Mod (1,$self->q); $m = lift ($m / $self->p);
        return $self->error ("Bad `u'.") unless $self->u == $m;
    }

    $self->Checked(1);
    return 1;

}


sub DESTROY { 

    my $self = shift; 
    delete $$self{private_encrypted}{__password}; 
    delete $$self{private_encrypted};
    delete $$self{private};
    delete $$self{Password};
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
    $self->reveal(%params);
    return $self;
}


sub serialize { 

    my ($self, %params) = @_;
    if ($$self{private}) {   # this is an unencrypted key
        for (keys %{$$self{private}}) { 
            $$self{private}{$_} = pari2pv($$self{private}{$_});
        }
    }
    return Dumper $self; 

} 


sub deserialize { 

    my ($self, %params) = @_; 
    my $string = join'', @{$params{String}}; 
    $string =~ s/\$VAR1 =//;
    $self = eval $string;
    if ($$self{private}) { # the key is unencrypted 
        for (keys %{$$self{private}}) { 
            $$self{private}{$_} = PARI($$self{private}{$_});
        }
        return $self;
    }
    my $private = new Tie::EncryptedHash; 
    %$private = %{$$self{private_encrypted}};
    $self->{private_encrypted} = $private;
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


