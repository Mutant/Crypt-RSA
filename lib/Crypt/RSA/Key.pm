#!/usr/bin/perl -sw
##
## Crypt::RSA::Keys
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: Key.pm,v 1.8 2001/04/07 12:46:18 vipul Exp $

package Crypt::RSA::Key; 
use lib "/home/vipul/PERL/crypto/rsa/lib";
use lib "/home/vipul/PERL/crypto/primes/lib";
use strict;
use vars qw(@ISA $VERSION);
use Crypt::RSA::Errorhandler;
use Crypt::Primes qw(rsaparams);
use Crypt::RSA::DataFormat qw(bitsize);
use Crypt::RSA::Key::Public; 
use Crypt::RSA::Key::Private; 
use Math::Pari qw(PARI Mod lift);
@ISA = qw(Crypt::RSA::Errorhandler);
use Data::Dumper;

($VERSION)  = '$Revision: 1.8 $' =~ /\s(\d+\.\d+)\s/; 

sub new { 
    return bless {}, shift;
}


sub generate {

    my ($self, %params) = @_; 

    my $key;
    unless ($params{q} && $params{p} && $params{e}) { 
        return $self->error ("Missing argument.") unless 
            $params{Size} && $params{Password} && $params{Identity};

        return $self->error ("Keysize too small.") if 
            $params{Size} < 48;

        return $self->error ("Odd keysize.") if 
            $params{Size} % 2; 

        my $size = int($params{Size}/2);  
        my $verbosity = $params{Verbosity} || 0;

        my $cbitsize = 0;
        while (!($cbitsize)) { 
            $key = rsaparams ( Size => $size, Verbosity => $verbosity );
            my $n = $$key{p} * $$key{q};
            $cbitsize = 1 if bitsize($n) == $params{Size}
        }
    } 

    my $pubkey = new Crypt::RSA::Key::Public; 
    my $prikey = new Crypt::RSA::Key::Private (Password => $params{Password});
    $pubkey->Identity ($params{Identity});
    $prikey->Identity ($params{Identity});

    $pubkey->e ($$key{e} || $params{e});
    $prikey->p ($$key{p} || $params{p});
    $prikey->q ($$key{q} || $params{q});

    $prikey->phi (($prikey->p - 1) * ($prikey->q - 1));
    my $m = Mod (1, $prikey->phi);

    $prikey->d (lift($m/$pubkey->e));
    $prikey->n ($prikey->p * $prikey->q);
    $pubkey->n ($prikey->n);

    return $self->error ("d is too small. Regenerate.") if
        bitsize($prikey->d) < 0.25 * bitsize($prikey->n);

    $$key{p} = 0; $$key{q} = 0; $$key{e} = 0; $m = 0;

    if ($params{Filename}) { 
        $pubkey->write ("$params{Filename}.public");
        $prikey->write ("$params{Filename}.private");
    }

    return ($pubkey, $prikey);

}


1;

=head1 NAME

Crypt::RSA::Key - RSA Key Pair Generator.

=head1 SYNOPSIS

    my $keychain = new Crypt::RSA::Key;
    my ($public, $private) = $keychain->generate ( 
                              Identity  => 'Lord Macbeth <macbeth@glamis.com>',
                              Size      => 2048,  
                              Password  => 'A day so foul & fair', 
                              Verbosity => 1,
                             );
    die $keychain->errstr() unless $public && $private;

=head1 DESCRIPTION

This module provides a method to generate an RSA key pair.

=head1 METHODS

=head2 new()

Constructor.  

=head2 generate()

Generates an RSA key of specified bitsize. generate() returns a list of
two elements, a Crypt::RSA::Key::Public object that holds the public part
of the key pair and a Crypt::RSA::Key::Private object that holds that
private part. On failure, it sets $self->errstr to appropriate error
string. generate() takes a hash argument with the following keys:

=over 4

=item B<Size>

Bitsize of the key to be generated. This should be an even integer > 48.
Bitsize is a mandatory argument.

=item B<Password>

String with which the private key will be encrypted. Password is a
mandatory argument.

=item B<Identity>

A string that identifies the owner of the key. This string usually takes
the form of a name and an email address. The identity is not bound to the
key with a signature. However, a future release or another module will
provide this facility. Identity is a mandatory argument.

=item B<Cipher>

The block cipher which is used for encrypting the private key. Defaults to
`Blowfish'. Cipher could be set to any value that works with Crypt::CBC(3)
and Tie::EncryptedHash(3).

=item B<Verbosity> 

When set to 1, generate() will draw a progress display on console.

=item B<Filename>

The generated key pair will be written to disk, in $Filename.public and
$Filename.private files, if this argument is provided. Disk writes can be
deferred by skipping this argument and achieved later with the write()
method of Crypt::RSA::Key::Public(3) and Crypt::RSA::Key::Private(3).

=head1 ERROR HANDLING

See B<ERROR HANDLING> in Crypt::RSA(3) manpage.

=head1 BUGS

There's an inefficiency in the way generate() ensures the key pair is
exactly Size bits long. This will be fixed in a future release.

=head1 AUTHOR

Vipul Ved Prakash, E<lt>mail@vipul.netE<gt>

=head1 SEE ALSO

Crypt::RSA(3), Crypt::RSA::Key::Public(3), Crypt::RSA::Key::Private(3), 
Crypt::Primes(3), Tie::EncryptedHash(3)

=cut


