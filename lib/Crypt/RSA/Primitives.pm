#!/usr/bin/perl -sw
##
## Crypt::RSA::Primitives -- Cryptography and encoding primitives  
##                           used by Crypt::RSA.
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: Primitives.pm,v 1.8 2001/03/31 02:45:23 vipul Exp $

use lib "/home/vipul/PERL/crypto/rsa/lib";
package Crypt::RSA::Primitives; 
use strict;
use vars qw(@ISA);
use Crypt::RSA::Errorhandler;
use Crypt::RSA::Debug qw(debug);
use Math::Pari qw(PARI Mod lift);
use Carp;
@ISA = qw(Crypt::RSA::Errorhandler);

sub new { 
    return bless {}, shift; 
} 


sub core_encrypt {

    # procedure: 
    # c = (m ** e) mod n 

    my ($self, %params) = @_;
    my $key = $params{Key}; my $plaintext = $params{Plaintext};
    debug ("pt == $plaintext");
    return $self->error ("Numeric representation of plaintext is out of bound.", 
                          \$plaintext, $key) if $plaintext > $key->n;
    my $m = Mod ($plaintext, $key->n);
    my $c = lift ($m**$key->e);
    debug ("ct == $c");
    return $c;

}


sub core_decrypt {

    # procedure: 
    # p = (c ** d) mod n

    my ($self, %params) = @_;
    my $key = $params{Key}; 
    my $cyphertext = $params{Cyphertext};
    return $self->error ("Decryption error.") if $cyphertext > $key->n;
    my $m = Mod ($cyphertext, $key->n);
    my $p = lift ($m**$key->d);
    debug ("ct == $cyphertext");
    debug ("pt == $p");
    return $p;

}


sub core_sign { 

    my ($self, %params) = @_; 
    $params{Cyphertext} = $params{Message};
    return $self->core_decrypt (%params); 

} 


sub core_verify { 

    my ($self, %params) = @_; 
    $params{Plaintext} = $params{Signature};
    return $self->core_encrypt (%params); 

}


1;

=head1 NAME

Crypt::RSA::Primitives - RSA encryption, decryption, signature and verification primitives. 

=head1 SYNOPSIS

    my $prim = new Crypt::RSA::Primitives;
    my $ctxt = $prim->core_encrypt (Key => $key, Plaintext => $string); 
    my $ptxt = $prim->core_decrypt (Key => $key, Cyphertext => $ctxt);
    my $sign = $prim->core_sign    (Key => $key, Message => $string); 
    my $vrfy = $prim->core_verify  (Key => $key, Signature => $sig);

=head1 DESCRIPTION

This module implements RSA encryption, decryption, signature and
verfication primitives. These primitives should only be used in the
context of an encryption or signing scheme. See Crypt::RSA::ES::OAEP(3),
and Crypt::RSA::SS::PSS(3) for the implementation of two such schemes.

=head1 ERROR HANDLING

See B<ERROR HANDLING> in Crypt::RSA(3) manpage.

=head1 AUTHOR

Vipul Ved Prakash, E<lt>mail@vipul.netE<gt>

=head1 SEE ALSO 

Crypt::RSA(3), Crypt::RSA::Key(3), Crypt::RSA::ES::OAEP(3), 
Crypt::RSA::SS::PSS(3)

=cut


