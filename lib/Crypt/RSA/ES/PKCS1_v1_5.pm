#!/usr/bin/perl -sw
##
## Crypt::RSA::ES::PKCS1_v1_5
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: PKCS1_v1_5.pm,v 1.3 2001/04/05 11:26:59 vipul Exp $

package Crypt::RSA::ES::PKCS1_v1_5;
use lib "/home/vipul/PERL/crypto/rsa/lib";
use strict;
use vars qw(@ISA $VERSION);
use Crypt::RSA::Errorhandler; 
use Crypt::RSA::DataFormat qw(bitsize os2ip i2osp generate_random_octet);
use Crypt::RSA::Primitives;
use Crypt::RSA::Debug      qw(debug);
use Math::Pari             qw(floor);
use Sort::Versions         qw(versioncmp);
use Carp;
@ISA = qw(Crypt::RSA::Errorhandler);
($VERSION)  = '$Revision: 1.3 $' =~ /\s(\d+\.\d+)\s/; 

sub new { 
    my ($class, %params) = @_;
    my $self = bless { primitives => new Crypt::RSA::Primitives, 
                       VERSION    => $VERSION,
                      }, $class;
    if ($params{Version}) { 
        # do versioning here.
    }
    return $self;
}


sub encrypt { 
    my ($self, %params) = @_; 
    my $key = $params{Key}; my $M = $params{Message};
    my $k = int(floor(bitsize($key->n)/8));  debug ("k: $k");
    my $em = $self->encode ($M, $k-1) || 
        return $self->error ($self->errstr, \$M, $key, \%params);
    my $m = os2ip ($em);
    my $c = $self->{primitives}->core_encrypt (Plaintext => $m, Key => $key);
    my $ec = i2osp ($c, $k);  debug ("ec: $ec");
    return $ec;
}    


sub decrypt { 
    my ($self, %params) = @_;
    my $key = $params{Key}; my $C = $params{Cyphertext}; 
    my $k = int(floor(bitsize($key->n)/8));  
    my $c = os2ip ($C);
    if (bitsize($c) > bitsize($key->n)) { 
        return $self->error ("Decryption error.", $key, \%params) 
    }
    my $m = $self->{primitives}->core_decrypt (Cyphertext => $c, Key => $key) || 
        return $self->error ("Decryption error.", $key, \%params);
    my $em = i2osp ($m, $k-1) || 
        return $self->error ("Decryption error.", $key, \%params);
    my $M = $self->decode ($em) || 
        return $self->error ("Decryption error.", $key, \%params);
    return $M;
} 


sub encode { 
    my ($self, $M, $emlen) = @_; 
    my $mlen = length($M);
    return $self->error ("Message too long.", \$M) if $mlen > $emlen-10;
    my ($PS, $pslen) = ("", 0);

    $pslen = $emlen-$mlen-2;
    $PS = generate_random_octet ($pslen);
    my $em = chr(2).$PS.chr(0).$M;
    return $em;
}


sub decode { 
    my ($self, $em) = @_; 

    return $self->error ("Decoding error.") if length($em) < 10;

    my ($chr0, $chr2) = (chr(0), chr(2));
    my ($ps, $M);
    unless ( ($ps, $M) = $em =~ /^$chr2(.{8,})$chr0(.*)$/s ) { 
        return $self->error ("Decoding error.");
    } 

    return $M;
}

sub version {
    my $self = shift;
    return $self->{VERSION};
}


1;

=head1 NAME

Crypt::RSA::ES::PKCS_v1_5 - PKCS1 v1.5 padded encryption with RSA. 

=head1 SYNOPSIS

    my $pkcs = new Crypt::RSA::ES::PKCS1_v1_5; 

    my $ct = $pkcs->encrypt( Key => $key, Message => $message ) || 
                die $pkcs->errstr; 

    my $pt = $pkcs->decrypt( Key => $key, Cyphertext => $ct )   || 
                die $pkcs->errstr; 

=head1 DESCRIPTION

This module implements PKCS v1.5 padded encryption scheme based on RSA.

=head1 METHODS

=head2 B<new()>

Constructor. 

=head2 B<version()>

Returns the version number of the module.

=head2 B<encrypt()>

Encrypts a string with a public key and returns the encrypted string
on success. encrypt() takes a hash argument with the following
mandatory keys:

=over 4

=item B<Message>

A string to be encrypted. The length of this string should not exceed k-10
octets, where k is the octet length of the RSA modulus. If Message is
longer than k-10, the method will fail and set $self->errstr to "Message
too long."

=item B<Key>

Public key of the recipient, a Crypt::RSA::Key::Public object.

=back

=head2 B<decrypt()>

Decrypts cyphertext with a private key and returns plaintext on
success. $self->errstr is set to "Decryption Error." or appropriate
error on failure. decrypt() takes a hash argument with the following
mandatory keys:

=over 4

=item B<Cyphertext>

A string encrypted with encrypt(). The length of the cyphertext must be k
octets, where k is the length of the RSA modulus.

=item B<Key>

Private key of the receiver, a Crypt::RSA::Key::Private object.

=head1 ERROR HANDLING

See ERROR HANDLING in Crypt::RSA(3) manpage.

=head1 BIBLIOGRAPHY 

See BIBLIOGRAPHY in Crypt::RSA(3) manpage.

=head1 AUTHOR

Vipul Ved Prakash, E<lt>mail@vipul.netE<gt>

=head1 SEE ALSO 

Crypt::RSA(3), Crypt::RSA::Primitives(3), Crypt::RSA::Keys(3),
Crypt::RSA::SSA::PSS(3)

=cut


