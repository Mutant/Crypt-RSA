#!/usr/bin/perl -sw
##
## Crypt::RSA::EME::OAEP 
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: OAEP.pm,v 1.10 2001/03/12 04:50:58 vipul Exp $

use lib "/home/vipul/PERL/crypto/rsa/lib";
package Crypt::RSA::EME::OAEP; 
use strict;
use vars qw(@ISA);
use Crypt::RSA::Errorhandler; 
use Crypt::RSA::DataFormat qw(bitsize os2ip i2osp octet_xor generate_random_octet mgf1);
use Crypt::RSA::Primitives;
use Crypt::RSA::Debug qw(debug);
use Digest::SHA1 qw(sha1);
use Math::Pari qw(floor);
use Carp;
@ISA = qw(Crypt::RSA::Errorhandler);


sub new { 
    return bless { primitives => new Crypt::RSA::Primitives, 
                   P => "Crypt::RSA $Crypt::RSA::VERSION",
                   hlen => 20,
                 }, shift 
}


sub encrypt { 
    my ($self, %params) = @_; 
    my $key = $params{Key}; my $M = $params{Message};
    my $k = int(floor(bitsize($key->n)/8));  debug ("k: $k");
    my $em = $self->encode ($M, $self->{P}, $k-1) || 
        return $self->error ($self->errstr, \$M, $key, \%params);
    my $m = os2ip ($em);
    my $c = $self->{primitives}->core_encrypt ( Plaintext => $m, Key => $key );
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
    my $M = $self->decode ($em, $self->{P}) || 
        return $self->error ("Decryption error.", $key, \%params);
    return $M;
} 


sub encode { 
    my ($self, $M, $P, $emlen) = @_; 
    my $hlen = $$self{hlen};
    my $mlen = length($M);
    return $self->error ("Message too long.", \$P, \$M) if $mlen > $emlen-(2*$hlen)-1;
    my ($PS, $pslen) = ("", 0);
    if ($pslen = $emlen-(2*$hlen+1+$mlen)) { 
        $PS = chr(0)x$pslen;
    }
    my $phash = $self->hash ($P);
    my $db = $phash . $PS . chr(1) . $M; 
    my $seed = generate_random_octet ($hlen);
    my $dbmask = $self->mgf1 ($seed, $emlen-$hlen);
    my $maskeddb = octet_xor ($db, $dbmask);
    my $seedmask = $self->mgf1 ($maskeddb, $hlen);
    my $maskedseed = octet_xor ($seed, $seedmask);
    my $em = $maskedseed . $maskeddb;

    debug ("emlen == $emlen");
    debug ("M == $M [" . length($M) . "]"); 
    debug ("PS == $PS [$pslen]"); 
    debug ("phash == $phash [" . length($phash) . "]"); 
    debug ("seed == $seed [" . length($seed) . "]"); 
    debug ("seedmask == $seedmask [" . length($seedmask) . "]"); 
    debug ("db == $db [" . length($db) . "]"); 
    debug ("dbmask == $dbmask [" . length($dbmask) . "]"); 
    debug ("maskeddb == $maskeddb [" . length($maskeddb) . "]"); 
    debug ("em == $em [" . length($em) . "]"); 

    return $em;
}


sub decode { 
    my ($self, $em, $P) = @_; 
    my $hlen = $$self{hlen};

    return $self->error ("Decoding error.", \$P) if length($em) < 2*$hlen+1;
    my $maskedseed = substr $em, 0, $hlen; 
    my $maskeddb = substr $em, $hlen; 
    my $seedmask = $self->mgf1 ($maskeddb, $hlen);
    my $seed = octet_xor ($maskedseed, $seedmask);
    my $dbmask = $self->mgf1 ($seed, length($em) - $hlen);
    my $db = octet_xor ($maskeddb, $dbmask); 
    my $phash = $self->hash ($P); 

    debug ("em == $em [" . length($em) . "]"); 
    debug ("phash == $phash [" . length($phash) . "]"); 
    debug ("seed == $seed [" . length($seed) . "]"); 
    debug ("seedmask == $seedmask [" . length($seedmask) . "]"); 
    debug ("maskedseed == $maskedseed [" . length($maskedseed) . "]"); 
    debug ("db == $db [" . length($db) . "]"); 
    debug ("maskeddb == $maskeddb [" . length($maskeddb) . "]"); 
    debug ("dbmask == $dbmask [" . length($dbmask) . "]"); 

    my ($phashorig) = substr $db, 0, $hlen;
    return $self->error ("Decoding error.", \$P) unless $phashorig eq $phash; 
    $db = substr $db, $hlen;
    my ($chr0, $chr1) = (chr(0), chr(1));
    my ($ps, $m);
    debug ("db == $db [" . length($db) . "]"); 
    unless ( ($ps, undef, $m) = $db =~ /^($chr0*)($chr1)(.*)$/s ) { 
        return $self->error ("Decoding error.", \$P);
    } 

    return $m;
}


sub hash { 
    return sha1 (@_); 
}


sub mgf {
    return mgf1 (@_);
}


1;

=head1 NAME

Crypt::RSA::EME::OAEP - Plaintext-aware encryption with RSA. 

=head1 SYNOPSIS

    my $oaep = new Crypt::RSA::EME::OAEP; 

    my $ct = $oaep->encrypt (Key => $key, Message => $message) || 
                die $oaep->errstr; 

    my $pt = $oaep->decrypt (Key => $key, Cyphertext => $ct)   || 
                die $oaep->errstr; 

=head1 DESCRIPTION

This module implements "plaintext-aware encryption" with RSA.
Plaintext-aware means it's computationally infeasible to obtain full or
partial information about a message from a cyphertext, and computationally
infeasible to generate a valid cyphertext without knowing the
corresponding message. It's impossible to mount chosen cyphertext attacks
against this scheme. For more information on plaintext-aware encryption,
see [3], [9] & [13].

=head1 METHODS

=head2 B<new()>

Constructor. 

=head2 B<encrypt()>

Encrypts a string with a public key and returns the encrypted string
on success. encrypt() takes a hash argument with the following
mandatory keys:

=over 4

=item B<Message>

A string to be encrypted. The length of this string should not exceed k-42
octets, where k is the octet length of the RSA modulus. If Message is
longer than k-42, the method will fail and set $self->errstr to "Message
too long."

=item B<Key>

Public key of the recepient, a Crypt::RSA::Key::Public object.

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

Private key of the reciever, a Crypt::RSA::Key::Private object.

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


