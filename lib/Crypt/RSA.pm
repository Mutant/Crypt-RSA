#!/usr/bin/perl -sw
##
## Crypt::RSA - Pure-perl implementation of RSA encryption/signing
##              algorithms.
##
## Copyright (c) 2000, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: RSA.pm,v 1.34 2001/04/07 16:53:39 vipul Exp $

package Crypt::RSA;
use lib '/home/vipul/PERL/crypto/rsa/lib';
use lib '/home/vipul/PERL/crypto/armour/lib';
use strict;
use vars qw(@ISA $VERSION);
use Crypt::RSA::Errorhandler; 
use Crypt::RSA::Key;
use Crypt::RSA::ES::OAEP;
use Crypt::RSA::SS::PSS;
use Crypt::RSA::DataFormat qw(bitsize steak);
use Crypt::RSA::Debug qw(debug);
use Convert::ASCII::Armour;
use Carp;
use Data::Dumper;

@ISA = qw(Crypt::RSA::Errorhandler);
($VERSION) = '$Revision: 1.34 $' =~ /\s(\d+\.\d+)\s/; 

my %DEFAULTS = ( 
    'ES'    => { Scheme  => "Crypt::RSA::ES::OAEP",
                  Enoc    => 'n-42', # 42 octets less than size of n
                  Dnoc    => 'n-0', 
                },
    'SS'    => { Scheme  => "Crypt::RSA::SS::PSS",
                  Snoc    => '-1',   # infinite
                  Dnoc    => '-1'    # infinite
                },
);


sub new { 

    my ($class, %params) = @_;
    my %self = (%DEFAULTS, %params);

    my $es    = $self{ES}{Scheme};
    my $ss    = $self{SS}{Scheme};
       eval   " require $es"; 
       eval   " require $ss";
    $self{es} = eval "${es}->new()";
    $self{ss} = eval "${ss}->new()";

    $self{armour}   = new Convert::ASCII::Armour; 
    $self{keychain} = new Crypt::RSA::Key; 

    return bless \%self, $class; 

}


sub keygen { 

    my ($self, %params) = @_;

    my @keys;
    return (@keys = $self->{keychain}->generate (%params))
                  ? @keys 
                  : $self->error ($self->{keychain}->errstr);

} 


sub encrypt { 

    my ($self, %params)   = @_;
    my $plaintext         = $params{Message};
    my $key               = $params{Key}; 

    my $blocksize;
    my $k = ((bitsize ($key->n)) / 8); 
    if ($$self{ES}{Enoc} =~ /\-(\d+)/) { 
               $blocksize = $k - $1;
    }

    my $cyphertext;
    my @segments = steak ($plaintext, $blocksize);
    for (@segments) {
        $cyphertext .= $self->{es}->encrypt (Message => $_, Key => $key)
            || return $self->error ($self->{es}->errstr, \$key, \%params);
    }

    if ($params{Armour} || $params{Armor}) { 
        $cyphertext = $self->{armour}->armour ( 
                             Object   => "RSA ENCRYPTED MESSAGE", 
                             Headers  => { Scheme  => $self->{ES}->{Scheme}, 
                                           Version => $self->{es}->version()
                                         }, 
                             Content  => { Cyphertext => $cyphertext },
                             Compress => 1, 
                            );
    } 

    return $cyphertext;

}


sub decrypt { 

    my ($self , %params) = @_;
    my $cyphertext       = $params{Cyphertext};
    my $key              = $params{Key}; 

    if ($params{Armour} || $params{Armor}) { 
        my $decoded = $self->{armour}->unarmour ($cyphertext) ||
            return $self->error ($self->{armour}->errstr());
        $cyphertext = $$decoded{Content}{Cyphertext}
    }

    my $k = ((bitsize ($key->n)) / 8); 
    # should be replaced by compute_blocksize( $k );
    my $blocksize = $k;  

    my $plaintext;
    my @segments = steak ($cyphertext, $blocksize);
    for (@segments) {
        $plaintext .= $self->{es}->decrypt (Cyphertext=> $_, Key => $key)
            || return $self->error ($self->{es}->errstr, \$key, \%params);
    }

    return $plaintext;

}


sub sign { 

    my ($self, %params) = @_;
    my $signature = $self->{ss}->sign (%params) 
                 || return $self->error ($self->{ss}->errstr,
                        $params{Key}, \%params);

    if ($params{Armour} || $params{Armor}) { 
        $signature      = $self->{armour}->armour ( 
               Object   => "RSA SIGNATURE", 
               Headers  => { Scheme  => $self->{SS}->{Scheme}, 
                             Version => $self->{ss}->version() 
                           }, 
               Content  => { Signature => $signature },
        );
    }

    return $signature;

} 


sub verify { 

    my ($self, %params) = @_;

    if ($params{Armour} || $params{Armor}) { 
        my $decoded  = $self->{armour}->unarmour ($params{Signature}) ||
            return $self->error ($self->{armour}->errstr());
        $params{Signature} = $$decoded{Content}{Signature}
    }

    my $verify = $self->{ss}->verify (%params) || 
        return $self->error ($self->{ss}->errstr, $params{Key}, \%params);

    return $verify;

}


1; 


=head1 NAME

Crypt::RSA - RSA public-key cryptosystem.

=head1 VERSION

 $Revision: 1.34 $ (Beta)
 $Date: 2001/04/07 16:53:39 $

=head1 SYNOPSIS

    my $rsa = new Crypt::RSA; 

    my ($public, $private) = $rsa->keygen ( 
                      Identity  => 'Lord Macbeth <macbeth@glamis.com>',
                      Size      => 2048,  
                      Password  => 'A day so foul & fair', 
                      Verbosity => 1,
                    ) or die $rsa->errstr();

    my $cyphertext = $rsa->encrypt ( 
                       Message    => $message,
                       Key        => $public
                       Armour     => 1,
                    ) || die $rsa->errstr();

    my $plaintext = $rsa->decrypt ( 
                       Cyphertext => $message, 
                       Key        => $private 
                       Armour     => 1,
                    ) || die $rsa->errstr();

    my $signature = $rsa->sign ( 
                       Message    => $message, 
                       Key        => $private
                    ) || die $rsa->errstr();

    my $verify   = $rsa->verify (
                       Message    => $message, 
                       Signature  => $signature, 
                       Key        => $public
                    ) || die $rsa->errstr();


=head1 DESCRIPTION

Crypt::RSA is a pure-perl, cleanroom implementation of the RSA public-key
cryptosystem, written atop the blazingly fast number theory library PARI.
As far as possible, Crypt::RSA conforms with PKCS #1, RSA Cryptography
Specifications v2.1[13].

Crypt::RSA is structured as a bundle of modules that provide arbitrary
length key pair generation, plaintext-aware encryption (OAEP) and digital
signatures with appendix (PSS). Crypt::RSA provides a convenient,
scheme-independent interface to the other modules in the bundle.

=head1 WARNINGS

=over 4

=item ASN.1 encoded formats are not supported yet.

=item This is beta, and largely untested, software. Please use at your own risk!

=back

=head1 METHODS

=head2 B<new()>

Constructor.

=head2 B<keygen()>

keygen() is a synonym for Crypt::RSA::Key::generate(). See
Crypt::RSA::Key(3) manpage for usage details.

=head2 B<encrypt()>

encrypt() performs RSA encryption on a string of arbitrary length with a
public key using the encryption scheme bound to the object at creation.
The default scheme is OAEP, implemented in Crypt::RSA::ES::OAEP(3).
encrypt() returns cyphertext (a string) on success and a non-true value on
failure. It takes a hash as argument with following keys:

=over 4

=item B<Message>

An arbitrary length string to be encrypted.

=item B<Key>

Public key of the recipient, a Crypt::RSA::Key::Public object.

=item B<Armour>

An optional boolean parameter that causes encrypt() to encode the
cyphertext as a 6-bit clean ASCII message.

=back

=head2 B<decrypt()>

decrypt() performs RSA decryption with a private key using the encryption
scheme bound to the object at creation. The default scheme is OAEP,
implemented in Crypt::RSA::ES::OAEP(3). decrypt() returns plaintext on
success and a non-true value on failure. It takes a hash as argument with
following keys:

=over 4

=item B<Cyphertext>

Encrypted text or arbitrary length. 

=item B<Key>

Private key, a Crypt::RSA::Key::Private object.

=item B<Armour> 

Boolean parameter that specifies whether the Cyphertext is encoded in
6-bit ASCII.

=back

=head2 B<sign()>

sign() creates an RSA signature on a string with a private key using the
signature scheme bound to the object at creation. The default scheme is
PSS, implemented in Crypt::RSA::SS::PSS(3). sign() returns a signature on
success and a non-true value on failure. It takes a hash as argument
with following keys:

=over 4

=item B<Message>

A string to be signed. 

=item B<Key>

Private key of the sender, a Crypt::RSA::Key::Private object.

=item B<Armour>

An optional boolean parameter that causes sign() to encode the
signature as a 6-bit clean ASCII message.

=back

=head2 B<verify()>

verify() verifies an RSA signature with a public key using the signature
scheme bound to the object at creation. The default scheme is
PSS, implemented in Crypt::RSA::SS::PSS(3). verify() returns a true 
value on success and a non-true value on failure. It takes a hash as argument
with following keys:

=over 4 

=item B<Message>

The original signed message, a string of arbitrary length.

=item B<Key>

Public key of the signer, a Crypt::RSA::Key::Public object.

=item B<Sign> 

Signature computed with sign(), a string.

=item B<Armour>

Boolean parameter that specifies whether the Signature is encoded in
6-bit ASCII.

=back

=head1 MODULES

Apart from Crypt::RSA, the following modules are intended for application
developer and end-user consumption:

=over 4

=item B<Crypt::RSA::Key>

RSA key pair generator.

=item B<Crypt::RSA::Key::Public>

RSA Public Key Management.

=item B<Crypt::RSA::Key::Private>

RSA Private Key Management.

=item B<Crypt::RSA::ES::OAEP>

Plaintext-aware encryption with RSA.

=item B<Crypt::RSA::SS::PSS>

Probabilistic Signature Scheme based on RSA.

=item B<Crypt::RSA::ES::PKCS1v15>

PKCS #1 v1.5 encryption scheme. 

=item B<Crypt::RSA::SS::PKCS1v15>

PKCS #1 v1.5 signature scheme. 

=back

=head1 ERROR HANDLING

All modules in the Crypt::RSA bundle use a common error handling method.
When a method fails it returns a non-true value and sets $self->errstr
to a string that explains the reason for the error. Private keys and
plaintext representations passed to the method in question are wiped
from memory.

=head1 AUTHOR

Vipul Ved Prakash, E<lt>mail@vipul.netE<gt>

=head1 ACKNOWLEDGEMENTS

Thanks to Ilya Zakharevich for answering even the goofiest of my questions
regarding Math::Pari with unwavering patience. Shizukesa on #perl for
clueing me into the error handling method used in this module and a-mused
for good advice.

=head1 LICENSE 

Copyright (c) 2000-2001, Vipul Ved Prakash. All rights reserved. This code
is free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=head1 SEE ALSO

Crypt::RSA::Primitives(3), Crypt::RSA::DataFormat(3),
Crypt::RSA::Errorhandler(3), Crypt::RSA::Debug(3), Crypt::Primes(3),
Crypt::Random(3), Crypt::CBC(3), Crypt::Blowfish(3),
Tie::EncryptedHash(3), Convert::ASCII::Armour(3), Math::Pari(3),
crypt-rsa-interoperability(3), crypt-rsa-interoperability-table(3).

=head1 MAILING LIST

pac@lists.vipul.net is a mailing list for discussing development of
asymmetric cryptography modules in perl. Please send Crypt::RSA related
communications directly to the list address. Subscription interface for
pac is at http://lists.vipul.net/mailman/listinfo/pac/

=head1 BIBLIOGRAPHY

(Chronologically sorted.)

=over 4

=item 1 B<R. Rivest, A. Shamir, L. Aldeman.> A Method for Obtaining Digital Signatures and Public-Key Cryptosystems (1978).

=item 2 B<U. Maurer.> Fast Generation of Prime Numbers and Secure Public-Key Cryptographic Parameters (1994).

=item 3 B<M. Bellare, P. Rogaway.> Optimal Asymmetric Encryption - How to Encrypt with RSA (1995).

=item 4 B<M. Bellare, P. Rogaway.> The Exact Security of Digital Signatures - How to sign with RSA and Rabin (1996).

=item 5 B<B. Schneier.> Applied Cryptography, Second Edition (1996).

=item 6 B<A. Menezes, P. Oorschot, S. Vanstone.> Handbook of Applied Cryptography (1997).

=item 7 B<D. Boneh.> Twenty Years of Attacks on the RSA Cryptosystem (1998).

=item 8 B<D. Bleichenbacher, M. Joye, J. Quisquater.> A New and Optimal Chosen-message Attack on RSA-type Cryptosystems (1998).

=item 9 B<B. Kaliski, J. Staddon.> Recent Results on PKCS #1: RSA Encryption Standard, RSA Labs Bulletin Number 7 (1998).

=item 10 B<B. Kaliski, J. Staddon.> PKCS #1: RSA Cryptography Specifications v2.0, RFC 2437 (1998).

=item 11 B<SSH Communications Security.> SSH 1.2.7 source code (1998).

=item 12 B<S. Simpson.> PGP DH vs. RSA FAQ v1.5 (1999).

=item 13 B<RSA Laboratories> Draft I, PKCS #1 v2.1: RSA Cryptography Standard (1999).

=item 14 B<E. Young, T. Hudson, OpenSSL Team.> OpenSSL 0.9.5a source code (2000).

=cut


