#!/usr/bin/perl -sw
##
## Crypt::RSA - Pure-perl implementation of RSA encryption/signing
##              algorithms.
##
## Copyright (c) 2000, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: RSA.pm,v 1.24 2001/03/12 04:49:49 vipul Exp $

package Crypt::RSA;
use lib '/home/vipul/PERL/crypto/rsa/lib';
# use strict;
use vars qw(@ISA);
use Crypt::RSA::Errorhandler; 
use Crypt::RSA::Key;
use Crypt::RSA::EME::OAEP;
use Crypt::RSA::SSA::PSS;
use Crypt::RSA::DataFormat qw(bitsize steak);
use Crypt::RSA::Debug qw(debug);
use Carp;
use Data::Dumper;

@ISA = qw(Crypt::RSA::Errorhandler);

($VERSION) = '$Revision: 1.24 $' =~ /\s(\d+\.\d+)\s/; 

my %DEFAULTS = ( 
    'EME'    => { Scheme      => "Crypt::RSA::EME::OAEP",
                  Encryptsize => 'n-42', # 42 octets less than size of n
                  Decryptsize => 'n-0', 
                },
    'SSA'    => { Scheme     => "Crypt::RSA::SSA::PSS",
                  Signsize   => '-1',   # infinite
                  Verifysize => '-1'
                }
);

sub new { 
    my ($class, %params) = @_;
    my %self = (%DEFAULTS, %params);


    # replace literals with $self{EME} and $self{PSS}
    $self{keychain}  = new Crypt::RSA::Key; 
    $self{eme} = new Crypt::RSA::EME::OAEP;
    $self{ssa} = new Crypt::RSA::SSA::PSS;

    return bless \%self, $class; 
}

sub keygen { 
    my ($self, %params) = @_;
    my @keys = $self->{keychain}->generate (%params);
    return @keys if @keys;
    return $self->error ($self->{keychain}->errstr);
} 


sub encrypt { 
    my ($self, %params) = @_;
    my $key = $params{Key}; 
    my $plaintext = $params{Message};
    my $cyphertext;
    my $blocksize = ((bitsize ($key->n)) / 8); 
    if ($$self{EME}{Encryptsize} =~ /\-(\d+)/) { 
        $blocksize -= $1;
    }
    my @segments = steak ($plaintext, $blocksize);
    for (@segments) {
        $cyphertext .= $self->{eme}->encrypt (Message => $_, Key => $key)
            || return $self->error ($self->{eme}->errstr, \$key, \%params);
    }
    $cyphertext = pack "u*", $cyphertext if $params{Armour};
    return $cyphertext;
}


sub decrypt { 
    my ($self, %params) = @_;
    my $key = $params{Key}; 
    my $cyphertext = $params{Cyphertext};
    $cyphertext = unpack "u*", $cyphertext if $params{Armour};
    my $plaintext;
    my $blocksize = ((bitsize ($key->n)) / 8); 
    my @segments = steak ($cyphertext, $blocksize);
    for (@segments) {
        $plaintext .= $self->{eme}->decrypt (Cyphertext=> $_, Key => $key)
            || return $self->error ($self->{eme}->errstr, \$key, \%params);
    }
    return $plaintext;
}
 

1; 


=head1 NAME

Crypt::RSA - RSA public-key cryptosystem.

=head1 VERSION

 $Revision: 1.24 $ (Beta)
 $Date: 2001/03/12 04:49:49 $

=head1 SYNOPSIS

    my $rsa = new Crypt::RSA; 

    my ($public, $private) = $rsa->keygen ( ... ); 

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
cryptosystem, written atop the blazingly fast number theory library Pari.
As far as possible, Crypt::RSA conforms with PKCS #1, RSA Cryptography
Specifications v2.1[13].

This implementation is structured as a bundle of modules that provide key
pair generation and management, plaintext-aware encryption and digital
signatures with appendix. Crypt::RSA is a DWIM wrapper around the other
modules in the bundle.

=head1 WARNINGS

This is beta, and largely untested, software. Please use at your own risk!

ASN.1 encoded formats are not supported yet.

=head1 METHODS

=head2 B<new()>

Constructor.

=head2 B<keygen()>



=head1 MODULES

As of this writing, Crypt::RSA is just a placeholder for the wrapper
code, which will appear soon. In the meantime, please use the following
modules directly:

=over 4

=item B<Crypt::RSA::Key>

RSA key pair generator.

=item B<Crypt::RSA::Key::Public>

RSA Public Key Management.

=item B<Crypt::RSA::Key::Private>

RSA Private Key Management.

=item B<Crypt::RSA::EME::OAEP>

Plaintext-aware encryption with RSA.

=item B<Crypt::RSA::SSA::PSS>

Probablistic Signature Scheme based on RSA.

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
regarding Math::Pari with unwavering paitence. Shizukesa on #perl for
clueing me into the error handling method used in this module and a-mused
for good advice.

=head1 LICENSE 

Copyright (c) 1998-2001, Vipul Ved Prakash. All rights reserved. This code
is free software; you can redistribute it and/or modify it under the same
terms as Perl itself.

=head1 SEE ALSO

Crypt::RSA::Primitives(3), Crypt::RSA::DataFormat(3),
Crypt::RSA::Errorhandler(3), Crypt::RSA::Debug(3), Crypt::Primes(3),
Crypt::Random(3), Crypt::CBC(3), Crypt::Blowfish(3), Tie::EncryptedHash(3),
Math::Pari(3).

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


