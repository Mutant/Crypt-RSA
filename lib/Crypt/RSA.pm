#!/usr/bin/perl -sw
##
## Crypt::RSA - Pure-perl implementation of RSA encryption/signing
##              algorithms.
##
## Copyright (c) 2000, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: RSA.pm,v 1.23 2001/03/07 15:39:55 vipul Exp $

use lib "/home/vipul/PERL/crypto/primes/lib";
package Crypt::RSA;
use Carp;

($VERSION) = '$Revision: 1.23 $' =~ /\s(\d+\.\d+)\s/; 

sub new { 
    return bless { P => "Crypt::RSA $VERSION" }, shift; 
}

1; 

=head1 NAME

Crypt::RSA - RSA public-key cryptosystem.

=head1 VERSION

 $Revision: 1.23 $ (Beta)
 $Date: 2001/03/07 15:39:55 $

=head1 DESCRIPTION

Crypt::RSA is a pure-perl, cleanroom implementation of the RSA public-key
cryptosystem, written atop the blazingly fast number theory library PARI.
As far as possible, Crypt::RSA conforms with I<PKCS #1, RSA Cryptography
Specifications v2.1>[13].

This implementation is structured as a bundle of modules that provide key
pair generation and management, plaintext-aware encryption and digital
signatures with appendix. Crypt::RSA is a DWIM wrapper around the other
modules in the bundle.

=head1 WARNINGS

This is beta, and largely untested, software. Please use at your own risk!

Due to lack of a suitable ASN.1 encoder in perl, ASN.1 encoded formats are
not supported yet.

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


