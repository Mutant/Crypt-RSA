#!/usr/bin/perl -sw
##
## Makefile.PL for Crypt-RSA. 
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: Makefile.PL,v 1.2 2001/03/04 15:09:03 vipul Exp $

use ExtUtils::MakeMaker;
WriteMakefile(
    'NAME'	       => 'Crypt::RSA',
    'AUTHOR'       => 'Vipul Ved Prakash <mail@vipul.net>',
    'VERSION_FROM' => 'lib/Crypt/RSA.pm',
    'PREREQ_PM'    => { 'Math::Pari'         => '2.001804', 
                        'Crypt::Random'      => '0.33', 
                        'Crypt::Primes'      => '0.38',
                        'Data::Dumper'       => 0,
                        'Crypt::CBC'         => 0, 
                        'Crypt::Blowfish'    => 0,
                        'Tie::EncryptedHash' => 0,
                      } 
);

