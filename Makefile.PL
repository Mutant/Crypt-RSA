#!/usr/bin/perl -sw
##
## Makefile.PL for Crypt-RSA. 
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: Makefile.PL,v 1.7 2001/04/17 19:48:36 vipul Exp $

use ExtUtils::MakeMaker;
WriteMakefile(
    'NAME'         => 'Crypt::RSA',
    'AUTHOR'       => 'Vipul Ved Prakash <mail@vipul.net>',
    'VERSION_FROM' => 'lib/Crypt/RSA.pm',
    'PREREQ_PM'    => { 
                        'Math::Pari'             => '2.001804', 
                        'Crypt::Random'          => '0.34', 
                        'Crypt::Primes'          => '0.38',
                        'Crypt::CBC'             =>  0, 
                        'Crypt::Blowfish'        =>  0,
                        'Data::Dumper'           =>  0,
                        'Tie::EncryptedHash'     =>  0,
                        'Convert::ASCII::Armour' =>  0,
                        'Sort::Versions'         =>  0,
                        'Digest::SHA1'           =>  0,
                        'Digest::MD5'            =>  0,
                        'Digest::MD2'            =>  0,
                      } 
);

