#!/usr/bin/perl -s
##
## 09-publickey.t
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id$

use lib '../lib';
use lib 'lib';
use Crypt::RSA::Key;
use Data::Dumper;

my $i = 0;
print "1..12\n";
my $keychain = new Crypt::RSA::Key; 

for my $ksize (qw(150 300 512 768 1024 2048)) { 
my ($pub, $pri) = $keychain->generate ( Identity => 'mail@vipul.net', 
                                        Password => 'a day so foul and fair', 
                                        Verbosity => 1,
                                        Size     => $ksize );

die $keychain->errstr if $keychain->errstr();

print $pub->Identity eq 'mail@vipul.net' ? "ok" : "not ok"; print " ", ++$i, "\n";
print $pub->n eq $pri->p * $pri->q  ? "ok" : "not ok"; print " ", ++$i, "\n";
}


