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
use Crypt::RSA::Key::Public;
use Math::Pari qw(PARI);

print "1..6\n";
my $i = 0;
my $keyfile = "./rsa-public-key";
my $n = PARI('90323071930747658587680108508312228275784837926947082008548691733142705211489057935389756600126815968792421058507821141460115569139868202311230475972964057619586895938810033730091286963807334963647271206191891975955352543611579505094807268518669728893837266971976327030260763032999438640559854194396431791831');
my $e = PARI('65537');

my $key = new Crypt::RSA::Key::Public();
$key->n ($n);
$key->e ($e);
$key->Identity ('mail@vipul.net');

print $key->n == $n ? "ok" : "not ok"; print " ", ++$i, "\n";
print $key->e == $e ? "ok" : "not ok"; print " ", ++$i, "\n";
print $key->Identity eq 'mail@vipul.net' ? "ok" : "not ok"; print " ", ++$i, "\n";

$key->write(Filename => $keyfile);

my $pkey = new Crypt::RSA::Key::Public (Filename => $keyfile);
print $pkey->n == $n ? "ok" : "not ok"; print " ", ++$i, "\n";
print $pkey->e == $e ? "ok" : "not ok"; print " ", ++$i, "\n";
print $pkey->Identity eq 'mail@vipul.net' ? "ok" : "not ok"; print " ", ++$i, "\n";

unlink $keyfile;

