#!/usr/bin/perl -sw
##
## 06-oaep.t
##
## Copyright (c) 2000, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: 06-oaep.t,v 1.2 2001/02/22 15:50:54 vipul Exp $

use lib '../lib';
use lib 'lib';
use Crypt::RSA::EME::OAEP;
use Crypt::RSA::Key;

print "1..1\n";
my $i = 0;
my $oaep = new Crypt::RSA::EME::OAEP;
my $message = "My plenteous joys, Wanton in fullness, seek to hide themselves.";
my $keychain = new Crypt::RSA::Key;
my ($pub, $priv) = $keychain->generate ( Size => 1024, Password => 'xx', Identity => 'xx', Verbosity => 1 );
die $keychain->errstr() if $keychain->errstr();

my $ct = $oaep->encrypt (Key => $pub, Message => $message);
     die $oaep->errstr unless $ct;
my $pt = $oaep->decrypt (Key => $priv, Cyphertext => $ct);
    die die $oaep->errstr unless $pt;

print "$pt\n";
print $pt eq $message ? "ok" : "not ok"; print " ", ++$i, "\n";

