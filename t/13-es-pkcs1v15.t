#!/usr/bin/perl -sw
##
## 06-oaep.t
##
## Copyright (c) 2000, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: 13-es-pkcs1v15.t,v 1.1 2001/04/06 18:33:31 vipul Exp $

use lib '../lib';
use lib 'lib';
use Crypt::RSA::ES::PKCS1v15;
use Crypt::RSA::Key;

print "1..1\n";
my $i = 0;
my $oaep = new Crypt::RSA::ES::PKCS1v15;
my $message = "My plenteous joys, Wanton in fullness, seek to hide themselves.";
my $keychain = new Crypt::RSA::Key;
my ($pub, $priv) = $keychain->generate ( Size => 1020, Password => 'xx', Identity => 'xx', Verbosity => 1 );
die $keychain->errstr() if $keychain->errstr();

my $ct = $oaep->encrypt (Key => $pub, Message => $message);
     die $oaep->errstr unless $ct;
my $pt = $oaep->decrypt (Key => $priv, Cyphertext => $ct);
    die die $oaep->errstr unless $pt;

print "$pt\n";
print $pt eq $message ? "ok" : "not ok"; print " ", ++$i, "\n";

