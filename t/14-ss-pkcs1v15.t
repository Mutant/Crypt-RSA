#!/usr/bin/perl -sw
##
##
##
## Copyright (c) 2000, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: 14-ss-pkcs1v15.t,v 1.1 2001/04/06 18:33:31 vipul Exp $ 

use lib '../lib';
use lib 'lib';
use Crypt::RSA::Key;
use Crypt::RSA::SS::PKCS1v15;
use Math::Pari qw(PARI);

print "1..3\n";
my $i = 0;

my $message =  " Whither should I fly? \
                 I have done no harm. But I remember now \
                 I am in this earthly world, where to do harm \
                 Is often laudable, to do good sometime \
                 Accounted dangerous folly. ";

my $keychain = Crypt::RSA::Key->new();

my ($pub, $priv) = $keychain->generate ( 
                     Size => 512, 
                     Password => 'bl0gr', 
                     Identity => 'Lady McDuff', 
                     Verbosity => 1
                    ); 

for (qw(MD2 MD5 SHA1)) { 
   
    my $pkcs = new Crypt::RSA::SS::PKCS1v15 ( Digest => $_ );
 
    my $sig = $pkcs->sign (
                Message => $message,
                Key     => $priv,
    ) || die $pkcs->errstr();

    my $verify = $pkcs->verify (
                   Key => $pub, 
                   Message => $message, 
                   Signature => $sig, 
    ) || die $pkcs->errstr;

    print $verify ? "ok" : "not ok"; print " ", ++$i, "\n";

}
