#!/usr/bin/perl -sw
##
##
##
## Copyright (c) 2000, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: 07-pss.t,v 1.3 2001/04/06 18:33:31 vipul Exp $ 

use lib '../lib';
use lib 'lib';
use Crypt::RSA::Key;
use Crypt::RSA::SS::PSS;
use Math::Pari qw(PARI);

print "1..4\n";
my $i = 0;
my $pss = new Crypt::RSA::SS::PSS; 

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

for (1 .. 4) { 

    $message .= "\n$message";

    my $sig = $pss->sign (
                Message => $message,
                Key     => $priv,
    ) || die $pss->errstr();

    my $verify = $pss->verify (
                   Key => $pub, 
                   Message => $message, 
                   Signature => $sig, 
    ) || die $pss->errstr;

    print $verify ? "ok" : "not ok"; print " ", ++$i, "\n";

}
