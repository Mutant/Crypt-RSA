#!/usr/bin/perl -s
##
## random_octet.t 
##
## Copyright (c) 2000, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: 03-random_octet.t,v 1.1 2001/04/06 18:33:31 vipul Exp $

use lib '../lib';
use Crypt::RSA; 
use Crypt::RSA::DataFormat qw(generate_random_octet);

print "1..6\n";  my $i = 0;

for my $len (qw/10 512 1024/) { 
    my $ro = generate_random_octet ( $len );
    print $ro ne "" ? "ok" : "not ok"; print " ", ++$i, "\n";
    print length($ro) == $len ? "ok" : "not ok"; print " ", ++$i, "\n";
}

