#!/usr/bin/perl -sw
##
## Crypt::RSA::Errorhandler -- Base class that provide error 
##                             handling functionality.
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: Errorhandler.pm,v 1.2 2001/03/05 01:10:45 vipul Exp $

package Crypt::RSA::Errorhandler; 
use strict;

sub new { 
    bless {}, shift
}


sub error { 
    my ($self, $errstr, @towipe) = @_;
    $$self{errstr} = "$errstr\n";
    for (@towipe) { 
        my $var = $_;
        if (ref($var) =~ /Crypt::RSA/) { 
            $var->DESTROY();
        } elsif (ref($var) eq "SCALAR") { 
            $$var = ""; 
        } elsif (ref($var) eq "ARRAY") { 
            @$var = ();
        } elsif (ref($var) eq "HASH") { 
            %$var = ();
        }
    }
    return;    
} 


sub errstr { 
    my $self = shift;
    return $$self{errstr};
}


1;

