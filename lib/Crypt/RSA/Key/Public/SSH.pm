#!/usr/bin/perl -sw
##
## Crypt::RSA::Key::Private::SSH
##
## Copyright (c) 2001, Vipul Ved Prakash.  All rights reserved.
## This code is free software; you can redistribute it and/or modify
## it under the same terms as Perl itself.
##
## $Id: SSH.pm,v 1.1 2001/05/20 23:37:48 vipul Exp $

package Crypt::RSA::Key::Public::SSH;
use strict;
use lib qw(lib);
use Crypt::RSA::DataFormat qw(bitsize);
use Crypt::RSA::Key::Public;
use vars qw(@ISA);
@ISA = qw(Crypt::RSA::Key::Public);

sub deserialize {
    my ($self, %params) = @_;
    my ($bitsize, $e, $n, $ident) = split /\s/, join'',@{$params{String}};
    $self->n ($n);
    $self->e ($e);
    $self->Identity ($ident);
    return $self;
}

sub serialize { 
    my ($self, %params) = @_;
    my $bitsize = bitsize ($self->n);
    my $string = join ' ', $bitsize, $self->e, $self->n, $self->Identity;
    return $string;
}

1;

