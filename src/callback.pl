#!/usr/bin/perl

use strict;

print <<EOF;
// THIS IS A GENERATED FILE: RUN callback.pl to regenerate it
// THIS IS A GENERATED FILE: callback.pl is part of the GVPE
// THIS IS A GENERATED FILE: distribution.

/*
    callback.h -- C++ callback mechanism
    Copyright (C) 2003-2007 Marc Lehmann <pcg\@goof.com>
 
    This file is part of GVPE.

    GVPE is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with gvpe; if not, write to the Free Software
    Foundation, Inc. 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef CALLBACK_H__
#define CALLBACK_H__

#define CALLBACK_H_VERSION 3

template<typename signature>
struct callback;

EOF

for my $a (0..10) {
   my $CLASS     = join "", map ", class A$_", 1..$a;
   my $TYPE      = join ", ", map "A$_", 1..$a;
   my $ARG       = join ", ", map "a$_", 1..$a;
   my $TYPEARG   = join ", ", map "A$_ a$_", 1..$a;
   my $TYPEDEFS  = join " ", map "typedef A$_ arg$_\_type;", 1..$a;
   my $TYPEvoid  = $TYPE    ? $TYPE        : "void";
   my $_ARG      = $ARG     ? ", $ARG"     : "";
   my $_TYPE     = $TYPE    ? ", $TYPE"    : "";
   my $_TYPEARG  = $TYPEARG ? ", $TYPEARG" : "";
   my $_TTYPE    = $a       ? join "", map ", typename T::arg$_\_type", 1..$a : "";
   
   print <<EOF;
template<class R$CLASS>
struct callback<R ($TYPE)>
{
  typedef R (*ptr_type)(void *self$_TYPE);

  template<class K, R (K::*method)($TYPE)>
  void set (K *object)
  {
    self = object;
    func = thunk<K, method>;
  }

  R call ($TYPEARG) const
  {
    return func (self$_ARG);
  }

  R operator ()($TYPEARG) const
  {
    return call ($ARG);
  }

private:

  void *self;
  ptr_type func;

  template<class klass, R (klass::*method)($TYPE)>
  static R thunk (void *self$_TYPEARG)
  {
    klass *obj = static_cast<klass *>(self);
    return (obj->*method) ($ARG);
  }
};

EOF
}

print <<EOF

#endif
EOF

