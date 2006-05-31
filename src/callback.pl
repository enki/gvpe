#!/usr/bin/perl

print <<EOF;
// THIS IS A GENERATED FILE: RUN callback.pl to regenerate it
// THIS IS A GENERATED FILE: callback.pl is part of the GVPE
// THIS IS A GENERATED FILE: distribution.

/*
    callback.h -- C++ callback mechanism
    Copyright (C) 2003-2006 Marc Lehmann <pcg\@goof.com>
 
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

#define CALLBACK_H_VERSION 2

template<class signature>
struct callback_funtype_trait;

template<int arity, class signature>
struct callback_get_impl;

EOF

for my $a (0..10) {
   my $CLASS     = join "", map ", class A$_", 1..$a;
   my $TYPE      = join ", ", map "A$_", 1..$a;
   my $ARG       = join ", ", map "a$_", 1..$a;
   my $TYPEARG   = join ", ", map "A$_ a$_", 1..$a;
   my $TYPEDEFS  = join " ", map "typedef A$_ arg$_\_type;", 1..$a;
   my $TYPEvoid  = $TYPE    ? $TYPE        : "void";
   my $_TYPE     = $TYPE    ? ", $TYPE"    : "";
   my $_ARG      = $ARG     ? ", $ARG"     : "";
   my $_TYPEARG  = $TYPEARG ? ", $TYPEARG" : "";
   my $_TTYPE    = $a       ? join "", map ", typename T::arg$_\_type", 1..$a : "";
   
   print <<EOF;
template<class R$CLASS>
class callback$a
{
  struct object { };

  typedef R (object::*ptr_type)($TYPE);

  void *obj;
  R (object::*meth)($TYPE);

  /* a proxy is a kind of recipe on how to call a specific class method	*/
  struct proxy_base {
    virtual R call (void *obj, R (object::*meth)($TYPE)$_TYPEARG) const = 0;
  };
  template<class O1, class O2>
  struct proxy : proxy_base {
    virtual R call (void *obj, R (object::*meth)($TYPE)$_TYPEARG) const
      {
        return (R)((reinterpret_cast<O1 *>(obj)) ->* (reinterpret_cast<R (O2::*)($TYPE)>(meth)))
          ($ARG);
      }
  };

  proxy_base *prxy;

public:
  template<class O1, class O2>
  explicit callback$a (O1 *object, R (O2::*method)($TYPE))
    {
      static proxy<O1,O2> p;
      obj  = reinterpret_cast<void *>(object);
      meth = reinterpret_cast<R (object::*)($TYPE)>(method);
      prxy = &p;
    }

  R call($TYPEARG) const
    {
      return prxy->call (obj, meth$_ARG);
    }

  R operator ()($TYPEARG) const
    {
      return call ($ARG);
    }
};

template<class R$CLASS>
struct callback_funtype_trait$a
{
  static const int arity = $a;
  typedef R type ($TYPEvoid);
  typedef R result_type;
  $TYPEDEFS
};

template<class R$CLASS>
struct callback_funtype_trait<R ($TYPE)> : callback_funtype_trait$a<R$_TYPE>
{
};

template<class signature>
struct callback_get_impl<$a, signature>
{
  typedef callback_funtype_trait<signature> T;
  typedef callback$a<typename T::result_type$_TTYPE> type;
};
   
EOF
}

print <<EOF

template<class signature>
struct callback : callback_get_impl<callback_funtype_trait<signature>::arity, signature>::type
{
  typedef typename callback_get_impl<callback_funtype_trait<signature>::arity, signature>::type base_type;

  template<class O, class M>
  explicit callback (O object, M method)
    : base_type (object, method)
    {
    }
};

#endif
EOF

