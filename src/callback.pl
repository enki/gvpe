#!/usr/bin/perl

print <<EOF;
// THIS IS A GENERATED FILE, RUN callback.pl to regenerate it
// THIS IS A GENERATED FILE, RUN callback.pl to regenerate it
// THIS IS A GENERATED FILE, RUN callback.pl to regenerate it
// THIS IS A GENERATED FILE, RUN callback.pl to regenerate it
// THIS IS A GENERATED FILE, RUN callback.pl to regenerate it
// THIS IS A GENERATED FILE, RUN callback.pl to regenerate it

/*
    callback.h -- C++ callback mechanism
    Copyright (C) 2003 Marc Lehmann <pcg\@goof.com>
 
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc. 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef CALLBACK_H__
#define CALLBACK_H__

EOF

for my $a (0..7) {
   my $CLASS     = join "", map ", class A$_", 1..$a;
   my $TYPE      = join ", ", map "A$_", 1..$a;
   my $ARG       = join ", ", map "a$_", 1..$a;
   my $TYPEARG   = join ", ", map "A$_ a$_", 1..$a;
   my $_ARG      = $ARG     ? ", $ARG"     : "";
   my $_TYPEARG  = $TYPEARG ? ", $TYPEARG" : "";
   
   print <<EOF;
template<class R$CLASS>
class callback$a {
  struct object { };

  void *obj;
  R (object::*meth)($TYPE);

  /* a proxy is a kind of recipe on how to call a specific class method	*/
  struct proxy_base {
    virtual R call (void *obj, R (object::*meth)($TYPE)$_TYPEARG) = 0;
  };
  template<class O1, class O2>
  struct proxy : proxy_base {
    virtual R call (void *obj, R (object::*meth)($TYPE)$_TYPEARG)
      {
        ((reinterpret_cast<O1 *>(obj)) ->* (reinterpret_cast<R (O2::*)($TYPE)>(meth)))
          ($ARG);
      }
  };

  proxy_base *prxy;

public:
  template<class O1, class O2>
  callback$a (O1 *object, R (O2::*method)($TYPE))
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

EOF
}

print <<EOF
#endif
EOF

