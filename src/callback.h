/*
    callback.h -- C++ callback mechanism
 
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

#ifndef VPE_CALLBACK_H__
#define VPE_CALLBACK_H__

template<class R, class A>
class callback {
  struct object { };

  void *obj;
  R (object::*meth)(A arg);

  // a proxy is a kind of recipe on how to call a specific class method
  struct proxy_base {
    virtual R call (void *obj, R (object::*meth)(A), A arg) = 0;
  };
  template<class O1, class O2>
  struct proxy : proxy_base {
    virtual R call (void *obj, R (object::*meth)(A), A arg)
      {
        ((reinterpret_cast<O1 *>(obj)) ->* (reinterpret_cast<R (O2::*)(A)>(meth)))
          (arg);
      }
  };

  proxy_base *prxy;

public:
  template<class O1, class O2>
  callback (O1 *object, R (O2::*method)(A))
    {
      static proxy<O1,O2> p;
      obj  = reinterpret_cast<void *>(object);
      meth = reinterpret_cast<R (object::*)(A)>(method);
      prxy = &p;
    }

  R call(A arg) const
    {
      return prxy->call (obj, meth, arg);
    }

  R operator ()(A arg) const
    {
      return call (arg);
    }
};

#endif

