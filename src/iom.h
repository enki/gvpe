/*
    iom.h -- I/O multiplexor
 
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

#ifndef VPE_IOM_H__
#define VPE_IOM_H__

#include <vector>

#include <sys/poll.h>

#include "slog.h"

typedef double timestamp;

extern timestamp NOW;

template<class R, class A> class callback;
struct io_watcher;
struct time_watcher;

class io_manager {
  vector<pollfd> pfs;
  vector<io_watcher *> iow;
  vector<time_watcher *> tw; // actually a heap
public:

  // register a watcher
  void reg (int fd, short events, io_watcher *w);
  void unreg (io_watcher *w);
  void reg (time_watcher *w);
  void unreg (time_watcher *w);
  
  void loop ();

  io_manager ();
  ~io_manager ();
};

extern io_manager iom;

template<class R, class A>
class callback {
  struct object { };

  void *obj;
  R (object::*meth)(A arg);

  // a proxy is a kind of recipe on how to call a specific class method
  struct proxy_base {
    virtual R call (void *obj, void (object::*meth)(A), A arg) = 0;
  };
  template<class O1, class O2>
  struct proxy : proxy_base {
    virtual R call (void *obj, void (object::*meth)(A), A arg)
      {
        ((reinterpret_cast<O1 *>(obj)) ->* (reinterpret_cast<void (O2::*)(A)>(meth)))
          (arg);
      }
  };

  proxy_base *prxy;

public:
  template<class O1, class O2>
  callback (O1 *object, void (O2::*method)(A))
    {
      static proxy<O1,O2> p;
      obj  = reinterpret_cast<void *>(object);
      meth = reinterpret_cast<void (object::*)(A)>(method);
      prxy = &p;
    }

  R call(A arg)
    {
      return prxy->call (obj, meth, arg);
    }
};

struct io_watcher : callback<void, short> {
  template<class O1, class O2>
  io_watcher (int fd, short events, O1 *object, void (O2::*method)(short revents))
    : callback<void, short>(object,method)
    {
      iom.reg (fd, events, this);
    }

  ~io_watcher ()
    {
      iom.unreg (this);
    }
};

struct time_watcher : callback<void, timestamp &> {
  timestamp at;

  void set (timestamp when);

  template<class O1, class O2>
  time_watcher (timestamp when, O1 *object, void (O2::*method)(timestamp &))
    : callback<void, timestamp &>(object,method)
    , at(when)
    {
      iom.reg (this);
    }

  ~time_watcher ()
    {
      iom.unreg (this);
    }
};

#endif

