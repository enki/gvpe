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

#include "callback.h"
#include "slog.h"

typedef double tstamp;

extern tstamp NOW;

struct io_watcher;
struct time_watcher;

class io_manager {
  vector<pollfd> pfs;
  vector<const io_watcher *> iow;
  vector<time_watcher *> tw; // actually a heap

  void idle_cb (tstamp &ts); time_watcher *idle;
public:

  void reschedule_time_watchers ();

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

struct io_watcher : callback<void, short> {
  template<class O1, class O2>
  io_watcher (O1 *object, void (O2::*method)(short revents))
    : callback<void, short>(object,method)
    { }

  ~io_watcher ()
    {
      iom.unreg (this);
    }

  void start (int fd, short events)
    {
      iom.reg (fd, events, this);
    }

  void stop ()
    {
      iom.unreg (this);
    }
};

#define TSTAMP_CANCEL -1.

struct time_watcher : callback<void, tstamp &> {
  bool registered; // already registered?
  tstamp at;

  template<class O1, class O2>
  time_watcher (O1 *object, void (O2::*method)(tstamp &))
    : callback<void, tstamp &>(object,method)
    , registered(false)
    { }

  ~time_watcher ()
    {
      iom.unreg (this);
    }

  void set (tstamp when);
  void trigger ();

  void operator ()()
    {
      trigger ();
    }

  void start ();
  void start (tstamp when)
    {
      set (when);
    }

  void stop ()
    {
      iom.unreg (this);
    }

  void reset (tstamp when = TSTAMP_CANCEL)
    {
      stop ();
      at = when;
    }
};

#endif

