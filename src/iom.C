/*
    iom.C -- I/O multiplexor
 
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

#include "config.h"

#include <sys/time.h>

#include <algorithm>
#include <functional>

#include "gettext.h"

#include "slog.h"
#include "iom.h"

tstamp NOW;
bool iom_valid;
io_manager iom;

inline bool earliest_first (const time_watcher *a, const time_watcher *b)
{
  return a->at > b->at;
}

void time_watcher::set (tstamp when)
{
  at = when;

  if (registered)
    iom.reschedule_time_watchers ();
}

void time_watcher::trigger ()
{
  call (*this);

  if (registered)
    iom.reschedule_time_watchers ();
  else
    iom.reg (this);
}

time_watcher::~time_watcher ()
{
  if (iom_valid)
    iom.unreg (this);
}

void io_watcher::set(int fd_, short events_)
{
  fd     = fd_;
  events = events_;

  if (registered)
    {
      iom.unreg (this);
      iom.reg (this);
    }
}

io_watcher::~io_watcher ()
{
  if (iom_valid)
    iom.unreg (this);
}

void io_manager::reg (io_watcher *w)
{
  if (!w->registered)
    {
      w->registered = true;

      pollfd pfd;

      pfd.fd     = w->fd;
      pfd.events = w->events;

      pfs.push_back (pfd);
      iow.push_back (w);
    }
}

void io_manager::unreg (io_watcher *w)
{
  if (w->registered)
    {
      w->registered = false;

      unsigned int sz = iow.size ();
      unsigned int i = find (iow.begin (), iow.end (), w) - iow.begin ();

      assert (i != sz);

      if (sz == 1)
        {
          pfs.clear ();
          iow.clear ();
        }
      else if (i == sz - 1)
        {
          iow.pop_back ();
          pfs.pop_back ();
        }
      else
        {
          iow[i] = iow[sz - 1]; iow.pop_back ();
          pfs[i] = pfs[sz - 1]; pfs.pop_back ();
        }
    }
}

void io_manager::reschedule_time_watchers ()
{
  make_heap (tw.begin (), tw.end (), earliest_first);
}

void io_manager::reg (time_watcher *w)
{
  if (!w->registered)
    {
      w->registered = true;

      tw.push_back (w);
      push_heap (tw.begin (), tw.end (), earliest_first);
    }
}

void io_manager::unreg (time_watcher *w)
{
  if (w->registered)
    {
      w->registered = false;

      unsigned int sz = tw.size ();
      unsigned int i = find (tw.begin (), tw.end (), w) - tw.begin ();

      assert (i != sz);
      
      if (i != sz - 1)
        tw[i] = tw[sz - 1];

      tw.pop_back ();
      reschedule_time_watchers ();
    }
}

inline void set_now (void)
{
  struct timeval tv;

  gettimeofday (&tv, 0);

  NOW = (tstamp)tv.tv_sec + (tstamp)tv.tv_usec / 1000000;
}

void io_manager::loop ()
{
  set_now ();

  for (;;)
    {
      while (tw[0]->at <= NOW)
        {
          // remove the first watcher
          time_watcher *w = tw[0];

          pop_heap (tw.begin (), tw.end (), earliest_first);
          tw.pop_back ();

          w->registered = false;

          // call it
          w->call (*w);

          // re-add it if necessary
          if (w->at >= 0 && !w->registered)
            reg (w);
        }

      int timeout = (int) ((tw[0]->at - NOW) * 1000);

      int fds = poll (&pfs[0], pfs.size (), timeout);

      set_now ();

      vector<io_watcher *>::iterator w;
      vector<pollfd>::iterator p;

      for (w = iow.begin (), p = pfs.begin ();
           fds > 0 && w < iow.end ();
           ++w, ++p)
        if (p->revents)
          {
            --fds;

            if (p->revents & POLLNVAL)
              {
                slog (L_ERR, _("io_watcher started on illegal file descriptor, disabling."));
                (*w)->stop ();
              }
            else
              (*w)->call (**w, p->revents);
          }
    }
}

void io_manager::idle_cb (time_watcher &w)
{
  w.at = NOW + 86400; // wake up every day, for no good reason
}

io_manager::io_manager ()
{
  iom_valid = true;

  set_now ();
  idle = new time_watcher (this, &io_manager::idle_cb);
  idle->start (0);
}

io_manager::~io_manager ()
{
  iom_valid = false;
}

