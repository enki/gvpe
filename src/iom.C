#include <unistd.h>
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

#include "slog.h"

#include "iom.h"

inline bool lowest_first (const time_watcher *a, const time_watcher *b)
{
  return a->at > b->at;
}

timestamp NOW;

io_manager iom;

void time_watcher::set (timestamp when)
{
  iom.unreg (this);
  at = when;
  iom.reg (this);
}

void io_manager::reg (int fd, short events, io_watcher *w)
{
  pollfd pfd;

  pfd.fd     = fd;
  pfd.events = events;

  pfs.push_back (pfd);
  iow.push_back (w);
}

void io_manager::unreg (io_watcher *w)
{
  unsigned int sz = iow.size ();
  unsigned int i = find (iow.begin (), iow.end (), w) - iow.begin ();

  if (i != sz)
    {
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

void io_manager::reg (time_watcher *w)
{
  tw.push_back (w);
  push_heap (tw.begin (), tw.end (), lowest_first);
}

void io_manager::unreg (time_watcher *w)
{
  unsigned int sz = tw.size ();
  unsigned int i = find (tw.begin (), tw.end (), w) - tw.begin ();

  if (i != sz)
    {
      if (sz == 1)
        tw.clear ();
      else 
        {
          if (i != sz - 1)
            tw[i] = tw[sz - 1];

          tw.pop_back ();
          make_heap (tw.begin (), tw.end (), lowest_first);
        }
    }
}

inline void set_now (void)
{
  struct timeval tv;

  gettimeofday (&tv, 0);

  NOW = (timestamp)tv.tv_sec + (timestamp)tv.tv_usec / 1000000;
}

void io_manager::loop ()
{
  set_now ();

  for (;;)
    {
      int timeout = tw.empty () ? -1 : (int) ((tw[0]->at - NOW) * 1000);

      //printf ("s%d t%d #%d <%f<%f<\n", pfs.size (), timeout, tw.size (), tw[0]->at - NOW, tw[1]->at - NOW);

      if (timeout >= 0)
        {
          int fds = poll (&pfs[0], pfs.size (), timeout);

          set_now ();

          for (unsigned int i = iow.size (); fds && i--; )
            if (pfs[i].revents)
              {
                --fds;
                iow[i]->call (pfs[i].revents);
              }
        }

      while (!tw.empty () && tw[0]->at <= NOW)
        {
          pop_heap (tw.begin (), tw.end (), lowest_first);
          time_watcher *w = tw[tw.size () - 1];
          w->call (w->at);
          push_heap (tw.begin (), tw.end (), lowest_first);
        }
    }
}

io_manager::io_manager ()
{
  set_now ();
}

io_manager::~io_manager ()
{
  //
}

