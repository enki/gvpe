/*
    util.h -- process management and other utility functions
    Copyright (C) 1998-2002 Ivo Timmermans <ivo@o2w.nl>
                  2000-2002 Guus Sliepen <guus@sliepen.eu.org>
                  2003      Marc Lehmannn <pcg@goof.com>
 
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

#ifndef UTIL_H__
#define UTIL_H__

#include <sys/socket.h>
#include <netinet/in.h>

#include <map>

#include "device.h"

#define SOCKADDR	sockaddr_in	// this is lame, I know

/*
 * check for an existing vped for this net, and write pid to pidfile
 */
extern int write_pidfile (void);

/*
 * kill older vped
 */
extern int kill_other (int signal);

/*
 * Detach from current terminal, write pidfile, kill parent
 */
extern int detach (int do_detach);

/*
 * Set all files and paths according to netname
 */
extern void make_names (void);

/*
 * check wether the given path is an absolute pathname
 */
#define ABSOLUTE_PATH(c) ((c)[0] == '/')

static inline void
id2mac (unsigned int id, void *m)
{
  mac &p = *(mac *)m;

  p[0] = 0xfe;
  p[1] = 0xfd;
  p[2] = 0x80;
  p[3] = 0x00;
  p[4] = id >> 8;
  p[5] = id;
}

#define mac2id(p) (p[0] & 0x01 ? 0 : (p[4] << 8) | p[5])

// a very simple fifo pkt-queue
class pkt_queue
  {
    tap_packet *queue[QUEUEDEPTH];
    int i, j;

  public:

    void put (tap_packet *p);
    tap_packet *get ();

    pkt_queue ();
    ~pkt_queue ();
  };

struct sockinfo
  {
    u32 host;
    u16 port;

    void set (const SOCKADDR *sa)
    {
      host = sa->sin_addr.s_addr;
      port = sa->sin_port;
    }

    sockinfo()
    {
      host = port = 0;
    }

    sockinfo(const SOCKADDR &sa)
    {
      set (&sa);
    }

    sockinfo(const SOCKADDR *sa)
    {
      set (sa);
    }

    SOCKADDR *sa()
    {
      static SOCKADDR sa;

      sa.sin_family = AF_INET;
      sa.sin_port = port;
      sa.sin_addr.s_addr = host;

      return &sa;
    }

    operator const char *();
  };

inline bool
operator == (const sockinfo &a, const sockinfo &b)
{
  return a.host == b.host && a.port == b.port;
}

inline bool
operator < (const sockinfo &a, const sockinfo &b)
{
  return a.host < b.host 
         || (a.host == b.host && a.port < b.port);
}

// only do action once every x seconds per host.
// currently this is quite a slow implementation,
// but suffices for normal operation.
struct u32_rate_limiter : private map<u32, time_t>
 {
   int every;

   bool can (u32 host);

   u32_rate_limiter (time_t every = 1)
   {
     this->every = every;
   }
 };

struct net_rate_limiter : u32_rate_limiter
  {
    bool can (SOCKADDR *sa) { return u32_rate_limiter::can((u32)sa->sin_addr.s_addr); }
    bool can (sockinfo &si) { return u32_rate_limiter::can((u32)si.host); }

    net_rate_limiter (time_t every) : u32_rate_limiter (every) {}
  };

struct sliding_window {
  u32 v[(WINDOWSIZE + 31) / 32];
  u32 seq;

  void reset (u32 seqno)
    {
      memset (v, -1, sizeof v);
      seq = seqno;
    }

  bool recv_ok (u32 seqno)
    {
      if (seqno <= seq - WINDOWSIZE)
        slog (L_ERR, _("received duplicate or outdated packet (received %08lx, expected %08lx)\n"
                       "possible replay attack, or just massive packet reordering"), seqno, seq + 1);//D
      else if (seqno > seq + WINDOWSIZE)
        slog (L_ERR, _("received duplicate or out-of-sync packet (received %08lx, expected %08lx)\n"
                       "possible replay attack, or just massive packet loss"), seqno, seq + 1);//D
      else
        {
          while (seqno > seq)
            {
              seq++;

              u32 s = seq % WINDOWSIZE;
              u32 *cell = v + (s >> 5);
              u32 mask = 1 << (s & 31);

              *cell &= ~mask;
            }

          u32 s = seqno % WINDOWSIZE;
          u32 *cell = v + (s >> 5);
          u32 mask = 1 << (s & 31);

          //printf ("received seqno %08lx, seq %08lx, mask %08lx is %08lx\n", seqno, seq, mask, ismask);
          if (*cell & mask)
            {
              slog (L_ERR, _("received duplicate packet (received %08lx, expected %08lx)\n"
                             "possible replay attack, or just packet duplication"), seqno, seq + 1);//D
              return false;
            }
          else
            {
              *cell |= mask;
              return true;
            }
        }
    }
};

#endif

