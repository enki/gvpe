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

#include "iom.h"
#include "device.h"

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

