/*
    util.h -- process management and other utility functions
    Copyright (C) 1998-2002 Ivo Timmermans <ivo@o2w.nl>
                  2000-2002 Guus Sliepen <guus@sliepen.eu.org>
                  2003      Marc Lehmann <gvpe@schmorp.de>
 
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

#ifndef UTIL_H__
#define UTIL_H__

#include <openssl/rsa.h>

#include "gettext.h"

#include "slog.h"
#include "iom.h"

/*
 * check for an existing gvpe for this net, and write pid to pidfile
 */
extern int write_pidfile (void);

/*
 * kill older gvpe
 */
extern int kill_other (int signal);

/*
 * Detach from current terminal, write pidfile, kill parent
 */
extern int detach (int do_detach);

/*
 * check wether the given path is an absolute pathname
 */
#define ABSOLUTE_PATH(c) ((c)[0] == '/')

/*****************************************************************************/

typedef u8 mac[6];

extern void id2mac (unsigned int id, void *m);

#define mac2id(p) ((p)[0] & 0x01 ? 0 : ((p)[4] << 8) | (p)[5])

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

typedef callback0<const char *> run_script_cb;

// run a shell script (or actually an external program).
bool run_script (const run_script_cb &cb, bool wait);

#if ENABLE_HTTP_PROXY
u8 *base64_encode (const u8 *data, unsigned int len);
#endif

/*****************************************************************************/

typedef u8 rsaclear[RSA_KEYLEN - RSA_OVERHEAD]; // challenge data;
typedef u8 rsacrypt[RSA_KEYLEN]; // encrypted challenge

static inline void
rsa_encrypt (RSA *key, const rsaclear &chg, rsacrypt &encr)
{
  if (RSA_public_encrypt (sizeof chg,
                          (unsigned char *)&chg, (unsigned char *)&encr,
                          key, RSA_PKCS1_OAEP_PADDING) < 0)
    fatal ("RSA_public_encrypt error");
}

static inline bool
rsa_decrypt (RSA *key, const rsacrypt &encr, rsaclear &chg)
{
  return RSA_private_decrypt (sizeof encr,
                              (unsigned char *)&encr, (unsigned char *)&chg,
                              key, RSA_PKCS1_OAEP_PADDING) > 0;
}

#endif

