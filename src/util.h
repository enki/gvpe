/*
    util.h -- process management and other utility functions
    Copyright (C) 1998-2002 Ivo Timmermans <ivo@o2w.nl>
                  2000-2002 Guus Sliepen <guus@sliepen.eu.org>
                  2003-2011 Marc Lehmann <gvpe@schmorp.de>
 
    This file is part of GVPE.

    GVPE is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the
    Free Software Foundation; either version 3 of the License, or (at your
    option) any later version.
   
    This program is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
    Public License for more details.
   
    You should have received a copy of the GNU General Public License along
    with this program; if not, see <http://www.gnu.org/licenses/>.
   
    Additional permission under GNU GPL version 3 section 7
   
    If you modify this Program, or any covered work, by linking or
    combining it with the OpenSSL project's OpenSSL library (or a modified
    version of that library), containing parts covered by the terms of the
    OpenSSL or SSLeay licenses, the licensors of this Program grant you
    additional permission to convey the resulting work.  Corresponding
    Source for a non-source form of such a combination shall include the
    source code for the parts of OpenSSL used as well as that of the
    covered work.
*/

#ifndef UTIL_H__
#define UTIL_H__

#include <cstring>
#include <sys/types.h>

#include <openssl/rsa.h>

#include "gettext.h"

#include "slog.h"
#include "ev_cpp.h"
#include "callback.h"

typedef ev_tstamp tstamp;

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

struct sliding_window
{
  u32 v[(WINDOWSIZE + 31) / 32];
  u32 seq;

  void reset (u32 seqno)
    {
      memset (v, -1, sizeof v);
      seq = seqno;
    }

  // 0 == ok, 1 == far history, 2 == duplicate in-window, 3 == far future
  int seqno_classify (u32 seqno)
    {
      if (seqno <= seq - WINDOWSIZE)
        return 1;
      else if (seqno > seq + WINDOWSIZE * 16)
        return 3;
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
            return 2;
          else
            {
              *cell |= mask;
              return 0;
            }
        }
    }
};

typedef callback<const char *()> run_script_cb;

// run a shell script (or actually an external program).
pid_t run_script (const run_script_cb &cb, bool wait);

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

/*****************************************************************************/

void async (callback<void ()> work_cb, callback<void ()> done_cb);

#endif

