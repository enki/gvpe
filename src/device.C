/*
    device.C -- include the correct low-level implementation.
    Copyright (C) 2003-2008 Marc Lehmann <gvpe@schmorp.de>
 
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

#include "config.h"

#include <cstring>
#include <cstdlib>

#include "slog.h"
#include "device.h"

static void *pkt_cachep[PKTCACHESIZE];
static int pkt_cachen = 0;

void *net_packet::operator new(size_t s)
{
  if (s > sizeof (data_packet))
    {
      slog (L_ERR, _("FATAL: allocation for network packet larger than max supported packet size (%d > %d)."),
            s, sizeof (data_packet));
      abort ();
    }

  if (pkt_cachen)
    return pkt_cachep[--pkt_cachen];
  else
    {
      void *p  = malloc (sizeof (data_packet));
      memset (p, 0, sizeof (data_packet));
      return p;
    }
}

void net_packet::operator delete(void *p)
{
  if (p)
    {
      if (pkt_cachen < PKTCACHESIZE)
        {
          memset (p, 0, sizeof (data_packet));
          pkt_cachep[pkt_cachen++] = p;
        }
      else
        free (p);
    }
}

#if IFTYPE_tincd
# include "device-tincd.C"
#elif IFTYPE_native && IF_linux
# include "device-linux.C"
#elif IFTYPE_native && IF_cygwin
# include "device-cygwin.C"
#elif IFTYPE_native && IF_darwin
# include "device-darwin.C"
#else
# error No interface implementation for your IFTYPE/IFSUBTYPE combination.
#endif


