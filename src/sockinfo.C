/*
    sockinfo.c -- socket address management
    
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

#include <arpa/inet.h>
#include <netdb.h>

#include "gettext.h"

#include "sockinfo.h"
#include "slog.h"

void sockinfo::set (const sockaddr_in *sa, u8 prot_)
{
  host = sa->sin_addr.s_addr;
  port = prot_ == PROT_IPv4 ? 0 : sa->sin_port;
  prot = prot_;
}

void
sockinfo::set (const conf_node *conf)
{
  host = 0;
  port = htons (conf->udp_port);

  if (conf->hostname)
    {
      struct hostent *he = gethostbyname (conf->hostname);

      if (he
          && he->h_addrtype == AF_INET && he->h_length == 4 && he->h_addr_list[0])
        {
          //sa->sin_family = he->h_addrtype;
          memcpy (&host, he->h_addr_list[0], 4);

          prot = PROT_UDPv4 | PROT_IPv4;
        }
      else
        slog (L_NOTICE, _("unable to resolve host '%s'"), conf->hostname);
    }
}


const sockaddr *
sockinfo::sav4() const
{
  static sockaddr_in sa;

  sa.sin_family      = AF_INET;
  sa.sin_port        = port;
  sa.sin_addr.s_addr = host;

  return (const sockaddr *)&sa;
}

static char hostport[15 + 1 + 5 + 1]; // IPv4 : port

const char *
sockinfo::ntoa () const
{
  in_addr ia = { host };

  sprintf (hostport, "%.15s", inet_ntoa (ia));

  return hostport;
}

sockinfo::operator const char *() const
{
  in_addr ia = { host };

  sprintf (hostport, "%.15s:%d", inet_ntoa (ia), ntohs (port) & 0xffff);

  return hostport;
}

