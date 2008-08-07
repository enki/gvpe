/*
    sockinfo.C -- socket address management
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

#include <netdb.h>

#include "gettext.h"

#include "sockinfo.h"
#include "slog.h"

#include <cstring>
#include <cstdio>

// all ipv4-based protocols
#define PROTv4 (PROT_UDPv4 | PROT_TCPv4 | PROT_ICMPv4 | PROT_IPv4 | PROT_DNSv4)

void sockinfo::set (const sockaddr_in *sa, u8 prot_)
{
  host = sa->sin_addr.s_addr;
  port = prot_ & (PROT_IPv4 | PROT_ICMPv4) ? 0 : sa->sin_port;
  prot = prot_;
}

void sockinfo::set (const char *hostname, u16 port_, u8 prot_)
{
  prot = prot_;
  host = 0;
  port = htons (port_);

  if (prot & PROTv4
      && hostname)
    {
      struct hostent *he = gethostbyname (hostname);

      if (he
          && he->h_addrtype == AF_INET && he->h_length == 4 && he->h_addr_list[0])
        {
          //sa->sin_family = he->h_addrtype;
          memcpy (&host, he->h_addr_list[0], 4);
        }
      else
        slog (L_NOTICE, _("unable to resolve host '%s'"), hostname);
    }
}

void
sockinfo::set (const conf_node *conf, u8 prot_)
{
  if (prot_ == PROT_DNSv4)
    {
      host = htonl (conf->id); port = 0; prot = prot_;
    }
  else
    set (conf->hostname,
         prot_ == PROT_UDPv4   ? conf->udp_port
         : prot_ == PROT_TCPv4 ? conf->tcp_port
         : prot_ == PROT_DNSv4 ? conf->dns_port
         : 0,
         prot_);
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

static char hostport[10 + 15 + 1 + 5 + 1]; // proto / IPv4 : port

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

  sprintf (hostport, "%s/%.15s:%d", strprotocol (prot), inet_ntoa (ia), ntohs (port) & 0xffff);

  return hostport;
}

u8
sockinfo::supported_protocols (conf_node *conf)
{
  u8 protocols = prot;

  if (prot & (PROT_UDPv4 | PROT_TCPv4))
    protocols |= PROT_IPv4 | PROT_ICMPv4;

  if (conf
      && prot & PROTv4
      && conf->protocols & PROT_UDPv4
      && conf->udp_port)
    protocols |= PROT_UDPv4;

  if (conf
      && prot & PROTv4
      && conf->protocols & PROT_TCPv4
      && conf->tcp_port)
    protocols |= PROT_TCPv4;

  if (conf
      && prot & PROTv4
      && conf->protocols & PROT_DNSv4
      && conf->dns_port)
    protocols |= PROT_DNSv4;

  return protocols;
}

bool
sockinfo::upgrade_protocol (u8 prot_, conf_node *conf)
{
  if (prot_ == prot)
    return true;

  if (prot & PROTv4
      && prot_ & PROTv4)
    {
      if (prot_ & (PROT_IPv4 | PROT_ICMPv4))
        {
          prot = prot_;
          port = 0;
          return true;
        }

      if (conf
          && prot_ & PROT_UDPv4
          && conf->protocols & PROT_UDPv4
          && conf->udp_port)
        {
          prot = prot_;
          port = htons (conf->udp_port);
          return true;
        }

      if (conf
          && prot_ & PROT_TCPv4
          && conf->protocols & PROT_TCPv4
          && conf->tcp_port)
        {
          prot = prot_;
          port = htons (conf->tcp_port);
          return true;
        }
    }

  return false;
}

bool
operator == (const sockinfo &a, const sockinfo &b)
{
  return a.host == b.host && a.port == b.port && a.prot == b.prot;
}

bool
operator < (const sockinfo &a, const sockinfo &b)
{
  return a.host < b.host
         || (a.host == b.host && (a.port < b.port
                                  || (a.port == b.port && a.prot < b.prot)));
}

