/*
    vpn_dns.C -- handle the dns tunnel part of the protocol.
    Copyright (C) 2003-2004 Marc Lehmann <pcg@goof.com>
 
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

#if ENABLE_DNS

// dns processing is EXTREMELY ugly. For obvious(?) reasons.
// it's a hack, use only in emergency situations please.

#include <cstring>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <map>

#include "netcompat.h"

#include "vpn.h"

#if ENABLE_HTTP_PROXY
# include "conf.h"
#endif

#define MIN_RETRY 1.
#define MAX_RETRY 60.

#define SERVER conf.dns_port

/*

protocol, in shorthand :)

<cseqno> ANY?	poll for more data
   => TXT <sseqno><data>
<cseqno><data> TXT?	send more data
   => TXT <empty>

sequence numbers are 12 bit, 9 bit packet-number and 3 bit fragment id (7
- id, actually) last fragment is sent first, however

*/

void
vpn::dnsv4_ev (io_watcher &w, short revents)
{
  if (revents & EVENT_READ)
    {
      struct sockaddr_in sa;
      socklen_t sa_len = sizeof (sa);
      int len;
    }
}

bool
vpn::send_dnsv4_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
  //return i->send_packet (pkt, tos);
}

#endif

