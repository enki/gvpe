/*
    vpn.C -- handle the protocol, encryption, handshaking etc.
    Copyright (C) 2003-2005 Marc Lehmann <gvpe@schmorp.de>
 
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
    Foundation, Inc. 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "config.h"

#include <list>

#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>

#include "netcompat.h"

#include "pidfile.h"

#include "connection.h"
#include "util.h"
#include "vpn.h"

vpn network; // THE vpn (bad design...)

/////////////////////////////////////////////////////////////////////////////

const char *vpn::script_if_up ()
{
  // the tunnel device mtu should be the physical mtu - overhead
  // the tricky part is rounding to the cipher key blocksize
  int mtu = conf.mtu - ETH_OVERHEAD - VPE_OVERHEAD - MAX_OVERHEAD;
  mtu += ETH_OVERHEAD - 6 - 6; // now we have the data portion
  mtu -= mtu % EVP_CIPHER_block_size (CIPHER); // round
  mtu -= ETH_OVERHEAD - 6 - 6; // and get interface mtu again

  char *env;
  asprintf (&env, "CONFBASE=%s", confbase); putenv (env);
  asprintf (&env, "NODENAME=%s", THISNODE->nodename); putenv (env);
  asprintf (&env, "NODEID=%d", THISNODE->id); putenv (env);
  asprintf (&env, "IFNAME=%s", tap->interface ()); putenv (env);
  asprintf (&env, "IFTYPE=%s", IFTYPE); putenv (env);
  asprintf (&env, "IFSUBTYPE=%s", IFSUBTYPE); putenv (env);
  asprintf (&env, "MTU=%d", mtu); putenv (env);
  asprintf (&env, "MAC=%02x:%02x:%02x:%02x:%02x:%02x",
            0xfe, 0xfd, 0x80, 0x00, THISNODE->id >> 8,
            THISNODE->id & 0xff);
  putenv (env);

  return ::conf.script_if_up ? ::conf.script_if_up : "if-up";
}

int
vpn::setup ()
{
  ipv4_fd = -1;

  if (THISNODE->protocols & PROT_IPv4 && ::conf.ip_proto)
    {
      ipv4_fd = socket (PF_INET, SOCK_RAW, ::conf.ip_proto);

      if (ipv4_fd < 0)
        return -1;

      fcntl (ipv4_fd, F_SETFL, O_NONBLOCK);

#if defined(SOL_IP) && defined(IP_MTU_DISCOVER)
      // this I really consider a linux bug. I am neither connected
      // nor do I fragment myself. Linux still sets DF and doesn't
      // fragment for me sometimes.
      {
        int oval = IP_PMTUDISC_DONT;
        setsockopt (ipv4_fd, SOL_IP, IP_MTU_DISCOVER, &oval, sizeof oval);
      }
#endif

      sockinfo si (THISNODE, PROT_IPv4);

      if (bind (ipv4_fd, si.sav4 (), si.salenv4 ()))
        {
          slog (L_ERR, _("can't bind ipv4 socket on %s: %s"), (const char *)si, strerror (errno));
          exit (EXIT_FAILURE);
        }

      ipv4_ev_watcher.start (ipv4_fd, EVENT_READ);
    }

  udpv4_fd = -1;

  if (THISNODE->protocols & PROT_UDPv4 && THISNODE->udp_port)
    {
      udpv4_fd = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);

      if (udpv4_fd < 0)
        return -1;

      fcntl (udpv4_fd, F_SETFL, O_NONBLOCK);

      // standard daemon practise...
      {
        int oval = 1;
        setsockopt (udpv4_fd, SOL_SOCKET, SO_REUSEADDR, &oval, sizeof oval);
      }

#if defined(SOL_IP) && defined(IP_MTU_DISCOVER)
      // this I really consider a linux bug. I am neither connected
      // nor do I fragment myself. Linux still sets DF and doesn't
      // fragment for me sometimes.
      {
        int oval = IP_PMTUDISC_DONT;
        setsockopt (udpv4_fd, SOL_IP, IP_MTU_DISCOVER, &oval, sizeof oval);
      }
#endif

      sockinfo si (THISNODE, PROT_UDPv4);

      if (bind (udpv4_fd, si.sav4 (), si.salenv4 ()))
        {
          slog (L_ERR, _("can't bind udpv4 on %s: %s"), (const char *)si, strerror (errno));
          exit (EXIT_FAILURE);
        }

      udpv4_ev_watcher.start (udpv4_fd, EVENT_READ);
    }

  icmpv4_fd = -1;

#if ENABLE_ICMP
  if (THISNODE->protocols & PROT_ICMPv4)
    {
      icmpv4_fd = socket (PF_INET, SOCK_RAW, IPPROTO_ICMP);

      if (icmpv4_fd < 0)
        return -1;

      fcntl (icmpv4_fd, F_SETFL, O_NONBLOCK);

#ifdef ICMP_FILTER
      {
        icmp_filter oval;
        oval.data = 0xffffffff;
        if (::conf.icmp_type < 32)
          oval.data &= ~(1 << ::conf.icmp_type);

        setsockopt (icmpv4_fd, SOL_RAW, ICMP_FILTER, &oval, sizeof oval);
      }
#endif

#if defined(SOL_IP) && defined(IP_MTU_DISCOVER)
      // this I really consider a linux bug. I am neither connected
      // nor do I fragment myself. Linux still sets DF and doesn't
      // fragment for me sometimes.
      {
        int oval = IP_PMTUDISC_DONT;
        setsockopt (udpv4_fd, SOL_IP, IP_MTU_DISCOVER, &oval, sizeof oval);
      }
#endif

      sockinfo si (THISNODE, PROT_ICMPv4);

      if (bind (icmpv4_fd, si.sav4 (), si.salenv4 ()))
        {
          slog (L_ERR, _("can't bind icmpv4 on %s: %s"), (const char *)si, strerror (errno));
          exit (EXIT_FAILURE);
        }

      icmpv4_ev_watcher.start (icmpv4_fd, EVENT_READ);
    }
#endif

  tcpv4_fd = -1;

#if ENABLE_TCP
  if (THISNODE->protocols & PROT_TCPv4 && THISNODE->tcp_port)
    {
      tcpv4_fd = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);

      if (tcpv4_fd < 0)
        return -1;

      fcntl (tcpv4_fd, F_SETFL, O_NONBLOCK);

      // standard daemon practise...
      {
        int oval = 1;
        setsockopt (tcpv4_fd, SOL_SOCKET, SO_REUSEADDR, &oval, sizeof oval);
      }

      sockinfo si (THISNODE, PROT_TCPv4);

      if (bind (tcpv4_fd, si.sav4 (), si.salenv4 ()))
        {
          slog (L_ERR, _("can't bind tcpv4 on %s: %s"), (const char *)si, strerror (errno));
          exit (EXIT_FAILURE);
        }

      if (listen (tcpv4_fd, 5))
        {
          slog (L_ERR, _("can't listen tcpv4 on %s: %s"), (const char *)si, strerror (errno));
          exit (EXIT_FAILURE);
        }

      tcpv4_ev_watcher.start (tcpv4_fd, EVENT_READ);
    }
#endif

#if ENABLE_DNS
  if (THISNODE->protocols & PROT_DNSv4)
    {
      dnsv4_fd = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);

      if (dnsv4_fd < 0)
        return -1;

      // standard daemon practise...
      {
        int oval = 1;
        setsockopt (tcpv4_fd, SOL_SOCKET, SO_REUSEADDR, &oval, sizeof oval);
      }

      sockinfo si (THISNODE, PROT_DNSv4);

      if (bind (dnsv4_fd, si.sav4 (), si.salenv4 ()))
        {
          slog (L_ERR, _("can't bind dnsv4 on %s: %s"), (const char *)si, strerror (errno));
          exit (EXIT_FAILURE);
        }

      dnsv4_ev_watcher.start (dnsv4_fd, EVENT_READ);
    }
#endif

  tap = new tap_device ();
  if (!tap) //D this, of course, never catches
    {
      slog (L_ERR, _("cannot create network interface '%s'"), conf.ifname);
      exit (EXIT_FAILURE);
    }
  
  run_script (run_script_cb (this, &vpn::script_if_up), true);

  tap_ev_watcher.start (tap->fd, EVENT_READ);

  reconnect_all ();

  return 0;
}

bool
vpn::send_ipv4_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
#if defined(SOL_IP) && defined(IP_TOS)
  setsockopt (ipv4_fd, SOL_IP, IP_TOS, &tos, sizeof tos);
#endif
  sendto (ipv4_fd, &((*pkt)[0]), pkt->len, 0, si.sav4 (), si.salenv4 ());

  return true;
}

static u16
ipv4_checksum (u16 *data, unsigned int len)
{
  // use 32 bit accumulator and fold back carry bits at the end
  u32 sum = 0;

  while (len > 1)
    {
      sum += *data++;
      len -= 2;
    }

  // odd byte left?
  if (len)
    sum += *(u8 *)data;

  // add back carry bits
  sum = (sum >> 16) + (sum & 0xffff);	// lo += hi
  sum += (sum >> 16);			// carry

  return ~sum;
}

#if ENABLE_ICMP
bool
vpn::send_icmpv4_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
#if defined(SOL_IP) && defined(IP_TOS)
  setsockopt (icmpv4_fd, SOL_IP, IP_TOS, &tos, sizeof tos);
#endif

  pkt->unshift_hdr (4);

  icmp_header *hdr = (icmp_header *)&((*pkt)[0]);
  hdr->type = ::conf.icmp_type;
  hdr->code = 255;
  hdr->checksum = 0;
  hdr->checksum = ipv4_checksum ((u16 *)hdr, pkt->len);

  sendto (icmpv4_fd, &((*pkt)[0]), pkt->len, 0, si.sav4 (), si.salenv4 ());

  return true;
}
#endif

bool
vpn::send_udpv4_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
#if defined(SOL_IP) && defined(IP_TOS)
  setsockopt (udpv4_fd, SOL_IP, IP_TOS, &tos, sizeof tos);
#endif
  sendto (udpv4_fd, &((*pkt)[0]), pkt->len, 0, si.sav4 (), si.salenv4 ());

  return true;
}

void
vpn::inject_data_packet (tap_packet *pkt, int dst)
{
  if (dst)
    {
      // unicast
      if (dst != THISNODE->id)
        conns[dst - 1]->inject_data_packet (pkt);
    }
  else
    {
      // broadcast, this is ugly, but due to the security policy
      // we have to connect to all hosts...
      for (conns_vector::iterator c = conns.begin (); c != conns.end (); ++c)
        if ((*c)->conf != THISNODE)
          (*c)->inject_data_packet (pkt, true);
  }
}

void
vpn::recv_vpn_packet (vpn_packet *pkt, const sockinfo &rsi)
{
  unsigned int src = pkt->src ();
  unsigned int dst = pkt->dst ();

  slog (L_NOISE, _("<<?/%s received possible vpn packet type %d from %d to %d, length %d"),
        (const char *)rsi, pkt->typ (), pkt->src (), pkt->dst (), pkt->len);

  if (src == 0 || src > conns.size ()
      || dst > conns.size ()
      || pkt->typ () >= vpn_packet::PT_MAX)
    slog (L_WARN, _("(%s): received corrupted packet type %d (src %d, dst %d)"),
          (const char *)rsi, pkt->typ (), pkt->src (), pkt->dst ());
  else if (dst > conns.size ())
    slog (L_WARN, _("(%s): received corrupted packet type %d (src %d, dst %d)"),
          (const char *)rsi, pkt->typ (), pkt->src (), pkt->dst ());
  else
    {
      connection *c = conns[src - 1];

      if (dst == 0)
        slog (L_WARN, _("%s(%s): received broadcast (protocol violation)"),
              c->conf->nodename, (const char *)rsi);
      else if (dst != THISNODE->id)
        {
          if (THISNODE->routerprio)
            // the tos setting gets lost here. who cares.
            conns[dst - 1]->inject_vpn_packet (pkt);
          else
            slog (L_WARN,
                  _("%s(%s): forwarding request (=> %s), but we are no router"),
                  c->conf->nodename, (const char *)rsi,
                  conns[dst - 1]->conf->nodename);
        }
      else
        c->recv_vpn_packet (pkt, rsi);
    }
}

void
vpn::ipv4_ev (io_watcher &w, short revents)
{
  if (revents & EVENT_READ)
    {
      vpn_packet *pkt = new vpn_packet;
      struct sockaddr_in sa;
      socklen_t sa_len = sizeof (sa);
      int len;

      len = recvfrom (w.fd, &((*pkt)[0]), MAXSIZE, 0, (sockaddr *)&sa, &sa_len);

      sockinfo si(sa, PROT_IPv4);

      if (len > 0)
        {
          pkt->len = len;

          // raw sockets deliver the ipv4, but don't expect it on sends
          // this is slow, but...
          pkt->skip_hdr (IP_OVERHEAD);

          recv_vpn_packet (pkt, si);
        }
      else
        {
          // probably ECONNRESET or somesuch
          slog (L_DEBUG, _("%s: %s"), (const char *)si, strerror (errno));
        }

      delete pkt;
    }
  else
    {
      slog (L_ERR,
              _("FATAL: unknown revents %08x in socket, terminating\n"),
              revents);
      exit (EXIT_FAILURE);
    }
}

#if ENABLE_ICMP
void
vpn::icmpv4_ev (io_watcher &w, short revents)
{
  if (revents & EVENT_READ)
    {
      vpn_packet *pkt = new vpn_packet;
      struct sockaddr_in sa;
      socklen_t sa_len = sizeof (sa);
      int len;

      len = recvfrom (w.fd, &((*pkt)[0]), MAXSIZE, 0, (sockaddr *)&sa, &sa_len);

      sockinfo si(sa, PROT_ICMPv4);

      if (len > 0)
        {
          pkt->len = len;

          icmp_header *hdr = (icmp_header *)&((*pkt)[IP_OVERHEAD]);

          if (hdr->type == ::conf.icmp_type
              && hdr->code == 255)
            {
              // raw sockets deliver the ipv4, but don't expect it on sends
              // this is slow, but...
              pkt->skip_hdr (ICMP_OVERHEAD);

              recv_vpn_packet (pkt, si);
            }
        }
      else
        {
          // probably ECONNRESET or somesuch
          slog (L_DEBUG, _("%s: %s"), (const char *)si, strerror (errno));
        }

      delete pkt;
    }
  else
    {
      slog (L_ERR,
              _("FATAL: unknown revents %08x in socket, terminating\n"),
              revents);
      exit (EXIT_FAILURE);
    }
}
#endif

void
vpn::udpv4_ev (io_watcher &w, short revents)
{
  if (revents & EVENT_READ)
    {
      vpn_packet *pkt = new vpn_packet;
      struct sockaddr_in sa;
      socklen_t sa_len = sizeof (sa);
      int len;

      len = recvfrom (w.fd, &((*pkt)[0]), MAXSIZE, 0, (sockaddr *)&sa, &sa_len);

      sockinfo si(sa, PROT_UDPv4);

      if (len > 0)
        {
          pkt->len = len;

          recv_vpn_packet (pkt, si);
        }
      else
        {
          // probably ECONNRESET or somesuch
          slog (L_DEBUG, _("%s: fd %d, %s"), (const char *)si, w.fd, strerror (errno));
        }

      delete pkt;
    }
  else
    {
      slog (L_ERR,
              _("FATAL: unknown revents %08x in socket, terminating\n"),
              revents);
      exit (EXIT_FAILURE);
    }
}

void
vpn::tap_ev (io_watcher &w, short revents)
{
  if (revents & EVENT_READ)
    {
      /* process data */
      tap_packet *pkt;

      pkt = tap->recv ();

      if (!pkt)
        return;

      if (pkt->len > 14)
        {
          int dst = mac2id (pkt->dst);
          int src = mac2id (pkt->src);

          if (src != THISNODE->id)
            {
              slog (L_ERR, _("FATAL: tap packet not originating on current node received, exiting."));
              exit (EXIT_FAILURE);
            }

          if (dst == THISNODE->id)
            {
              slog (L_ERR, _("FATAL: tap packet destined for current node received, exiting."));
              exit (EXIT_FAILURE);
            }

          if (dst > conns.size ())
            slog (L_ERR, _("tap packet for unknown node %d received, ignoring."), dst);
          else
            inject_data_packet (pkt, dst);
        }

      delete pkt;
    }
  else
    abort ();
}

void
vpn::event_cb (time_watcher &w)
{
  if (events)
    {
      if (events & EVENT_SHUTDOWN)
        {
          slog (L_INFO, _("preparing shutdown..."));

          shutdown_all ();
          remove_pid (conf.pidfilename);
          slog (L_INFO, _("terminating"));
          exit (EXIT_SUCCESS);
        }

      if (events & EVENT_RECONNECT)
        {
          slog (L_INFO, _("forced reconnect"));

          reconnect_all ();
        }

      events = 0;
    }
}

void
vpn::shutdown_all ()
{
  for (conns_vector::iterator c = conns.begin (); c != conns.end (); ++c)
    (*c)->shutdown ();
}

void
vpn::reconnect_all ()
{
  for (conns_vector::iterator c = conns.begin (); c != conns.end (); ++c)
    delete *c;

  conns.clear ();

  connection_init ();

  for (configuration::node_vector::iterator i = conf.nodes.begin ();
       i != conf.nodes.end (); ++i)
    {
      connection *conn = new connection (this, *i);
      conns.push_back (conn);
      conn->establish_connection ();
    }
}

connection *vpn::find_router ()
{
  u32 prio = 1;
  connection *router = 0;

  for (conns_vector::iterator i = conns.begin (); i != conns.end (); ++i)
    {
      connection *c = *i;

      if (c->conf->routerprio > prio
          && c->connectmode == conf_node::C_ALWAYS // so we don't drop the connection if in use
          && c->ictx && c->octx
          && c->conf != THISNODE)                  // redundant, since ictx==octx==0 always on thisnode
        {
          prio = c->conf->routerprio;
          router = c;
        }
    }

  return router;
}

void vpn::send_connect_request (int id)
{
  connection *c = find_router ();

  if (c)
    c->send_connect_request (id);
  else
    // no router found, aggressively connect to all routers
    for (conns_vector::iterator i = conns.begin (); i != conns.end (); ++i)
      if ((*i)->conf->routerprio && (*i)->conf != THISNODE)
        (*i)->establish_connection ();
}

void
connection::dump_status ()
{
  slog (L_NOTICE, _("node %s (id %d)"), conf->nodename, conf->id);
  slog (L_NOTICE, _("  connectmode %d (%d) / sockaddr %s / minor %d"),
        connectmode, conf->connectmode, (const char *)si, (int)prot_minor);
  slog (L_NOTICE, _("  ictx/octx %08lx/%08lx / oseqno %d / retry_cnt %d"),
        (long)ictx, (long)octx, (int)oseqno, (int)retry_cnt);
  slog (L_NOTICE, _("  establish_conn %ld / rekey %ld / keepalive %ld"),
        (long)(establish_connection.at), (long)(rekey.at), (long)(keepalive.at));
}

void
vpn::dump_status ()
{
  slog (L_NOTICE, _("BEGIN status dump (%ld)"), (long)NOW);

  for (conns_vector::iterator c = conns.begin (); c != conns.end (); ++c)
    (*c)->dump_status ();

  slog (L_NOTICE, _("END status dump"));
}

vpn::vpn (void)
: event            (this, &vpn::event_cb)
, udpv4_ev_watcher (this, &vpn::udpv4_ev)
, ipv4_ev_watcher  (this, &vpn::ipv4_ev)
#if ENABLE_TCP
, tcpv4_ev_watcher (this, &vpn::tcpv4_ev)
#endif
#if ENABLE_ICMP
, icmpv4_ev_watcher(this, &vpn::icmpv4_ev)
#endif
#if ENABLE_DNS
, dnsv4_ev_watcher (this, &vpn::dnsv4_ev)
#endif
, tap_ev_watcher   (this, &vpn::tap_ev)
{
}

vpn::~vpn ()
{
}

