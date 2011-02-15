/*
    vpn.C -- handle the protocol, encryption, handshaking etc.
    Copyright (C) 2003-2008,2010,2011 Marc Lehmann <gvpe@schmorp.de>
 
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

static void inline
set_tos (int fd, int &tos_prev, int tos)
{
#if defined(SOL_IP) && defined(IP_TOS)
  if (tos_prev == tos)
    return;

  tos_prev = tos;
  setsockopt (fd, SOL_IP, IP_TOS, &tos, sizeof tos);
#endif
}

void
vpn::script_init_env ()
{
  // the tunnel device mtu should be the physical mtu - overhead
  // the tricky part is rounding to the cipher key blocksize
  int mtu = conf.mtu - ETH_OVERHEAD - VPE_OVERHEAD - MAX_OVERHEAD;
  mtu += ETH_OVERHEAD - 6 - 6; // now we have the data portion
  mtu -= mtu % EVP_CIPHER_block_size (CIPHER); // round
  mtu -= ETH_OVERHEAD - 6 - 6; // and get interface mtu again

  char *env;
  asprintf (&env, "CONFBASE=%s", confbase); putenv (env);
  asprintf (&env, "IFNAME=%s", tap->interface ()); putenv (env);
  asprintf (&env, "IFTYPE=%s", IFTYPE); putenv (env);
  asprintf (&env, "IFSUBTYPE=%s", IFSUBTYPE); putenv (env);
  asprintf (&env, "MTU=%d", mtu); putenv (env);
  asprintf (&env, "NODES=%d", conns.size ()); putenv (env);
  asprintf (&env, "NODEID=%d", THISNODE->id); putenv (env);

  conns [THISNODE->id - 1]->script_init_env ("");

  for (conns_vector::iterator c = conns.begin (); c != conns.end (); ++c)
    {
      char ext[16];
      snprintf (ext, 16, "_%d", (*c)->conf->id);
      (*c)->script_init_env (ext);
    }
}

inline const char *
vpn::script_if_init ()
{
  script_init_env ();

  return tap->if_up ();
}

inline const char *
vpn::script_if_up ()
{
  script_init_env ();

  char *filename;
  asprintf (&filename,
            "%s/%s",
            confbase,
            ::conf.script_if_up ? ::conf.script_if_up : "if-up");

  return filename;
}

int
vpn::setup_socket (u8 prot, int family, int type, int proto)
{
  int fd = socket (family, type, proto);

  if (fd < 0)
    {
      slog (L_ERR, _("unable to create %s socket: %s."), strprotocol (prot), strerror (errno));
      return fd;
    }

  fcntl (fd, F_SETFL, O_NONBLOCK);
  fcntl (fd, F_SETFD, FD_CLOEXEC);

#ifdef SO_MARK
  if (::conf.nfmark)
    if (setsockopt (fd, SOL_SOCKET, SO_MARK, &::conf.nfmark, sizeof ::conf.nfmark))
      slog (L_WARN, _("unable to set nfmark on %s socket: %s"), strprotocol (prot), strerror (errno));
#endif

  return fd;
}

int
vpn::setup ()
{
  int success = 0;

  ipv4_tos = -1;
  ipv4_fd  = -1;

  if (THISNODE->protocols & PROT_IPv4 && ::conf.ip_proto)
    {
      ipv4_fd = setup_socket (PROT_IPv4, PF_INET, SOCK_RAW, ::conf.ip_proto);

      if (ipv4_fd < 0)
        return -1;

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
          slog (L_ERR, _("can't bind ipv4 socket on %s: %s, exiting."), (const char *)si, strerror (errno));
          return -1;
        }

      ipv4_ev_watcher.start (ipv4_fd, EV_READ);
      ++success;
    }
  else
    THISNODE->protocols &= ~PROT_IPv4;

  udpv4_tos = -1;
  udpv4_fd  = -1;

  if (THISNODE->protocols & PROT_UDPv4 && THISNODE->udp_port)
    {
      udpv4_fd = setup_socket (PROT_UDPv4, PF_INET, SOCK_DGRAM, IPPROTO_UDP);

      if (udpv4_fd < 0)
        return -1;

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
          slog (L_ERR, _("can't bind udpv4 on %s: %s, exiting."), (const char *)si, strerror (errno));
          return -1;
        }

      udpv4_ev_watcher.start (udpv4_fd, EV_READ);
      ++success;
    }
  else
    THISNODE->protocols &= ~PROT_UDPv4;

  icmpv4_tos = -1;
  icmpv4_fd  = -1;

#if ENABLE_ICMP
  if (THISNODE->protocols & PROT_ICMPv4)
    {
      icmpv4_fd = setup_socket (PROT_ICMPv4, PF_INET, SOCK_RAW, IPPROTO_ICMP);

      if (icmpv4_fd < 0)
        return -1;

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
        setsockopt (icmpv4_fd, SOL_IP, IP_MTU_DISCOVER, &oval, sizeof oval);
      }
#endif

      sockinfo si (THISNODE, PROT_ICMPv4);

      if (bind (icmpv4_fd, si.sav4 (), si.salenv4 ()))
        {
          slog (L_ERR, _("can't bind icmpv4 on %s: %s, exiting."), (const char *)si, strerror (errno));
          return -1;
        }

      icmpv4_ev_watcher.start (icmpv4_fd, EV_READ);
      ++success;
    }
#endif

  tcpv4_fd = -1;

#if ENABLE_TCP
  if (THISNODE->protocols & PROT_TCPv4 && THISNODE->tcp_port)
    {
      tcpv4_fd = setup_socket (PROT_TCPv4, PF_INET, SOCK_STREAM, IPPROTO_TCP);

      if (tcpv4_fd < 0)
        return -1;

      // standard daemon practise...
      {
        int oval = 1;
        setsockopt (tcpv4_fd, SOL_SOCKET, SO_REUSEADDR, &oval, sizeof oval);
      }

      sockinfo si (THISNODE, PROT_TCPv4);

      if (bind (tcpv4_fd, si.sav4 (), si.salenv4 ()))
        {
          slog (L_ERR, _("can't bind tcpv4 on %s: %s, exiting."), (const char *)si, strerror (errno));
          return -1;
        }

      if (listen (tcpv4_fd, 5))
        {
          slog (L_ERR, _("can't listen tcpv4 on %s: %s, exiting."), (const char *)si, strerror (errno));
          return -1;
        }

      tcpv4_ev_watcher.start (tcpv4_fd, EV_READ);
      ++success;
    }
  else
    THISNODE->protocols &= ~PROT_TCPv4;
#endif

  dnsv4_tos = -1;
  dnsv4_fd  = -1;

#if ENABLE_DNS
  if (THISNODE->protocols & PROT_DNSv4)
    {
      dns_forwarder.set (::conf.dns_forw_host, ::conf.dns_forw_port, PROT_DNSv4);

      dnsv4_fd = setup_socket (PROT_DNSv4, PF_INET, SOCK_DGRAM, IPPROTO_UDP);

      if (dnsv4_fd < 0)
        return -1;

# if defined(SOL_IP) && defined(IP_MTU_DISCOVER)
      // this I really consider a linux bug. I am neither connected
      // nor do I fragment myself. Linux still sets DF and doesn't
      // fragment for me sometimes.
      {
        int oval = IP_PMTUDISC_DONT;
        setsockopt (dnsv4_fd, SOL_IP, IP_MTU_DISCOVER, &oval, sizeof oval);
      }
# endif

      // standard daemon practise...
      {
        int oval = 1;
        setsockopt (dnsv4_fd, SOL_SOCKET, SO_REUSEADDR, &oval, sizeof oval);
      }

      sockinfo si (THISNODE->dns_hostname,
                   THISNODE->dns_hostname ? THISNODE->dns_port : 0,
                   PROT_DNSv4);

      if (bind (dnsv4_fd, si.sav4 (), si.salenv4 ()))
        {
          slog (L_ERR, _("can't bind dnsv4 on %s: %s, exiting."), (const char *)si, strerror (errno));
          return -1;
        }

      dnsv4_ev_watcher.start (dnsv4_fd, EV_READ);
      ++success;
    }
#endif

  /////////////////////////////////////////////////////////////////////////////

  if (!success)
    {
      slog (L_ERR, _("no protocols enabled."));
      return -1;
    }

  reconnect_all ();

  /////////////////////////////////////////////////////////////////////////////

  tap = new tap_device ();
  if (!tap) //D this, of course, never catches
    {
      slog (L_ERR, _("cannot create network interface '%s'."), conf.ifname);
      return -1;
    }
  
  fcntl (tap->fd, F_SETFD, FD_CLOEXEC);

  run_script_cb cb;
  cb.set<vpn, &vpn::script_if_init> (this);

  if (tap->if_up () &&
      !run_script (cb, true))
    {
      slog (L_ERR, _("interface initialization command '%s' failed."),
            tap->if_up ());
      return -1;
    }

  cb.set<vpn, &vpn::script_if_up> (this);
  if (!run_script (cb, true))
    {
      slog (L_ERR, _("if-up command execution failed."));
      return -1;
    }

  tap_ev_watcher.start (tap->fd, EV_READ);

  return 0;
}

bool
vpn::send_ipv4_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
  set_tos (ipv4_fd, ipv4_tos, tos);
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
  pkt->unshift_hdr (4);

  icmp_header *hdr = (icmp_header *)&((*pkt)[0]);
  hdr->type = ::conf.icmp_type;
  hdr->code = 255;
  hdr->checksum = 0;
  hdr->checksum = ipv4_checksum ((u16 *)hdr, pkt->len);

  set_tos (icmpv4_fd, icmpv4_tos, tos);
  sendto (icmpv4_fd, &((*pkt)[0]), pkt->len, 0, si.sav4 (), si.salenv4 ());

  return true;
}
#endif

bool
vpn::send_udpv4_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
  set_tos (udpv4_fd, udpv4_tos, tos);
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
          (*c)->inject_data_packet (pkt);
  }
}

void
vpn::recv_vpn_packet (vpn_packet *pkt, const sockinfo &rsi)
{
  unsigned int src = pkt->src ();
  unsigned int dst = pkt->dst ();

  slog (L_NOISE, _("<<?/%s received possible vpn packet type %d from %d to %d, length %d."),
        (const char *)rsi, pkt->typ (), pkt->src (), pkt->dst (), pkt->len);

  if (src == 0 || src > conns.size ()
      || dst > conns.size ()
      || pkt->typ () >= vpn_packet::PT_MAX)
    slog (L_WARN, _("(%s): received corrupted packet type %d (src %d, dst %d)."),
          (const char *)rsi, pkt->typ (), pkt->src (), pkt->dst ());
  else if (dst > conns.size ())
    slog (L_WARN, _("(%s): received corrupted packet type %d (src %d, dst %d)."),
          (const char *)rsi, pkt->typ (), pkt->src (), pkt->dst ());
  else
    {
      connection *c = conns[src - 1];

      if (dst == 0)
        slog (L_WARN, _("%s(%s): received broadcast (protocol violation)."),
              c->conf->nodename, (const char *)rsi);
      else if (dst != THISNODE->id)
        {
          if (THISNODE->routerprio)
            // the tos setting gets lost here. who cares.
            conns[dst - 1]->inject_vpn_packet (pkt);
          else
            slog (L_WARN,
                  _("%s(%s): request to forward packet to %s, but we are no router (config mismatch?)."),
                  c->conf->nodename, (const char *)rsi,
                  conns[dst - 1]->conf->nodename);
        }
      else
        c->recv_vpn_packet (pkt, rsi);
    }
}

bool
vpn::send_vpn_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
  switch (si.prot)
    {
      case PROT_IPv4:
        return send_ipv4_packet (pkt, si, tos);

      case PROT_UDPv4:
        return send_udpv4_packet (pkt, si, tos);

#if ENABLE_TCP
      case PROT_TCPv4:
        return send_tcpv4_packet (pkt, si, tos);
#endif
#if ENABLE_ICMP
      case PROT_ICMPv4:
        return send_icmpv4_packet (pkt, si, tos);
#endif
#if ENABLE_DNS
      case PROT_DNSv4:
        return send_dnsv4_packet (pkt, si, tos);
#endif
      default:
        slog (L_CRIT, _("%s: FATAL: trying to send packet with unsupported protocol."), (const char *)si);
    }

  return false;
}

inline void
vpn::ipv4_ev (ev::io &w, int revents)
{
  if (revents & EV_READ)
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

          // raw sockets deliver the ipv4 header, but don't expect it on sends
          pkt->skip_hdr (IP_OVERHEAD);

          recv_vpn_packet (pkt, si);
        }
      else
        {
          // probably ECONNRESET or somesuch
          slog (L_DEBUG, _("%s: %s."), (const char *)si, strerror (errno));
        }

      delete pkt;
    }
  else
    {
      slog (L_ERR,
            _("FATAL: unknown revents %08x in socket, exiting.\n"),
            revents);
      exit (EXIT_FAILURE);
    }
}

#if ENABLE_ICMP
inline void
vpn::icmpv4_ev (ev::io &w, int revents)
{
  if (revents & EV_READ)
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
          slog (L_DEBUG, _("%s: %s."), (const char *)si, strerror (errno));
        }

      delete pkt;
    }
  else
    {
      slog (L_ERR,
              _("FATAL: unknown revents %08x in socket, exiting.\n"),
              revents);
      exit (EXIT_FAILURE);
    }
}
#endif

inline void
vpn::udpv4_ev (ev::io &w, int revents)
{
  if (revents & EV_READ)
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
          slog (L_DEBUG, _("%s: fd %d, %s."), (const char *)si, w.fd, strerror (errno));
        }

      delete pkt;
    }
  else
    {
      slog (L_ERR,
              _("FATAL: unknown revents %08x in socket, exiting.\n"),
              revents);
      exit (EXIT_FAILURE);
    }
}

inline void
vpn::tap_ev (ev::io &w, int revents)
{
  if (revents & EV_READ)
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
              slog (L_ERR, _("FATAL: tap packet not originating on current node received (if-up script not working properly?), exiting."));
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

inline void
vpn::event_cb (ev::timer &w, int)
{
  if (events)
    {
      if (events & EVENT_SHUTDOWN)
        {
          slog (L_INFO, _("preparing shutdown..."));

          shutdown_all ();
          remove_pid (conf.pidfilename);
          slog (L_INFO, _("exiting."));
          exit (EXIT_SUCCESS);
        }

      if (events & EVENT_RECONNECT)
        {
          slog (L_INFO, _("forced reconnect."));

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

  for (configuration::node_vector::iterator i = conf.nodes.begin (); i != conf.nodes.end (); ++i)
    conns.push_back (new connection (this, *i));

  for (conns_vector::iterator c = conns.begin (); c != conns.end (); ++c)
    (*c)->establish_connection ();
}

bool
vpn::can_direct (conf_node *src, conf_node *dst) const
{
  return src != dst
      && src->may_direct (dst)
      && dst->may_direct (src)
      && (((src->protocols & dst->protocols) && src->connectmode == conf_node::C_ALWAYS)
          || (src->protocols & dst->connectable_protocols ()));
}

// only works for indirect and routed connections: find a router
// from THISNODE to dst
connection *
vpn::find_router_for (const connection *dst)
{
  connection *router = 0;

  // first try to find a router with a direct connection, route there
  // regardless of any other considerations.
  {
    u32 prio = 1;

    for (conns_vector::iterator i = conns.begin (); i != conns.end (); ++i)
      {
        connection *c = *i;

        if (c->conf->routerprio > prio
            && c->conf != THISNODE
            && can_direct (c->conf, dst->conf)
            && c->ictx && c->octx)
          {
            prio = c->conf->routerprio;
            router = c;
          }
      }
  }

  if (router)
    return router;

  // second try find the router with the highest priority, higher than ours
  {
    u32 prio = THISNODE->routerprio ? THISNODE->routerprio : 1;

    for (conns_vector::iterator i = conns.begin (); i != conns.end (); ++i)
      {
        connection *c = *i;

        if (c->conf->routerprio > prio
            && c != dst
            && c->conf != THISNODE
            && c->ictx && c->octx)
          {
            prio = c->conf->routerprio;
            router = c;
          }
      }
  }

  return router;
}

void
vpn::connection_established (connection *c)
{
  for (conns_vector::iterator i = conns.begin (); i != conns.end (); ++i)
    {
      connection *o = *i;

      if (!o->is_direct
          && o->si.valid ()
          && c->si != o->si
          && c == find_router_for (o))
        {
          slog (L_DEBUG, _("%s: can now route packets via %s, re-keying connection."),
                o->conf->nodename, c->conf->nodename);
          o->rekey ();
        }
    }
}

void
vpn::send_connect_request (connection *c)
{
  connection *r = find_router_for (c);

  if (r)
    {
      slog (L_TRACE, _("%s: no address known, sending mediated connection request via %s."),
            c->conf->nodename, r->conf->nodename);
      r->send_connect_request (c->conf->id);
    }
  else
    slog (L_DEBUG, _("%s: no way to connect and no router found: unable to connect at this time."),
          c->conf->nodename);
}

void
connection::dump_status ()
{
  slog (L_NOTICE, _("node %s (id %d)"), conf->nodename, conf->id);
  slog (L_NOTICE, _("  connectmode %d (%d) / sockaddr %s / minor %d"),
        connectmode, conf->connectmode, (const char *)si, (int)prot_minor);
  slog (L_NOTICE, _("  ictx/octx %08lx/%08lx / oseqno %d / retry_cnt %d"),
        (long)ictx, (long)octx, (int)oseqno, (int)retry_cnt);
}

void
vpn::dump_status ()
{
  slog (L_NOTICE, _("BEGIN status dump (%ld)"), (long)ev_now ());

  for (conns_vector::iterator c = conns.begin (); c != conns.end (); ++c)
    (*c)->dump_status ();

  slog (L_NOTICE, _("END status dump"));
}

vpn::vpn (void)
{
  event            .set<vpn, &vpn::event_cb > (this);
  udpv4_ev_watcher .set<vpn, &vpn::udpv4_ev > (this);
  ipv4_ev_watcher  .set<vpn, &vpn::ipv4_ev  > (this);
#if ENABLE_TCP
  tcpv4_ev_watcher .set<vpn, &vpn::tcpv4_ev > (this);
#endif
#if ENABLE_ICMP
  icmpv4_ev_watcher.set<vpn, &vpn::icmpv4_ev> (this);
#endif
#if ENABLE_DNS
  dnsv4_ev_watcher .set<vpn, &vpn::dnsv4_ev > (this);
#endif
  tap_ev_watcher   .set<vpn, &vpn::tap_ev   > (this);
}

vpn::~vpn ()
{
}

