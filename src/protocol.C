/*
    protocol.C -- handle the protocol, encryption, handshaking etc.
 
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

#include <list>

#include <cstdlib>
#include <cstring>
#include <cstdio>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

#include "pidfile.h"

#include "connection.h"
#include "util.h"
#include "protocol.h"

/////////////////////////////////////////////////////////////////////////////

const char *vpn::script_if_up (int)
{
  // the tunnel device mtu should be the physical mtu - overhead
  // the tricky part is rounding to the cipher key blocksize
  int mtu = conf.mtu - ETH_OVERHEAD - VPE_OVERHEAD - MAX_OVERHEAD;
  mtu += ETH_OVERHEAD - 6 - 6; // now we have the data portion
  mtu -= mtu % EVP_CIPHER_block_size (CIPHER); // round
  mtu -= ETH_OVERHEAD - 6 - 6; // and get interface mtu again

  char *env;
  asprintf (&env, "CONFBASE=%s", confbase);
  putenv (env);
  asprintf (&env, "NODENAME=%s", THISNODE->nodename);
  putenv (env);
  asprintf (&env, "NODEID=%d", THISNODE->id);
  putenv (env);
  asprintf (&env, "IFNAME=%s", tap->interface ());
  putenv (env);
  asprintf (&env, "MTU=%d", mtu);
  putenv (env);
  asprintf (&env, "MAC=%02x:%02x:%02x:%02x:%02x:%02x",
            0xfe, 0xfd, 0x80, 0x00, THISNODE->id >> 8,
            THISNODE->id & 0xff);
  putenv (env);

  return ::conf.script_if_up ? ::conf.script_if_up : "if-up";
}

int
vpn::setup ()
{
  sockinfo si;

  si.set (THISNODE);

  udpv4_fd = -1;

  if (THISNODE->protocols & PROT_UDPv4)
    {
      udpv4_fd = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);

      if (udpv4_fd < 0)
        return -1;

      if (bind (udpv4_fd, si.sav4 (), si.salenv4 ()))
        {
          slog (L_ERR, _("can't bind udpv4 to %s: %s"), (const char *)si, strerror (errno));
          exit (1);
        }

#ifdef IP_MTU_DISCOVER
      // this I really consider a linux bug. I am neither connected
      // nor do I fragment myself. Linux still sets DF and doesn't
      // fragment for me sometimes.
      {
        int oval = IP_PMTUDISC_DONT;
        setsockopt (udpv4_fd, SOL_IP, IP_MTU_DISCOVER, &oval, sizeof oval);
      }
#endif

      // standard daemon practise...
      {
        int oval = 1;
        setsockopt (udpv4_fd, SOL_SOCKET, SO_REUSEADDR, &oval, sizeof oval);
      }

      udpv4_ev_watcher.start (udpv4_fd, POLLIN);
    }

  ipv4_fd = -1;
  if (THISNODE->protocols & PROT_IPv4)
    {
      ipv4_fd = socket (PF_INET, SOCK_RAW, ::conf.ip_proto);

      if (ipv4_fd < 0)
        return -1;

      if (bind (ipv4_fd, si.sav4 (), si.salenv4 ()))
        {
          slog (L_ERR, _("can't bind ipv4 socket to %s: %s"), (const char *)si, strerror (errno));
          exit (1);
        }

#ifdef IP_MTU_DISCOVER
      // this I really consider a linux bug. I am neither connected
      // nor do I fragment myself. Linux still sets DF and doesn't
      // fragment for me sometimes.
      {
        int oval = IP_PMTUDISC_DONT;
        setsockopt (ipv4_fd, SOL_IP, IP_MTU_DISCOVER, &oval, sizeof oval);
      }
#endif

      ipv4_ev_watcher.start (ipv4_fd, POLLIN);
    }

  tap = new tap_device ();
  if (!tap) //D this, of course, never catches
    {
      slog (L_ERR, _("cannot create network interface '%s'"), conf.ifname);
      exit (1);
    }
  
  run_script (run_script_cb (this, &vpn::script_if_up), true);

  tap_ev_watcher.start (tap->fd, POLLIN);

  reconnect_all ();

  return 0;
}

void
vpn::send_ipv4_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
  setsockopt (ipv4_fd, SOL_IP, IP_TOS, &tos, sizeof tos);
  sendto (ipv4_fd, &((*pkt)[0]), pkt->len, 0, si.sav4 (), si.salenv4 ());
}

void
vpn::send_udpv4_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
  setsockopt (udpv4_fd, SOL_IP, IP_TOS, &tos, sizeof tos);
  sendto (udpv4_fd, &((*pkt)[0]), pkt->len, 0, si.sav4 (), si.salenv4 ());
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
  else
    {
      connection *c = conns[src - 1];

      if (dst == 0 && !THISNODE->routerprio)
        slog (L_WARN, _("%s(%s): received broadcast, but we are no router"),
              c->conf->nodename, (const char *)rsi);
      else if (dst != 0 && dst != THISNODE->id)
        // FORWARDING NEEDED ;)
        slog (L_WARN,
              _("received frame for node %d ('%s') from %s, but this is node %d ('%s')"),
              dst, conns[dst - 1]->conf->nodename,
              (const char *)rsi,
              THISNODE->id, THISNODE->nodename);
      else
        c->recv_vpn_packet (pkt, rsi);
    }
}

void
vpn::udpv4_ev (short revents)
{
  if (revents & (POLLIN | POLLERR))
    {
      vpn_packet *pkt = new vpn_packet;
      struct sockaddr_in sa;
      socklen_t sa_len = sizeof (sa);
      int len;

      len = recvfrom (udpv4_fd, &((*pkt)[0]), MAXSIZE, 0, (sockaddr *)&sa, &sa_len);

      sockinfo si(sa);

      if (len > 0)
        {
          pkt->len = len;

          recv_vpn_packet (pkt, si);
        }
      else
        {
          // probably ECONNRESET or somesuch
          slog (L_DEBUG, _("%s: %s"), (const char *)si, strerror (errno));
        }

      delete pkt;
    }
  else if (revents & POLLHUP)
    {
      // this cannot ;) happen on udp sockets
      slog (L_ERR, _("FATAL: POLLHUP on udp v4 fd, terminating."));
      exit (1);
    }
  else
    {
      slog (L_ERR,
              _("FATAL: unknown revents %08x in socket, terminating\n"),
              revents);
      exit (1);
    }
}

void
vpn::ipv4_ev (short revents)
{
  if (revents & (POLLIN | POLLERR))
    {
      vpn_packet *pkt = new vpn_packet;
      struct sockaddr_in sa;
      socklen_t sa_len = sizeof (sa);
      int len;

      len = recvfrom (ipv4_fd, &((*pkt)[0]), MAXSIZE, 0, (sockaddr *)&sa, &sa_len);

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
  else if (revents & POLLHUP)
    {
      // this cannot ;) happen on udp sockets
      slog (L_ERR, _("FATAL: POLLHUP on ipv4 fd, terminating."));
      exit (1);
    }
  else
    {
      slog (L_ERR,
              _("FATAL: unknown revents %08x in socket, terminating\n"),
              revents);
      exit (1);
    }
}

void
vpn::tap_ev (short revents)
{
  if (revents & POLLIN)
    {
      /* process data */
      tap_packet *pkt;

      pkt = tap->recv ();

      int dst = mac2id (pkt->dst);
      int src = mac2id (pkt->src);

      if (src != THISNODE->id)
        {
          slog (L_ERR, _("FATAL: tap packet not originating on current node received, terminating."));
          exit (1);
        }

      if (dst == THISNODE->id)
        {
          slog (L_ERR, _("FATAL: tap packet destined for current node received, terminating."));
          exit (1);
        }

      if (dst > conns.size ())
        slog (L_ERR, _("tap packet for unknown node %d received, ignoring."), dst);
      else
        {
          if (dst)
            {
              // unicast
              if (dst != THISNODE->id)
                conns[dst - 1]->inject_data_packet (pkt);
            }
          else
            {
              // broadcast, first check router, then self, then english
              connection *router = find_router ();

              if (router)
                router->inject_data_packet (pkt, true);
              else
                for (conns_vector::iterator c = conns.begin (); c != conns.end (); ++c)
                  if ((*c)->conf != THISNODE)
                    (*c)->inject_data_packet (pkt);
            }
        }

      delete pkt;
    }
  else if (revents & (POLLHUP | POLLERR))
    {
      slog (L_ERR, _("FATAL: POLLHUP or POLLERR on network device fd, terminating."));
      exit (1);
    }
  else
    abort ();
}

void
vpn::event_cb (tstamp &ts)
{
  if (events)
    {
      if (events & EVENT_SHUTDOWN)
        {
          slog (L_INFO, _("preparing shutdown..."));

          shutdown_all ();

          remove_pid (pidfilename);

          slog (L_INFO, _("terminating"));

          exit (0);
        }

      if (events & EVENT_RECONNECT)
        {
          slog (L_INFO, _("forced reconnect"));

          reconnect_all ();
        }

      events = 0;
    }

  ts = TSTAMP_CANCEL;
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
      connection *conn = new connection (this);

      conn->conf = *i;
      conns.push_back (conn);

      conn->establish_connection ();
    }
}

connection *vpn::find_router ()
{
  u32 prio = 0;
  connection *router = 0;

  for (conns_vector::iterator i = conns.begin (); i != conns.end (); ++i)
    {
      connection *c = *i;

      if (c->conf->routerprio > prio
          && c->connectmode == conf_node::C_ALWAYS
          && c->conf != THISNODE
          && c->ictx && c->octx)
        {
          prio = c->conf->routerprio;
          router = c;
        }
    }

  return router;
}

void vpn::connect_request (int id)
{
  connection *c = find_router ();

  if (c)
    c->connect_request (id);
  //else // does not work, because all others must connect to the same router
  //  // no router found, aggressively connect to all routers
  //  for (conns_vector::iterator i = conns.begin (); i != conns.end (); ++i)
  //    if ((*i)->conf->routerprio)
  //      (*i)->establish_connection ();
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
: udpv4_ev_watcher(this, &vpn::udpv4_ev)
, ipv4_ev_watcher(this, &vpn::ipv4_ev)
, tap_ev_watcher(this, &vpn::tap_ev)
, event(this, &vpn::event_cb)
{
}

vpn::~vpn ()
{
}

