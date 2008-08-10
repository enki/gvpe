/*
    vpn.h -- header for vpn.C
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

#ifndef GVPE_VPN_H__
#define GVPE_VPN_H__

#include "global.h"
#include "conf.h"
#include "device.h"
#include "connection.h"

struct vpn
{
  int udpv4_fd , tcpv4_fd, ipv4_fd , icmpv4_fd , dnsv4_fd;
  int udpv4_tos,           ipv4_tos, icmpv4_tos, dnsv4_tos;

  int events;

  enum {
    EVENT_RECONNECT = 1,
    EVENT_SHUTDOWN  = 2,
  };

  void event_cb (ev::timer &w, int revents); ev::timer event;

  tap_device *tap;

  typedef vector<connection *> conns_vector;
  conns_vector conns;

  // called when any conenction has been established
  void connection_established (connection *c);

  // return true if src can connect directly to dst
  bool can_direct (conf_node *src, conf_node *dst) const;
  connection *find_router_for (const connection *dst);

  void reconnect_all ();
  void shutdown_all ();

  void tap_ev (ev::io &w, int revents); ev::io tap_ev_watcher;
  void inject_data_packet (tap_packet *pkt, int dst);

  void send_connect_request (int id);

  void recv_vpn_packet (vpn_packet *pkt, const sockinfo &rsi);
  bool send_vpn_packet (vpn_packet *pkt, const sockinfo &si, int tos = 0);

#if ENABLE_TCP
  void tcpv4_ev (ev::io &w, int revents); ev::io tcpv4_ev_watcher;
  bool send_tcpv4_packet (vpn_packet *pkt, const sockinfo &si, int tos);
#endif

#if ENABLE_ICMP
  void icmpv4_ev (ev::io &w, int revents); ev::io icmpv4_ev_watcher;
  bool send_icmpv4_packet (vpn_packet *pkt, const sockinfo &si, int tos);
#endif

#if ENABLE_DNS
  vector<struct dns_snd *> dns_sndpq;
  sockinfo dns_forwarder;

  void dnsv4_ev (ev::io &w, int revents); ev::io dnsv4_ev_watcher;
  void dnsv4_server (struct dns_packet &pkt);
  void dnsv4_client (struct dns_packet &pkt);

  bool send_dnsv4_packet (vpn_packet *pkt, const sockinfo &si, int tos);
#endif

  void udpv4_ev (ev::io &w, int revents); ev::io udpv4_ev_watcher;
  bool send_udpv4_packet (vpn_packet *pkt, const sockinfo &si, int tos);

  void ipv4_ev (ev::io &w, int revents); ev::io ipv4_ev_watcher;
  bool send_ipv4_packet (vpn_packet *pkt, const sockinfo &si, int tos);

  vpn ();
  ~vpn ();

  int setup ();

  void dump_status ();

  void script_init_env ();
  const char *script_if_init ();
  const char *script_if_up ();
};

extern vpn network; // THE vpn

#endif

