/*
    vpn.h -- header for vpn.C
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
    Foundation, Inc. 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef GVPE_VPN_H__
#define GVPE_VPN_H__

#include "global.h"
#include "conf.h"
#include "device.h"
#include "connection.h"

struct vpn
  {
    int udpv4_fd, tcpv4_fd, ipv4_fd, icmpv4_fd, dnsv4_fd;

    int events;

    enum {
      EVENT_RECONNECT = 1,
      EVENT_SHUTDOWN  = 2,
    };

    void event_cb (ev::timer &w, int revents); ev::timer event;

    tap_device *tap;

    typedef vector<connection *> conns_vector;
    conns_vector conns;

    connection *find_router ();
    connection *find_forwarder ();

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

