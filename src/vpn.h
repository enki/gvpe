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
    Foundation, Inc. 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef VPE_VPN_H__
#define VPE_VPN_H__

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

    void event_cb (time_watcher &w); time_watcher event;

    tap_device *tap;

    typedef vector<connection *> conns_vector;
    conns_vector conns;

    connection *find_router ();
    connection *find_forwarder ();

    void reconnect_all ();
    void shutdown_all ();

    void tap_ev (io_watcher &w, short revents); io_watcher tap_ev_watcher;
    void inject_data_packet (tap_packet *pkt, int dst);

    void send_connect_request (int id);

    void recv_vpn_packet (vpn_packet *pkt, const sockinfo &rsi);

#if ENABLE_TCP
    void tcpv4_ev (io_watcher &w, short revents); io_watcher tcpv4_ev_watcher;
    bool send_tcpv4_packet (vpn_packet *pkt, const sockinfo &si, int tos);
#endif

#if ENABLE_ICMP
    void icmpv4_ev (io_watcher &w, short revents); io_watcher icmpv4_ev_watcher;
    bool send_icmpv4_packet (vpn_packet *pkt, const sockinfo &si, int tos);
#endif

#if ENABLE_DNS
    vector<struct dns_req *> dns_sndpq;

    void dnsv4_ev (io_watcher &w, short revents); io_watcher dnsv4_ev_watcher;
    struct dns_packet *dnsv4_server (struct dns_packet *pkt);
    void dnsv4_client (struct dns_packet *pkt);
#endif

    void udpv4_ev (io_watcher &w, short revents); io_watcher udpv4_ev_watcher;
    bool send_udpv4_packet (vpn_packet *pkt, const sockinfo &si, int tos);

    void ipv4_ev (io_watcher &w, short revents); io_watcher ipv4_ev_watcher;
    bool send_ipv4_packet (vpn_packet *pkt, const sockinfo &si, int tos);

    vpn ();
    ~vpn ();

    int setup ();

    void dump_status ();

    const char *script_if_up ();
  };

extern vpn network; // THE vpn

#endif

