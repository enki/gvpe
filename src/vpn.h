/*
    vpn.h -- header for vpn.C
 
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

#ifndef VPE_VPN_H__
#define VPE_VPN_H__

#include <netinet/ip.h>

#include "global.h"
#include "conf.h"
#include "device.h"
#include "connection.h"

struct vpn
  {
    int udpv4_fd, tcpv4_fd, ipv4_fd, icmpv4_fd;

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

    void reconnect_all ();
    void shutdown_all ();

    void tap_ev (io_watcher &w, short revents); io_watcher tap_ev_watcher;

    void send_connect_request (int id);

    void recv_vpn_packet (vpn_packet *pkt, const sockinfo &rsi);
    bool send_vpn_packet (vpn_packet *pkt, const sockinfo &si, int tos);

#if ENABLE_TCP
    void tcpv4_ev (io_watcher &w, short revents); io_watcher tcpv4_ev_watcher;
    bool send_tcpv4_packet (vpn_packet *pkt, const sockinfo &si, int tos);
#endif

#if ENABLE_ICMP
    void icmpv4_ev (io_watcher &w, short revents); io_watcher icmpv4_ev_watcher;
    bool send_icmpv4_packet (vpn_packet *pkt, const sockinfo &si, int tos);
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

#endif

