/*
    protocol.h -- header for protocol.C
 
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

#ifndef VPE_PROTOCOL_H__
#define VPE_PROTOCOL_H__

#include <netinet/in.h>
#include <netinet/ip.h> // for tos etc.

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "conf.h"
#include "iom.h"
#include "util.h"
#include "device.h"

/* Protocol version. Different versions are incompatible,
   incompatible version have different protocols.
 */

#define PROTOCOL_MAJOR 2
#define PROTOCOL_MINOR 0

struct vpn;
struct vpn_packet;

typedef u8 rsachallenge[RSA_KEYLEN - RSA_OVERHEAD]; // challenge data
typedef u8 rsaencrdata[RSA_KEYLEN]; // encrypted challenge

struct crypto_ctx;

// a very simple fifo pkt-queue
class pkt_queue
  {
    tap_packet *queue[QUEUEDEPTH];
    int i, j;

  public:

    void put (tap_packet *p);
    tap_packet *get ();

    pkt_queue ();
    ~pkt_queue ();
  };

enum auth_subtype { AUTH_INIT, AUTH_INITREPLY, AUTH_REPLY };

struct auth_packet;

struct connection
  {
    conf_node *conf;
    struct vpn *vpn;
    u32 seqrand;

    SOCKADDR sa;
    int retry_cnt;

    tstamp last_activity;	// time of last packet received

    u32 oseqno;
    sliding_window iseqno;

    pkt_queue queue;

    crypto_ctx *octx, *ictx;

    enum conf_node::connectmode connectmode;

    void reset_dstaddr ();

    void shutdown ();
    void reset_connection ();
    void establish_connection_cb (tstamp &ts); time_watcher establish_connection;
    void rekey_cb (tstamp &ts); time_watcher rekey; // next rekying (actually current reset + reestablishing)
    void keepalive_cb (tstamp &ts); time_watcher keepalive; // next keepalive probe

    void send_auth (auth_subtype subtype, SOCKADDR *sa, const rsachallenge *k = 0);
    void send_reset (SOCKADDR *dsa);
    void send_ping (SOCKADDR *dss, u8 pong = 0);
    void send_data_packet (tap_packet *pkt, bool broadcast = false);
    void inject_data_packet (tap_packet *pkt, bool broadcast = false);
    void connect_request (int id);

    void recv_vpn_packet (vpn_packet *pkt, SOCKADDR *rsa);

    void script_node ();
    const char *script_node_up ();
    const char *script_node_down ();

    connection(struct vpn *vpn_);
    ~connection ();
  };

struct vpn
  {
    int socket_fd;
    int events;

    enum {
      EVENT_RECONNECT = 1,
      EVENT_SHUTDOWN  = 2,
    };

    void event_cb (tstamp &ts); time_watcher event;

    tap_device *tap;

    typedef vector<connection *> conns_vector;
    conns_vector conns;

    connection *find_router ();

    void send_vpn_packet (vpn_packet *pkt, SOCKADDR *sa, int tos = IPTOS_RELIABILITY);
    void reconnect_all ();
    void shutdown_all ();
    void connect_request (int id);

    void vpn_ev (short revents); io_watcher vpn_ev_watcher;
    void udp_ev (short revents); io_watcher udp_ev_watcher;

    vpn ();
    ~vpn ();

    int setup ();

    const char *script_if_up ();
  };

#endif

