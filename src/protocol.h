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

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "conf.h"
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

enum auth_subtype { AUTH_INIT, AUTH_INITREPLY, AUTH_REPLY };

struct connection
  {
    conf_node *conf;
    struct vpn *vpn;

    SOCKADDR sa;
    int retry_cnt;

    time_t next_retry;		// next connection retry
    time_t next_rekey;		// next rekying (actually current reset + reestablishing)
    time_t last_activity;	// time of last packet received

    u32 oseqno;
    u32 iseqno;
    u32 ismask; // bitmask with set bits for each received seqno (input seen mask)

    pkt_queue queue;

    crypto_ctx *octx, *ictx;

    void reset_dstaddr ();

    void shutdown ();
    void reset_connection ();
    void establish_connection ();
    void rekey ();

    void send_auth (auth_subtype subtype, SOCKADDR *sa, rsachallenge *k = 0);
    void send_reset (SOCKADDR *dsa);
    void send_ping (SOCKADDR *dss, u8 pong = 0);
    void send_data_packet (tap_packet *pkt, bool broadcast = false);
    void inject_data_packet (tap_packet *pkt, bool broadcast = false);
    void connect_request (int id);

    void recv_vpn_packet (vpn_packet *pkt, SOCKADDR *rsa);

    void timer ();

    connection(struct vpn *vpn_)
        : vpn(vpn_)
    {
      octx = ictx = 0;
      retry_cnt = 0;
      reset_connection ();
    }

    ~connection ()
    {
      shutdown ();
    }

    void script_node ();
    const char *script_node_up ();
    const char *script_node_down ();
  };

struct vpn
  {
    int socket_fd;
    int events;

    tap_device *tap;

    enum {
      EVENT_RECONNECT = 1,
      EVENT_SHUTDOWN  = 2,
    };

    typedef vector<connection *> conns_vector;
    conns_vector conns;

    connection *find_router ();

    void send_vpn_packet (vpn_packet *pkt, SOCKADDR *sa);
    void reconnect_all ();
    void shutdown_all ();
    void connect_request (int id);

    vpn ();
    ~vpn ();

    int setup ();
    void main_loop ();

    const char *script_if_up ();
  };

#endif

