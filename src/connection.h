/*
    connection.h -- header for connection.C
 
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

#ifndef VPE_CONNECTION_H__
#define VPE_CONNECTION_H__

#include <openssl/hmac.h>

#include "global.h"
#include "conf.h"
#include "sockinfo.h"
#include "util.h"
#include "device.h"

struct vpn;

// called after HUP etc. to (re-)initialize global data structures
void connection_init ();

struct rsaid {
  u8 id[RSA_IDLEN]; // the challenge id
};

typedef u8 rsachallenge[RSA_KEYLEN - RSA_OVERHEAD]; // challenge data;
typedef u8 rsaencrdata[RSA_KEYLEN]; // encrypted challenge
typedef u8 rsaresponse[RSA_RESLEN]; // the encrypted ripemd160 hash

////////////////////////////////////////////////////////////////////////////////////////

struct crypto_ctx;

struct hmac_packet:net_packet
{
  u8 hmac[HMACLENGTH];		// each and every packet has a hmac field, but that is not (yet) checked everywhere

  void hmac_set (crypto_ctx * ctx);
  bool hmac_chk (crypto_ctx * ctx);

private:
  static unsigned char hmac_digest[EVP_MAX_MD_SIZE];

  void hmac_gen (crypto_ctx * ctx);
};

struct vpn_packet : hmac_packet
  {
    enum ptype
    {
      PT_RESET = 0,
      PT_DATA_UNCOMPRESSED,
      PT_DATA_COMPRESSED,
      PT_PING, PT_PONG,	// wasting namespace space? ;)
      PT_AUTH_REQ,	// authentification request
      PT_AUTH_RES,	// authentification response
      PT_CONNECT_REQ,	// want other host to contact me
      PT_CONNECT_INFO,	// request connection to some node
      PT_MAX
    };

    u8 type;
    u8 srcdst, src1, dst1;

    void set_hdr (ptype type_, unsigned int dst);

    unsigned int src () const
    {
      return src1 | ((srcdst >> 4) << 8);
    }

    unsigned int dst () const
    {
      return dst1 | ((srcdst & 0xf) << 8);
    }

    ptype typ () const
    {
      return (ptype) type;
    }
  };

////////////////////////////////////////////////////////////////////////////////////////

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

struct connection
  {
    conf_node *conf;
    struct vpn *vpn;

    sockinfo si; // the current(!) destination ip to send packets to
    int retry_cnt;

    tstamp last_activity;	// time of last packet received

    u32 oseqno;
    sliding_window iseqno;

    u8 protocol;

    pkt_queue queue;

    crypto_ctx *octx, *ictx;

    enum conf_node::connectmode connectmode;
    u8 prot_minor; // minor number of other side

    void reset_si ();
    const sockinfo &forward_si (const sockinfo &si) const;

    void shutdown ();
    void reset_connection ();
    void establish_connection_cb (time_watcher &w); time_watcher establish_connection;
    void rekey_cb (time_watcher &w); time_watcher rekey; // next rekying (actually current reset + reestablishing)
    void keepalive_cb (time_watcher &w); time_watcher keepalive; // next keepalive probe

    void send_auth_request (const sockinfo &si, bool initiate);
    void send_auth_response (const sockinfo &si, const rsaid &id, const rsachallenge &chg);
    void send_connect_info (int rid, const sockinfo &rsi, u8 rprotocols);
    void send_reset (const sockinfo &dsi);
    void send_ping (const sockinfo &dsi, u8 pong = 0);
    void send_data_packet (tap_packet *pkt, bool broadcast = false);
    void inject_data_packet (tap_packet *pkt, bool broadcast = false);
    void inject_vpn_packet (vpn_packet *pkt, int tos = 0); // for forwarding
    void connect_request (int id);

    void recv_vpn_packet (vpn_packet *pkt, const sockinfo &rsi);

    void script_node ();
    const char *script_node_up ();
    const char *script_node_down ();

    void dump_status ();

    connection(struct vpn *vpn_);
    ~connection ();
  };

#endif

