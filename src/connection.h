/*
    connection.h -- header for connection.C
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

#ifndef GVPE_CONNECTION_H__
#define GVPE_CONNECTION_H__

#include <openssl/hmac.h>

#include "global.h"
#include "conf.h"
#include "sockinfo.h"
#include "util.h"
#include "device.h"

struct vpn;

// called after HUP etc. to (re-)initialize global data structures
void connection_init ();

struct rsaid
{
  u8 id[RSA_IDLEN]; // the challenge id
};

typedef rsaclear rsachallenge;      // challenge data;
typedef rsacrypt rsaencrdata;       // encrypted challenge
typedef u8 rsaresponse[RSA_RESLEN]; // the encrypted ripemd160 hash

////////////////////////////////////////////////////////////////////////////////////////

struct crypto_ctx;

struct hmac_packet : net_packet
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
    PT_CONNECT_REQ,	// want other node to contact me
    PT_CONNECT_INFO,	// request connection to some node
    PT_DATA_BRIDGED,    // uncompressed packet with foreign mac pot. larger than path mtu (NYI)
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
  int i, j;
  int max_queue;
  double max_ttl;

  struct pkt {
    ev_tstamp tstamp;
    net_packet *pkt;
  } *queue;

  void expire_cb (ev::timer &w, int revents); ev::timer expire;

public:

  void put (net_packet *p);
  net_packet *get ();

  bool empty ()
  {
    return i == j;
  }

  pkt_queue (double max_ttl, int max_queue);
  ~pkt_queue ();
};

enum
{
  FEATURE_COMPRESSION = 0x01,
  FEATURE_ROHC        = 0x02,
  FEATURE_BRIDGING    = 0x04,
};

struct connection
{
  conf_node *conf;
  struct vpn *vpn;

  sockinfo si; // the current(!) destination ip to send packets to
  int retry_cnt;

  tstamp last_activity;	// time of last packet received
  tstamp last_establish_attempt;
  //tstamp last_si_change; // time we last changed the socket address

  u32 oseqno;
  sliding_window iseqno;

  u8 protocol;
  u8 features;
  bool is_direct; // current connection (si) is direct?

  pkt_queue data_queue, vpn_queue;

  crypto_ctx *octx, *ictx;

#if ENABLE_DNS
  struct dns_connection *dns;
#endif

  enum conf_node::connectmode connectmode;
  u8 prot_minor; // minor number of other side

  void reset_si ();
  const sockinfo &forward_si (const sockinfo &si) const;

  void shutdown ();
  void connection_established ();
  void reset_connection ();

  void establish_connection_cb (ev::timer &w, int revents); ev::timer establish_connection;
  void rekey_cb (ev::timer &w, int revents); ev::timer rekey; // next rekying (actually current reset + reestablishing)
  void keepalive_cb (ev::timer &w, int revents); ev::timer keepalive; // next keepalive probe

  void send_connect_request (int id);
  void send_auth_request (const sockinfo &si, bool initiate);
  void send_auth_response (const sockinfo &si, const rsaid &id, const rsachallenge &chg);
  void send_connect_info (int rid, const sockinfo &rsi, u8 rprotocols);
  void send_reset (const sockinfo &dsi);
  void send_ping (const sockinfo &dsi, u8 pong = 0);
  void send_data_packet (tap_packet *pkt);

  void post_inject_queue ();
  void inject_data_packet (tap_packet *pkt);
  void inject_vpn_packet (vpn_packet *pkt, int tos = 0); // for forwarding

  void recv_vpn_packet (vpn_packet *pkt, const sockinfo &rsi);
  void send_vpn_packet (vpn_packet *pkt, const sockinfo &si, int tos = 0);

  void script_init_env (const char *ext);
  void script_init_connect_env ();
  const char *script_node_up ();
  const char *script_node_change ();
  const char *script_node_down ();

  void dump_status ();

  connection (struct vpn *vpn, conf_node *conf);
  ~connection ();
};

#endif

