/*
    connection.C -- manage a single connection
 
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

extern "C" {
# include "lzf/lzf.h"
}

#include <list>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include "gettext.h"

#include "conf.h"
#include "slog.h"
#include "device.h"
#include "vpn.h"
#include "connection.h"

#if !HAVE_RAND_PSEUDO_BYTES
# define  RAND_pseudo_bytes RAND_bytes
#endif

#define MAGIC "vped\xbd\xc6\xdb\x82"	// 8 bytes of magic

struct crypto_ctx
{
  EVP_CIPHER_CTX cctx;
  HMAC_CTX hctx;

  crypto_ctx (const rsachallenge &challenge, int enc);
  ~crypto_ctx ();
};

crypto_ctx::crypto_ctx (const rsachallenge &challenge, int enc)
{
  EVP_CIPHER_CTX_init (&cctx);
  EVP_CipherInit_ex (&cctx, CIPHER, 0, &challenge[CHG_CIPHER_KEY], 0, enc);
  HMAC_CTX_init (&hctx);
  HMAC_Init_ex (&hctx, &challenge[CHG_HMAC_KEY], HMAC_KEYLEN, DIGEST, 0);
}

crypto_ctx::~crypto_ctx ()
{
  EVP_CIPHER_CTX_cleanup (&cctx);
  HMAC_CTX_cleanup (&hctx);
}

static void
rsa_hash (const rsaid &id, const rsachallenge &chg, rsaresponse &h)
{
  EVP_MD_CTX ctx;

  EVP_MD_CTX_init (&ctx);
  EVP_DigestInit (&ctx, RSA_HASH);
  EVP_DigestUpdate(&ctx, &chg, sizeof chg);
  EVP_DigestUpdate(&ctx, &id, sizeof id);
  EVP_DigestFinal (&ctx, (unsigned char *)&h, 0);
  EVP_MD_CTX_cleanup (&ctx);
}

struct rsa_entry {
  tstamp expire;
  rsaid id;
  rsachallenge chg;
};

struct rsa_cache : list<rsa_entry>
{
  void cleaner_cb (time_watcher &w); time_watcher cleaner;
  
  bool find (const rsaid &id, rsachallenge &chg)
    {
      for (iterator i = begin (); i != end (); ++i)
        {
          if (!memcmp (&id, &i->id, sizeof id) && i->expire > NOW)
            {
              memcpy (&chg, &i->chg, sizeof chg);

              erase (i);
              return true;
            }
        }

      if (cleaner.at < NOW)
        cleaner.start (NOW + RSA_TTL);

      return false;
    }

  void gen (rsaid &id, rsachallenge &chg)
    {
      rsa_entry e;

      RAND_bytes ((unsigned char *)&id,  sizeof id);
      RAND_bytes ((unsigned char *)&chg, sizeof chg);

      e.expire = NOW + RSA_TTL;
      e.id = id;
      memcpy (&e.chg, &chg, sizeof chg);

      push_back (e);

      if (cleaner.at < NOW)
        cleaner.start (NOW + RSA_TTL);
    }

  rsa_cache ()
    : cleaner (this, &rsa_cache::cleaner_cb)
    { }

} rsa_cache;

void rsa_cache::cleaner_cb (time_watcher &w)
{
  if (empty ())
    w.at = TSTAMP_CANCEL;
  else
    {
      w.at = NOW + RSA_TTL;

      for (iterator i = begin (); i != end (); )
        if (i->expire <= NOW)
          i = erase (i);
        else
          ++i;
    }
}

//////////////////////////////////////////////////////////////////////////////

void pkt_queue::put (tap_packet *p)
{
  if (queue[i])
    {
      delete queue[i];
      j = (j + 1) % QUEUEDEPTH;
    }

  queue[i] = p;

  i = (i + 1) % QUEUEDEPTH;
}

tap_packet *pkt_queue::get ()
{
  tap_packet *p = queue[j];

  if (p)
    {
      queue[j] = 0;
      j = (j + 1) % QUEUEDEPTH;
    }

  return p;
}

pkt_queue::pkt_queue ()
{
  memset (queue, 0, sizeof (queue));
  i = 0;
  j = 0;
}

pkt_queue::~pkt_queue ()
{
  for (i = QUEUEDEPTH; --i > 0; )
    delete queue[i];
}

struct net_rateinfo {
  u32    host;
  double pcnt, diff;
  tstamp last;
};

// only do action once every x seconds per host whole allowing bursts.
// this implementation ("splay list" ;) is inefficient,
// but low on resources.
struct net_rate_limiter : list<net_rateinfo>
{
  static const double ALPHA  = 1. - 1. / 90.; // allow bursts
  static const double CUTOFF = 20.;           // one event every CUTOFF seconds
  static const double EXPIRE = CUTOFF * 30.;  // expire entries after this time

  bool can (const sockinfo &si) { return can((u32)si.host);             }
  bool can (u32 host);
};

net_rate_limiter auth_rate_limiter, reset_rate_limiter;

bool net_rate_limiter::can (u32 host)
{
  iterator i;

  for (i = begin (); i != end (); )
    if (i->host == host)
      break;
    else if (i->last < NOW - EXPIRE)
      i = erase (i);
    else
      i++;

  if (i == end ())
    {
      net_rateinfo ri;

      ri.host = host;
      ri.pcnt = 1.;
      ri.diff = CUTOFF * (1. / (1. - ALPHA));
      ri.last = NOW;

      push_front (ri);

      return true;
    }
  else
    {
      net_rateinfo ri (*i);
      erase (i);

      ri.pcnt = ri.pcnt * ALPHA;
      ri.diff = ri.diff * ALPHA + (NOW - ri.last);

      ri.last = NOW;

      bool send = ri.diff / ri.pcnt > CUTOFF;

      if (send)
        ri.pcnt++;

      push_front (ri);

      return send;
    }
}

/////////////////////////////////////////////////////////////////////////////

unsigned char hmac_packet::hmac_digest[EVP_MAX_MD_SIZE];

void hmac_packet::hmac_gen (crypto_ctx *ctx)
{
  unsigned int xlen;

  HMAC_CTX *hctx = &ctx->hctx;

  HMAC_Init_ex (hctx, 0, 0, 0, 0);
  HMAC_Update (hctx, ((unsigned char *) this) + sizeof (hmac_packet),
               len - sizeof (hmac_packet));
  HMAC_Final (hctx, (unsigned char *) &hmac_digest, &xlen);
}

void
hmac_packet::hmac_set (crypto_ctx *ctx)
{
  hmac_gen (ctx);

  memcpy (hmac, hmac_digest, HMACLENGTH);
}

bool
hmac_packet::hmac_chk (crypto_ctx *ctx)
{
  hmac_gen (ctx);

  return !memcmp (hmac, hmac_digest, HMACLENGTH);
}

void vpn_packet::set_hdr (ptype type, unsigned int dst)
{
  this->type = type;

  int src = THISNODE->id;

  src1 = src;
  srcdst = ((src >> 8) << 4) | (dst >> 8);
  dst1 = dst;
}

#define MAXVPNDATA (MAX_MTU - 6 - 6)
#define DATAHDR (sizeof (u32) + RAND_SIZE)

struct vpndata_packet:vpn_packet
  {
    u8 data[MAXVPNDATA + DATAHDR]; // seqno

    void setup (connection *conn, int dst, u8 *d, u32 len, u32 seqno);
    tap_packet *unpack (connection *conn, u32 &seqno);
private:

    const u32 data_hdr_size () const
    {
      return sizeof (vpndata_packet) - sizeof (net_packet) - MAXVPNDATA - DATAHDR;
    }
  };

void
vpndata_packet::setup (connection *conn, int dst, u8 *d, u32 l, u32 seqno)
{
  EVP_CIPHER_CTX *cctx = &conn->octx->cctx;
  int outl = 0, outl2;
  ptype type = PT_DATA_UNCOMPRESSED;

#if ENABLE_COMPRESSION
  u8 cdata[MAX_MTU];
  u32 cl;

  cl = lzf_compress (d, l, cdata + 2, (l - 2) & ~7);
  if (cl)
    {
      type = PT_DATA_COMPRESSED;
      d = cdata;
      l = cl + 2;

      d[0] = cl >> 8;
      d[1] = cl;
    }
#endif

  EVP_EncryptInit_ex (cctx, 0, 0, 0, 0);

  struct {
#if RAND_SIZE
    u8 rnd[RAND_SIZE];
#endif
    u32 seqno;
  } datahdr;

  datahdr.seqno = ntohl (seqno);
#if RAND_SIZE
  RAND_pseudo_bytes ((unsigned char *) datahdr.rnd, RAND_SIZE);
#endif

  EVP_EncryptUpdate (cctx,
                     (unsigned char *) data + outl, &outl2,
                     (unsigned char *) &datahdr, DATAHDR);
  outl += outl2;

  EVP_EncryptUpdate (cctx,
                     (unsigned char *) data + outl, &outl2,
                     (unsigned char *) d, l);
  outl += outl2;

  EVP_EncryptFinal_ex (cctx, (unsigned char *) data + outl, &outl2);
  outl += outl2;

  len = outl + data_hdr_size ();

  set_hdr (type, dst);

  hmac_set (conn->octx);
}

tap_packet *
vpndata_packet::unpack (connection *conn, u32 &seqno)
{
  EVP_CIPHER_CTX *cctx = &conn->ictx->cctx;
  int outl = 0, outl2;
  tap_packet *p = new tap_packet;
  u8 *d;
  u32 l = len - data_hdr_size ();

  EVP_DecryptInit_ex (cctx, 0, 0, 0, 0);

#if ENABLE_COMPRESSION
  u8 cdata[MAX_MTU];

  if (type == PT_DATA_COMPRESSED)
    d = cdata;
  else
#endif
    d = &(*p)[6 + 6 - DATAHDR];

  /* this overwrites part of the src mac, but we fix that later */
  EVP_DecryptUpdate (cctx,
                     d, &outl2,
                     (unsigned char *)&data, len - data_hdr_size ());
  outl += outl2;

  EVP_DecryptFinal_ex (cctx, (unsigned char *)d + outl, &outl2);
  outl += outl2;
  
  seqno = ntohl (*(u32 *)(d + RAND_SIZE));

  id2mac (dst () ? dst() : THISNODE->id, p->dst);
  id2mac (src (),                        p->src);

#if ENABLE_COMPRESSION
  if (type == PT_DATA_COMPRESSED)
    {
      u32 cl = (d[DATAHDR] << 8) | d[DATAHDR + 1];

      p->len = lzf_decompress (d + DATAHDR + 2, cl < MAX_MTU ? cl : 0,
                               &(*p)[6 + 6], MAX_MTU)
               + 6 + 6;
    }
  else
    p->len = outl + (6 + 6 - DATAHDR);
#endif

  return p;
}

struct ping_packet : vpn_packet
{
  void setup (int dst, ptype type)
  {
    set_hdr (type, dst);
    len = sizeof (*this) - sizeof (net_packet);
  }
};

struct config_packet : vpn_packet
{
  // actually, hmaclen cannot be checked because the hmac
  // field comes before this data, so peers with other
  // hmacs simply will not work.
  u8 prot_major, prot_minor, randsize, hmaclen;
  u8 flags, challengelen, pad2, pad3;
  u32 cipher_nid, digest_nid, hmac_nid;

  const u8 curflags () const
  {
    return 0x80
           | (ENABLE_COMPRESSION ? 0x01 : 0x00);
  }

  void setup (ptype type, int dst);
  bool chk_config () const;
};

void config_packet::setup (ptype type, int dst)
{
  prot_major = PROTOCOL_MAJOR;
  prot_minor = PROTOCOL_MINOR;
  randsize = RAND_SIZE;
  hmaclen = HMACLENGTH;
  flags = curflags ();
  challengelen = sizeof (rsachallenge);

  cipher_nid = htonl (EVP_CIPHER_nid (CIPHER));
  digest_nid = htonl (EVP_MD_type (RSA_HASH));
  hmac_nid   = htonl (EVP_MD_type (DIGEST));

  len = sizeof (*this) - sizeof (net_packet);
  set_hdr (type, dst);
}

bool config_packet::chk_config () const
{
  return prot_major == PROTOCOL_MAJOR
         && randsize == RAND_SIZE
         && hmaclen == HMACLENGTH
         && flags == curflags ()
         && challengelen == sizeof (rsachallenge)
         && cipher_nid == htonl (EVP_CIPHER_nid (CIPHER))
         && digest_nid == htonl (EVP_MD_type (RSA_HASH))
         && hmac_nid   == htonl (EVP_MD_type (DIGEST));
}

struct auth_req_packet : config_packet
{
  char magic[8];
  u8 initiate; // false if this is just an automatic reply
  u8 protocols; // supported protocols (will get patches on forward)
  u8 pad2, pad3;
  rsaid id;
  rsaencrdata encr;

  auth_req_packet (int dst, bool initiate_, u8 protocols_)
  {
    config_packet::setup (PT_AUTH_REQ, dst);
    strncpy (magic, MAGIC, 8);
    initiate = !!initiate_;
    protocols = protocols_;

    len = sizeof (*this) - sizeof (net_packet);
  }
};

struct auth_res_packet : config_packet
{
  rsaid id;
  u8 pad1, pad2, pad3;
  u8 response_len; // encrypted length
  rsaresponse response;

  auth_res_packet (int dst)
  {
    config_packet::setup (PT_AUTH_RES, dst);

    len = sizeof (*this) - sizeof (net_packet);
  }
};

struct connect_req_packet : vpn_packet
{
  u8 id, protocols;
  u8 pad1, pad2;

  connect_req_packet (int dst, int id_, u8 protocols_)
  : id(id_)
  , protocols(protocols_)
  {
    set_hdr (PT_CONNECT_REQ, dst);
    len = sizeof (*this) - sizeof (net_packet);
  }
};

struct connect_info_packet : vpn_packet
{
  u8 id, protocols;
  u8 pad1, pad2;
  sockinfo si;

  connect_info_packet (int dst, int id_, const sockinfo &si_, u8 protocols_)
  : id(id_)
  , protocols(protocols_)
  , si(si_)
  {
    set_hdr (PT_CONNECT_INFO, dst);

    len = sizeof (*this) - sizeof (net_packet);
  }
};

/////////////////////////////////////////////////////////////////////////////

void
connection::reset_dstaddr ()
{
  si.set (conf);
}

void
connection::send_ping (const sockinfo &si, u8 pong)
{
  ping_packet *pkt = new ping_packet;

  pkt->setup (conf->id, pong ? ping_packet::PT_PONG : ping_packet::PT_PING);
  send_vpn_packet (pkt, si, IPTOS_LOWDELAY);

  delete pkt;
}

void
connection::send_reset (const sockinfo &si)
{
  if (reset_rate_limiter.can (si) && connectmode != conf_node::C_DISABLED)
    {
      config_packet *pkt = new config_packet;

      pkt->setup (vpn_packet::PT_RESET, conf->id);
      send_vpn_packet (pkt, si, IPTOS_MINCOST);

      delete pkt;
    }
}

void
connection::send_auth_request (const sockinfo &si, bool initiate)
{
  auth_req_packet *pkt = new auth_req_packet (conf->id, initiate, THISNODE->protocols);

  protocol = best_protocol (THISNODE->protocols & conf->protocols);

  // mask out protocols we cannot establish
  if (!conf->udp_port) protocol &= ~PROT_UDPv4;
  if (!conf->tcp_port) protocol &= ~PROT_TCPv4;

  if (protocol)
    {
      rsachallenge chg;

      rsa_cache.gen (pkt->id, chg);

      if (0 > RSA_public_encrypt (sizeof chg,
                                  (unsigned char *)&chg, (unsigned char *)&pkt->encr,
                                  conf->rsa_key, RSA_PKCS1_OAEP_PADDING))
        fatal ("RSA_public_encrypt error");

      slog (L_TRACE, ">>%d PT_AUTH_REQ [%s]", conf->id, (const char *)si);

      send_vpn_packet (pkt, si, IPTOS_RELIABILITY); // rsa is very very costly

      delete pkt;
    }
  else
    ; // silently fail
}

void
connection::send_auth_response (const sockinfo &si, const rsaid &id, const rsachallenge &chg)
{
  auth_res_packet *pkt = new auth_res_packet (conf->id);

  pkt->id = id;

  rsa_hash (id, chg, pkt->response);

  pkt->hmac_set (octx);

  slog (L_TRACE, ">>%d PT_AUTH_RES [%s]", conf->id, (const char *)si);

  send_vpn_packet (pkt, si, IPTOS_RELIABILITY); // rsa is very very costly

  delete pkt;
}

void
connection::send_connect_info (int rid, const sockinfo &rsi, u8 rprotocols)
{
  slog (L_TRACE, ">>%d PT_CONNECT_INFO(%d,%s)\n",
                 conf->id, rid, (const char *)rsi);

  connect_info_packet *r = new connect_info_packet (conf->id, rid, rsi, rprotocols);

  r->hmac_set (octx);
  send_vpn_packet (r, si);

  delete r;
}

void
connection::establish_connection_cb (time_watcher &w)
{
  if (ictx || conf == THISNODE
      || connectmode == conf_node::C_NEVER
      || connectmode == conf_node::C_DISABLED)
    w.at = TSTAMP_CANCEL;
  else if (w.at <= NOW)
    {
      double retry_int = double (retry_cnt & 3 ? (retry_cnt & 3) : 1 << (retry_cnt >> 2)) * 0.6;

      if (retry_int < 3600 * 8)
        retry_cnt++;

      w.at = NOW + retry_int;

      if (conf->hostname)
        {
          reset_dstaddr ();
          if (si.host && auth_rate_limiter.can (si))
           {
            if (retry_cnt < 4)
              send_auth_request (si, true);
            else
              send_ping (si, 0);
           }
        }
      else
        vpn->connect_request (conf->id);
    }
}

void
connection::reset_connection ()
{
  if (ictx && octx)
    {
      slog (L_INFO, _("%s(%s): connection lost"),
            conf->nodename, (const char *)si);

      if (::conf.script_node_down)
        run_script (run_script_cb (this, &connection::script_node_down), false);
    }

  delete ictx; ictx = 0;
  delete octx; octx = 0;

  si.host= 0;

  last_activity = 0;
  retry_cnt = 0;

  rekey.reset ();
  keepalive.reset ();
  establish_connection.reset ();
}

void
connection::shutdown ()
{
  if (ictx && octx)
    send_reset (si);

  reset_connection ();
}

void
connection::rekey_cb (time_watcher &w)
{
  w.at = TSTAMP_CANCEL;

  reset_connection ();
  establish_connection ();
}

void
connection::send_data_packet (tap_packet *pkt, bool broadcast)
{
  vpndata_packet *p = new vpndata_packet;
  int tos = 0;

  if (conf->inherit_tos
      && (*pkt)[12] == 0x08 && (*pkt)[13] == 0x00 // IP
      && ((*pkt)[14] & 0xf0) == 0x40)             // IPv4
    tos = (*pkt)[15] & IPTOS_TOS_MASK;

  p->setup (this, broadcast ? 0 : conf->id, &((*pkt)[6 + 6]), pkt->len - 6 - 6, ++oseqno); // skip 2 macs
  send_vpn_packet (p, si, tos);

  delete p;

  if (oseqno > MAX_SEQNO)
    rekey ();
}

void
connection::inject_data_packet (tap_packet *pkt, bool broadcast)
{
  if (ictx && octx)
    send_data_packet (pkt, broadcast);
  else
    {
      if (!broadcast)//DDDD
        queue.put (new tap_packet (*pkt));

      establish_connection ();
    }
}

void
connection::recv_vpn_packet (vpn_packet *pkt, const sockinfo &rsi)
{
  last_activity = NOW;

  slog (L_NOISE, "<<%d received packet type %d from %d to %d", 
        conf->id, pkt->typ (), pkt->src (), pkt->dst ());

  switch (pkt->typ ())
    {
      case vpn_packet::PT_PING:
        // we send pings instead of auth packets after some retries,
        // so reset the retry counter and establish a connection
        // when we receive a ping.
        if (!ictx)
          {
            if (auth_rate_limiter.can (rsi))
              send_auth_request (rsi, true);
          }
        else
          send_ping (rsi, 1); // pong

        break;

      case vpn_packet::PT_PONG:
        break;

      case vpn_packet::PT_RESET:
        {
          reset_connection ();

          config_packet *p = (config_packet *) pkt;

          if (!p->chk_config ())
            {
              slog (L_WARN, _("%s(%s): protocol mismatch, disabling node"),
                    conf->nodename, (const char *)rsi);
              connectmode = conf_node::C_DISABLED;
            }
          else if (connectmode == conf_node::C_ALWAYS)
            establish_connection ();
        }
        break;

      case vpn_packet::PT_AUTH_REQ:
        if (auth_rate_limiter.can (rsi))
          {
            auth_req_packet *p = (auth_req_packet *) pkt;

            slog (L_TRACE, "<<%d PT_AUTH_REQ(%d)", conf->id, p->initiate);

            if (p->chk_config () && !strncmp (p->magic, MAGIC, 8))
              {
                if (p->prot_minor != PROTOCOL_MINOR)
                  slog (L_INFO, _("%s(%s): protocol minor version mismatch: ours is %d, %s's is %d."),
                        conf->nodename, (const char *)rsi,
                        PROTOCOL_MINOR, conf->nodename, p->prot_minor);

                if (p->initiate)
                  send_auth_request (rsi, false);

                rsachallenge k;

                if (0 > RSA_private_decrypt (sizeof (p->encr),
                                             (unsigned char *)&p->encr, (unsigned char *)&k,
                                             ::conf.rsa_key, RSA_PKCS1_OAEP_PADDING))
                  slog (L_ERR, _("%s(%s): challenge illegal or corrupted"),
                        conf->nodename, (const char *)rsi);
                else
                  {
                    retry_cnt = 0;
                    establish_connection.set (NOW + 8); //? ;)
                    keepalive.reset ();
                    rekey.reset ();

                    delete ictx;
                    ictx = 0;

                    delete octx;

                    octx   = new crypto_ctx (k, 1);
                    oseqno = ntohl (*(u32 *)&k[CHG_SEQNO]) & 0x7fffffff;

                    conf->protocols = p->protocols;
                    send_auth_response (rsi, p->id, k);

                    break;
                  }
              }

            send_reset (rsi);
          }

        break;

      case vpn_packet::PT_AUTH_RES:
        {
          auth_res_packet *p = (auth_res_packet *) pkt;

          slog (L_TRACE, "<<%d PT_AUTH_RES", conf->id);

          if (p->chk_config ())
            {
              if (p->prot_minor != PROTOCOL_MINOR)
                slog (L_INFO, _("%s(%s): protocol minor version mismatch: ours is %d, %s's is %d."),
                      conf->nodename, (const char *)rsi,
                      PROTOCOL_MINOR, conf->nodename, p->prot_minor);

              rsachallenge chg;

              if (!rsa_cache.find (p->id, chg))
                slog (L_ERR, _("%s(%s): unrequested auth response"),
                      conf->nodename, (const char *)rsi);
              else
                {
                  crypto_ctx *cctx = new crypto_ctx (chg, 0);

                  if (!p->hmac_chk (cctx))
                    slog (L_ERR, _("%s(%s): hmac authentication error on auth response, received invalid packet\n"
                                   "could be an attack, or just corruption or an synchronization error"),
                          conf->nodename, (const char *)rsi);
                  else
                    {
                      rsaresponse h;

                      rsa_hash (p->id, chg, h);

                      if (!memcmp ((u8 *)&h, (u8 *)p->response, sizeof h))
                        {
                          prot_minor = p->prot_minor;

                          delete ictx; ictx = cctx;

                          iseqno.reset (ntohl (*(u32 *)&chg[CHG_SEQNO]) & 0x7fffffff); // at least 2**31 sequence numbers are valid

                          si = rsi;

                          rekey.set (NOW + ::conf.rekey);
                          keepalive.set (NOW + ::conf.keepalive);

                          // send queued packets
                          while (tap_packet *p = queue.get ())
                            {
                              send_data_packet (p);
                              delete p;
                            }

                          connectmode = conf->connectmode;

                          slog (L_INFO, _("%s(%s): %s connection established, protocol version %d.%d"),
                                conf->nodename, (const char *)rsi,
                                strprotocol (protocol),
                                p->prot_major, p->prot_minor);

                          if (::conf.script_node_up)
                            run_script (run_script_cb (this, &connection::script_node_up), false);

                          break;
                        }
                      else
                        slog (L_ERR, _("%s(%s): sent and received challenge do not match"),
                              conf->nodename, (const char *)rsi);
                    }

                  delete cctx;
                }
            }
        }

        send_reset (rsi);
        break;

      case vpn_packet::PT_DATA_COMPRESSED:
#if !ENABLE_COMPRESSION
        send_reset (rsi);
        break;
#endif

      case vpn_packet::PT_DATA_UNCOMPRESSED:

        if (ictx && octx)
          {
            vpndata_packet *p = (vpndata_packet *)pkt;

            if (rsi == si)
              {
                if (!p->hmac_chk (ictx))
                  slog (L_ERR, _("%s(%s): hmac authentication error, received invalid packet\n"
                                 "could be an attack, or just corruption or an synchronization error"),
                        conf->nodename, (const char *)rsi);
                else
                  {
                    u32 seqno;
                    tap_packet *d = p->unpack (this, seqno);

                    if (iseqno.recv_ok (seqno))
                      {
                        vpn->tap->send (d);

                        if (p->dst () == 0) // re-broadcast
                          for (vpn::conns_vector::iterator i = vpn->conns.begin (); i != vpn->conns.end (); ++i)
                            {
                              connection *c = *i;

                              if (c->conf != THISNODE && c->conf != conf)
                                c->inject_data_packet (d);
                            }

                        delete d;

                        break;
                      }
                  }
              }
            else
              slog (L_ERR,  _("received data packet from unknown source %s"), (const char *)rsi);
          }

        send_reset (rsi);
        break;

      case vpn_packet::PT_CONNECT_REQ:
        if (ictx && octx && rsi == si && pkt->hmac_chk (ictx))
          {
            connect_req_packet *p = (connect_req_packet *) pkt;

            assert (p->id > 0 && p->id <= vpn->conns.size ()); // hmac-auth does not mean we accept anything
            conf->protocols = p->protocols;
            connection *c = vpn->conns[p->id - 1];

            slog (L_TRACE, "<<%d PT_CONNECT_REQ(%d) [%d]\n",
                           conf->id, p->id, c->ictx && c->octx);

            if (c->ictx && c->octx)
              {
                // send connect_info packets to both sides, in case one is
                // behind a nat firewall (or both ;)
                c->send_connect_info (conf->id, si, conf->protocols);
                send_connect_info (c->conf->id, c->si, c->conf->protocols);
              }
          }

        break;

      case vpn_packet::PT_CONNECT_INFO:
        if (ictx && octx && rsi == si && pkt->hmac_chk (ictx))
          {
            connect_info_packet *p = (connect_info_packet *) pkt;

            assert (p->id > 0 && p->id <= vpn->conns.size ()); // hmac-auth does not mean we accept anything
            conf->protocols = p->protocols;
            connection *c = vpn->conns[p->id - 1];

            slog (L_TRACE, "<<%d PT_CONNECT_INFO(%d,%s) (%d)",
                           conf->id, p->id, (const char *)p->si, !c->ictx && !c->octx);

            c->send_auth_request (p->si, true);
          }

        break;

      default:
        send_reset (rsi);
        break;
    }
}

void connection::keepalive_cb (time_watcher &w)
{
  if (NOW >= last_activity + ::conf.keepalive + 30)
    {
      reset_connection ();
      establish_connection ();
    }
  else if (NOW < last_activity + ::conf.keepalive)
    w.at = last_activity + ::conf.keepalive;
  else if (conf->connectmode != conf_node::C_ONDEMAND
           || THISNODE->connectmode != conf_node::C_ONDEMAND)
    {
      send_ping (si);
      w.at = NOW + 5;
    }
  else
    reset_connection ();
}

void connection::connect_request (int id)
{
  connect_req_packet *p = new connect_req_packet (conf->id, id, conf->protocols);

  slog (L_TRACE, ">>%d PT_CONNECT_REQ(%d)", conf->id, id);
  p->hmac_set (octx);
  send_vpn_packet (p, si);

  delete p;
}

void connection::script_node ()
{
  vpn->script_if_up ();

  char *env;
  asprintf (&env, "DESTID=%d",   conf->id); putenv (env);
  asprintf (&env, "DESTNODE=%s", conf->nodename); putenv (env);
  asprintf (&env, "DESTIP=%s",   si.ntoa ()); putenv (env);
  asprintf (&env, "DESTPORT=%d", ntohs (si.port)); putenv (env);
}

const char *connection::script_node_up ()
{
  script_node ();

  putenv ("STATE=up");

  return ::conf.script_node_up ? ::conf.script_node_up : "node-up";
}

const char *connection::script_node_down ()
{
  script_node ();

  putenv ("STATE=down");

  return ::conf.script_node_up ? ::conf.script_node_down : "node-down";
}

// send a vpn packet out to other hosts
void
connection::send_vpn_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
  switch (protocol)
    {
      case PROT_IPv4:
        vpn->send_ipv4_packet (pkt, si, tos);
        break;

      case PROT_UDPv4:
        vpn->send_udpv4_packet (pkt, si, tos);
        break;

      case PROT_TCPv4:
        vpn->send_tcpv4_packet (pkt, si, tos);
        break;
    }
}

connection::connection(struct vpn *vpn_)
: vpn(vpn_)
, rekey (this, &connection::rekey_cb)
, keepalive (this, &connection::keepalive_cb)
, establish_connection (this, &connection::establish_connection_cb)
{
  octx = ictx = 0;
  retry_cnt = 0;

  connectmode = conf_node::C_ALWAYS; // initial setting
  reset_connection ();
}

connection::~connection ()
{
  shutdown ();
}

void connection_init ()
{
  auth_rate_limiter.clear ();
  reset_rate_limiter.clear ();
}

