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

#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

extern "C" {
# include "lzf/lzf.h"
}

#include "gettext.h"
#include "pidfile.h"

#include "conf.h"
#include "slog.h"
#include "device.h"
#include "protocol.h"

#if !HAVE_RAND_PSEUDO_BYTES
# define  RAND_pseudo_bytes RAND_bytes
#endif

static time_t next_timecheck;

#define MAGIC "vped\xbd\xc6\xdb\x82"	// 8 bytes of magic

static const rsachallenge &
challenge_bytes ()
{
  static rsachallenge challenge;
  static tstamp challenge_ttl;	// time this challenge needs to be recreated

  if (NOW > challenge_ttl)
    {
      RAND_bytes ((unsigned char *)&challenge, sizeof (challenge));
      challenge_ttl = NOW + CHALLENGE_TTL;
    }

  return challenge;
}

// caching of rsa operations really helps slow computers
struct rsa_entry {
  tstamp expire;
  rsachallenge chg;
  RSA *key; // which key
  rsaencrdata encr;

  rsa_entry ()
    {
      expire = NOW + CHALLENGE_TTL;
    }
};

struct rsa_cache : list<rsa_entry>
{
  void cleaner_cb (tstamp &ts); time_watcher cleaner;
  
  const rsaencrdata *public_encrypt (RSA *key, const rsachallenge &chg)
    {
      for (iterator i = begin (); i != end (); ++i)
       {
        if (i->key == key && !memcmp (&chg, &i->chg, sizeof chg))
          return &i->encr;
       }

      if (cleaner.at < NOW)
        cleaner.start (NOW + CHALLENGE_TTL);

      resize (size () + 1);
      rsa_entry *e = &(*rbegin ());

      e->key = key;
      memcpy (&e->chg, &chg, sizeof chg);

      if (0 > RSA_public_encrypt (sizeof chg,
                                  (unsigned char *)&chg, (unsigned char *)&e->encr,
                                  key, RSA_PKCS1_OAEP_PADDING))
        fatal ("RSA_public_encrypt error");

      return &e->encr;
    }

  const rsachallenge *private_decrypt (RSA *key, const rsaencrdata &encr)
    {
      for (iterator i = begin (); i != end (); ++i)
        if (i->key == key && !memcmp (&encr, &i->encr, sizeof encr))
          return &i->chg;

      if (cleaner.at < NOW)
        cleaner.start (NOW + CHALLENGE_TTL);

      resize (size () + 1);
      rsa_entry *e = &(*rbegin ());

      e->key = key;
      memcpy (&e->encr, &encr, sizeof encr);

      if (0 > RSA_private_decrypt (sizeof encr,
                                   (unsigned char *)&encr, (unsigned char *)&e->chg,
                                   key, RSA_PKCS1_OAEP_PADDING))
        {
          pop_back ();
          return 0;
        }

      return &e->chg;
    }

  rsa_cache ()
    : cleaner (this, &rsa_cache::cleaner_cb)
    { }

} rsa_cache;

void rsa_cache::cleaner_cb (tstamp &ts)
{
  if (empty ())
    ts = TSTAMP_CANCEL;
  else
    {
      ts = NOW + 3;
      for (iterator i = begin (); i != end (); )
        {
          if (i->expire >= NOW)
            i = erase (i);
          else
            ++i;
        }
    }
}

// run a script. yes, it's a template function. yes, c++
// is not a functional language. yes, this suxx.
template<class owner>
static void
run_script (owner *obj, const char *(owner::*setup)(), bool wait)
{
  int pid;

  if ((pid = fork ()) == 0)
    {
      char *filename;
      asprintf (&filename, "%s/%s", confbase, (obj->*setup) ());
      execl (filename, filename, (char *) 0);
      exit (255);
    }
  else if (pid > 0)
    {
      if (wait)
        {
          waitpid (pid, 0, 0);
          /* TODO: check status */
        }
    }
}

// xor the socket address into the challenge to ensure different challenges
// per host. we could rely on the OAEP padding, but this doesn't hurt.
void
xor_sa (rsachallenge &k, SOCKADDR *sa)
{
  ((u32 *) k)[(CHG_CIPHER_KEY + 0) / 4] ^= sa->sin_addr.s_addr;
  ((u16 *) k)[(CHG_CIPHER_KEY + 4) / 2] ^= sa->sin_port;
  ((u32 *) k)[(CHG_HMAC_KEY   + 0) / 4] ^= sa->sin_addr.s_addr;
  ((u16 *) k)[(CHG_HMAC_KEY   + 4) / 2] ^= sa->sin_port;
}

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
struct net_rate_limiter : private list<net_rateinfo>
{
  static const double ALPHA  = 1. - 1. / 90.; // allow bursts
  static const double CUTOFF = 20.;           // one event every CUTOFF seconds
  static const double EXPIRE = CUTOFF * 30.;  // expire entries after this time

  bool can (u32 host);
  bool can (SOCKADDR *sa) { return can((u32)sa->sin_addr.s_addr); }
  bool can (sockinfo &si) { return can((u32)si.host);             }
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

      //printf ("RATE %d %f,%f = %f > %f\n", !!send, ri.pcnt, ri.diff, ri.diff / ri.pcnt, CUTOFF);

      push_front (ri);

      return send;
    }
}

/////////////////////////////////////////////////////////////////////////////

static void next_wakeup (time_t next)
{
  if (next_timecheck > next)
    next_timecheck = next;
}

static unsigned char hmac_digest[EVP_MAX_MD_SIZE];

struct hmac_packet:net_packet
  {
    u8 hmac[HMACLENGTH];		// each and every packet has a hmac field, but that is not (yet) checked everywhere

    void hmac_set (crypto_ctx * ctx);
    bool hmac_chk (crypto_ctx * ctx);

private:
    void hmac_gen (crypto_ctx * ctx)
    {
      unsigned int xlen;
      HMAC_CTX *hctx = &ctx->hctx;

      HMAC_Init_ex (hctx, 0, 0, 0, 0);
      HMAC_Update (hctx, ((unsigned char *) this) + sizeof (hmac_packet),
                   len - sizeof (hmac_packet));
      HMAC_Final (hctx, (unsigned char *) &hmac_digest, &xlen);
    }
  };

void
hmac_packet::hmac_set (crypto_ctx * ctx)
{
  hmac_gen (ctx);

  memcpy (hmac, hmac_digest, HMACLENGTH);
}

bool
hmac_packet::hmac_chk (crypto_ctx * ctx)
{
  hmac_gen (ctx);

  return !memcmp (hmac, hmac_digest, HMACLENGTH);
}

struct vpn_packet : hmac_packet
  {
    enum ptype
    {
      PT_RESET = 0,
      PT_DATA_UNCOMPRESSED,
      PT_DATA_COMPRESSED,
      PT_PING, PT_PONG,	// wasting namespace space? ;)
      PT_AUTH,		// authentification
      PT_CONNECT_REQ,	// want other host to contact me
      PT_CONNECT_INFO,	// request connection to some node
      PT_REKEY,		// rekeying (not yet implemented)
      PT_MAX
    };

    u8 type;
    u8 srcdst, src1, dst1;

    void set_hdr (ptype type, unsigned int dst);

    unsigned int src ()
    {
      return src1 | ((srcdst >> 4) << 8);
    }

    unsigned int dst ()
    {
      return dst1 | ((srcdst & 0xf) << 8);
    }

    ptype typ ()
    {
      return (ptype) type;
    }
  };

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
      p->len = lzf_decompress (d + DATAHDR + 2, cl, &(*p)[6 + 6], MAX_MTU) + 6 + 6;
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
    u32 cipher_nid;
    u32 digest_nid;

    const u8 curflags () const
    {
      return 0x80
             | (ENABLE_COMPRESSION ? 0x01 : 0x00);
    }

    void setup (ptype type, int dst)
    {
      prot_major = PROTOCOL_MAJOR;
      prot_minor = PROTOCOL_MINOR;
      randsize = RAND_SIZE;
      hmaclen = HMACLENGTH;
      flags = curflags ();
      challengelen = sizeof (rsachallenge);

      cipher_nid = htonl (EVP_CIPHER_nid (CIPHER));
      digest_nid = htonl (EVP_MD_type (DIGEST));

      len = sizeof (*this) - sizeof (net_packet);
      set_hdr (type, dst);
    }

    bool chk_config ()
      {
        return prot_major == PROTOCOL_MAJOR
               && randsize == RAND_SIZE
               && hmaclen == HMACLENGTH
               && flags == curflags ()
               && challengelen == sizeof (rsachallenge)
               && cipher_nid == htonl (EVP_CIPHER_nid (CIPHER))
               && digest_nid == htonl (EVP_MD_type (DIGEST));
      }
  };

struct auth_packet : config_packet
  {
    char magic[8];
    u8 subtype;
    u8 pad1, pad2;
    rsaencrdata challenge;

    auth_packet (int dst, auth_subtype stype)
    {
      config_packet::setup (PT_AUTH, dst);
      subtype = stype;
      len = sizeof (*this) - sizeof (net_packet);
      strncpy (magic, MAGIC, 8);
    }
  };

struct connect_req_packet : vpn_packet
  {
    u8 id;
    u8 pad1, pad2, pad3;

    connect_req_packet (int dst, int id)
    {
      this->id = id;
      set_hdr (PT_CONNECT_REQ, dst);
      len = sizeof (*this) - sizeof (net_packet);
    }
  };

struct connect_info_packet : vpn_packet
  {
    u8 id;
    u8 pad1, pad2, pad3;
    sockinfo si;

    connect_info_packet (int dst, int id, sockinfo &si)
    {
      this->id = id;
      this->si = si;
      set_hdr (PT_CONNECT_INFO, dst);
      len = sizeof (*this) - sizeof (net_packet);
    }
  };

/////////////////////////////////////////////////////////////////////////////

void
fill_sa (SOCKADDR *sa, conf_node *conf)
{
  sa->sin_family = AF_INET;
  sa->sin_port = htons (conf->port);
  sa->sin_addr.s_addr = 0;

  if (conf->hostname)
    {
      struct hostent *he = gethostbyname (conf->hostname);

      if (he
          && he->h_addrtype == AF_INET && he->h_length == 4 && he->h_addr_list[0])
        {
          //sa->sin_family = he->h_addrtype;
          memcpy (&sa->sin_addr, he->h_addr_list[0], 4);
        }
      else
        slog (L_NOTICE, _("unable to resolve host '%s'"), conf->hostname);
    }
}

void
connection::reset_dstaddr ()
{
  fill_sa (&sa, conf);
}

void
connection::send_ping (SOCKADDR *dsa, u8 pong)
{
  ping_packet *pkt = new ping_packet;

  pkt->setup (conf->id, pong ? ping_packet::PT_PONG : ping_packet::PT_PING);
  vpn->send_vpn_packet (pkt, dsa, IPTOS_LOWDELAY);

  delete pkt;
}

void
connection::send_reset (SOCKADDR *dsa)
{
  if (reset_rate_limiter.can (dsa) && connectmode != conf_node::C_DISABLED)
    {
      config_packet *pkt = new config_packet;

      pkt->setup (vpn_packet::PT_RESET, conf->id);
      vpn->send_vpn_packet (pkt, dsa, IPTOS_MINCOST);

      delete pkt;
    }
}

static rsachallenge *
gen_challenge (u32 seqrand, SOCKADDR *sa)
{
  static rsachallenge k;

  memcpy (&k, &challenge_bytes (), sizeof (k));
  *(u32 *)&k[CHG_SEQNO] ^= seqrand;
  xor_sa (k, sa);

  return &k;
}

void
connection::send_auth (auth_subtype subtype, SOCKADDR *sa, const rsachallenge *k)
{
  if (subtype == AUTH_REPLY || auth_rate_limiter.can (sa))
    {
      if (!k)
        k = gen_challenge (seqrand, sa);

      auth_packet *pkt = new auth_packet (conf->id, subtype);

      memcpy (pkt->challenge, rsa_cache.public_encrypt (conf->rsa_key, *k), sizeof (rsaencrdata));

      slog (L_TRACE, ">>%d PT_AUTH(%d) [%s]", conf->id, subtype, (const char *)sockinfo (sa));

      vpn->send_vpn_packet (pkt, sa, IPTOS_RELIABILITY);

      delete pkt;
    }
}

void
connection::establish_connection_cb (tstamp &ts)
{
  if (ictx || conf == THISNODE || connectmode == conf_node::C_NEVER)
    ts = TSTAMP_CANCEL;
  else if (ts <= NOW)
    {
      double retry_int = double (retry_cnt & 3 ? (retry_cnt & 3) : 1 << (retry_cnt >> 2)) * 0.25;

      if (retry_int < 3600 * 8)
        retry_cnt++;

      ts = NOW + retry_int;

      if (conf->hostname)
        {
          reset_dstaddr ();
          if (sa.sin_addr.s_addr)
            if (retry_cnt < 4)
              send_auth (AUTH_INIT, &sa);
            else if (auth_rate_limiter.can (&sa))
              send_ping (&sa, 0);
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
      slog (L_INFO, _("connection to %d (%s) lost"), conf->id, conf->nodename);

      if (::conf.script_node_down)
        run_script (this, &connection::script_node_down, false);
    }

  delete ictx; ictx = 0;
  delete octx; octx = 0;

  RAND_bytes ((unsigned char *)&seqrand, sizeof (u32));

  sa.sin_port = 0;
  sa.sin_addr.s_addr = 0;

  last_activity = 0;

  rekey.reset ();
  keepalive.reset ();
  establish_connection.reset ();
}

void
connection::shutdown ()
{
  if (ictx && octx)
    send_reset (&sa);

  reset_connection ();
}

void
connection::rekey_cb (tstamp &ts)
{
  ts = TSTAMP_CANCEL;

  reset_connection ();
  establish_connection ();
}

void
connection::send_data_packet (tap_packet * pkt, bool broadcast)
{
  vpndata_packet *p = new vpndata_packet;
  int tos = 0;

  if (conf->inherit_tos
      && (*pkt)[12] == 0x08 && (*pkt)[13] == 0x00 // IP
      && ((*pkt)[14] & 0xf0) == 0x40)             // IPv4
    tos = (*pkt)[15] & IPTOS_TOS_MASK;

  p->setup (this, broadcast ? 0 : conf->id, &((*pkt)[6 + 6]), pkt->len - 6 - 6, ++oseqno); // skip 2 macs
  vpn->send_vpn_packet (p, &sa, tos);

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
connection::recv_vpn_packet (vpn_packet *pkt, SOCKADDR *ssa)
{
  last_activity = NOW;

  slog (L_NOISE, "<<%d received packet type %d from %d to %d", 
        conf->id, pkt->typ (), pkt->src (), pkt->dst ());

  switch (pkt->typ ())
    {
    case vpn_packet::PT_PING:
      // we send pings instead of auth packets after some retries,
      // so reset the retry counter and establish a conenction
      // when we receive a pong.
      if (!ictx && !octx)
        {
          retry_cnt = 0;
          establish_connection.at = 0;
          establish_connection ();
        }
      else
        send_ping (ssa, 1); // pong

      break;

    case vpn_packet::PT_PONG:
      break;

    case vpn_packet::PT_RESET:
      {
        reset_connection ();

        config_packet *p = (config_packet *) pkt;
        if (!p->chk_config ())
          {
            slog (L_WARN, _("protocol mismatch, disabling node '%s'"), conf->nodename);
            connectmode = conf_node::C_DISABLED;
          }
        else if (connectmode == conf_node::C_ALWAYS)
          establish_connection ();
      }
      break;

    case vpn_packet::PT_AUTH:
      {
        auth_packet *p = (auth_packet *) pkt;

        slog (L_TRACE, "<<%d PT_AUTH(%d)", conf->id, p->subtype);

        if (p->chk_config ()
            && !strncmp (p->magic, MAGIC, 8))
          {
            if (p->prot_minor != PROTOCOL_MINOR)
              slog (L_INFO, _("protocol minor version mismatch: ours is %d, %s's is %d."),
                    PROTOCOL_MINOR, conf->nodename, p->prot_minor);

            if (p->subtype == AUTH_INIT)
              send_auth (AUTH_INITREPLY, ssa);

            const rsachallenge *k = rsa_cache.private_decrypt (::conf.rsa_key, p->challenge);

            if (!k)
              {
                slog (L_ERR, _("challenge from %s (%s) illegal or corrupted"),
                      conf->nodename, (const char *)sockinfo (ssa));
                send_reset (ssa);
                break;
              }

            retry_cnt = 0;
            establish_connection.set (NOW + 8); //? ;)
            keepalive.reset ();
            rekey.reset ();

            switch (p->subtype)
              {
              case AUTH_INIT:
              case AUTH_INITREPLY:
                delete ictx;
                ictx = 0;

                delete octx;

                octx   = new crypto_ctx (*k, 1);
                oseqno = ntohl (*(u32 *)&k[CHG_SEQNO]) & 0x7fffffff;

                send_auth (AUTH_REPLY, ssa, k);
                break;

              case AUTH_REPLY:

                if (!memcmp ((u8 *)gen_challenge (seqrand, ssa), (u8 *)k, sizeof (rsachallenge)))
                  {
                    delete ictx;

                    ictx = new crypto_ctx (*k, 0);
                    iseqno.reset (ntohl (*(u32 *)&k[CHG_SEQNO]) & 0x7fffffff);	// at least 2**31 sequence numbers are valid

                    sa = *ssa;

                    rekey.set (NOW + ::conf.rekey);
                    keepalive.set (NOW + ::conf.keepalive);

                    // send queued packets
                    while (tap_packet *p = queue.get ())
                      {
                        send_data_packet (p);
                        delete p;
                      }

                    connectmode = conf->connectmode;

                    slog (L_INFO, _("connection to %d (%s %s) established"),
                          conf->id, conf->nodename, (const char *)sockinfo (ssa));

                    if (::conf.script_node_up)
                      run_script (this, &connection::script_node_up, false);
                  }
                else
                  slog (L_ERR, _("sent and received challenge do not match with (%s %s))"),
                        conf->nodename, (const char *)sockinfo (ssa));

                break;
              default:
                slog (L_ERR, _("authentification illegal subtype error (%s %s)"),
                      conf->nodename, (const char *)sockinfo (ssa));
                break;
              }
          }
        else
          send_reset (ssa);

        break;
      }

    case vpn_packet::PT_DATA_COMPRESSED:
#if !ENABLE_COMPRESSION
      send_reset (ssa);
      break;
#endif
    case vpn_packet::PT_DATA_UNCOMPRESSED:

      if (ictx && octx)
        {
          vpndata_packet *p = (vpndata_packet *)pkt;

          if (*ssa == sa)
            {
              if (!p->hmac_chk (ictx))
                slog (L_ERR, _("hmac authentication error, received invalid packet\n"
                               "could be an attack, or just corruption or an synchronization error"));
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
            slog (L_ERR,  _("received data packet from unknown source %s"), (const char *)sockinfo (ssa));//D
        }

      send_reset (ssa);
      break;

    case vpn_packet::PT_CONNECT_REQ:
      if (ictx && octx && *ssa == sa && pkt->hmac_chk (ictx))
        {
          connect_req_packet *p = (connect_req_packet *) pkt;

          assert (p->id > 0 && p->id <= vpn->conns.size ()); // hmac-auth does not mean we accept anything

          connection *c = vpn->conns[p->id - 1];

          slog (L_TRACE, "<<%d PT_CONNECT_REQ(%d) [%d]\n",
                         conf->id, p->id, c->ictx && c->octx);

          if (c->ictx && c->octx)
            {
              // send connect_info packets to both sides, in case one is
              // behind a nat firewall (or both ;)
              {
                sockinfo si(sa);
                
                slog (L_TRACE, ">>%d PT_CONNECT_INFO(%d,%s)\n",
                               c->conf->id, conf->id, (const char *)si);

                connect_info_packet *r = new connect_info_packet (c->conf->id, conf->id, si);

                r->hmac_set (c->octx);
                vpn->send_vpn_packet (r, &c->sa);

                delete r;
              }

              {
                sockinfo si(c->sa);
                
                slog (L_TRACE, ">>%d PT_CONNECT_INFO(%d,%s)\n",
                               conf->id, c->conf->id, (const char *)si);

                connect_info_packet *r = new connect_info_packet (conf->id, c->conf->id, si);

                r->hmac_set (octx);
                vpn->send_vpn_packet (r, &sa);

                delete r;
              }
            }
        }

      break;

    case vpn_packet::PT_CONNECT_INFO:
      if (ictx && octx && *ssa == sa && pkt->hmac_chk (ictx))
        {
          connect_info_packet *p = (connect_info_packet *) pkt;

          assert (p->id > 0 && p->id <= vpn->conns.size ()); // hmac-auth does not mean we accept anything

          connection *c = vpn->conns[p->id - 1];

          slog (L_TRACE, "<<%d PT_CONNECT_INFO(%d,%s) (%d)",
                         conf->id, p->id, (const char *)p->si, !c->ictx && !c->octx);

          c->send_auth (AUTH_INIT, p->si.sa ());
        }
      break;

    default:
      send_reset (ssa);
      break;
    }
}

void connection::keepalive_cb (tstamp &ts)
{
  if (NOW >= last_activity + ::conf.keepalive + 30)
    {
      reset_connection ();
      establish_connection ();
    }
  else if (NOW < last_activity + ::conf.keepalive)
    ts = last_activity + ::conf.keepalive;
  else if (conf->connectmode != conf_node::C_ONDEMAND
        || THISNODE->connectmode != conf_node::C_ONDEMAND)
    {
      send_ping (&sa);
      ts = NOW + 5;
    }
  else
    reset_connection ();

}

void connection::connect_request (int id)
{
  connect_req_packet *p = new connect_req_packet (conf->id, id);

  slog (L_TRACE, ">>%d PT_CONNECT_REQ(%d)", id, conf->id);
  p->hmac_set (octx);
  vpn->send_vpn_packet (p, &sa);

  delete p;
}

void connection::script_node ()
{
  vpn->script_if_up ();

  char *env;
  asprintf (&env, "DESTID=%d",   conf->id);
  putenv (env);
  asprintf (&env, "DESTNODE=%s", conf->nodename);
  putenv (env);
  asprintf (&env, "DESTIP=%s",   inet_ntoa (sa.sin_addr));
  putenv (env);
  asprintf (&env, "DESTPORT=%d", ntohs (sa.sin_port));
  putenv (env);
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

/////////////////////////////////////////////////////////////////////////////

const char *vpn::script_if_up ()
{
  // the tunnel device mtu should be the physical mtu - overhead
  // the tricky part is rounding to the cipher key blocksize
  int mtu = conf.mtu - ETH_OVERHEAD - VPE_OVERHEAD - UDP_OVERHEAD;
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
vpn::setup (void)
{
  struct sockaddr_in sa;

  socket_fd = socket (PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (socket_fd < 0)
    return -1;

  fill_sa (&sa, THISNODE);

  if (bind (socket_fd, (sockaddr *)&sa, sizeof (sa)))
    {
      slog (L_ERR, _("can't bind to %s: %s"), (const char *)sockinfo(sa), strerror (errno));
      exit (1);
    }

#ifdef IP_MTU_DISCOVER
  // this I really consider a linux bug. I am neither connected
  // nor do I fragment myself. Linux still sets DF and doesn't
  // fragment for me sometimes.
  {
    int oval = IP_PMTUDISC_DONT;
    setsockopt (socket_fd, SOL_IP, IP_MTU_DISCOVER, &oval, sizeof oval);
  }
#endif
  {
    int oval = 1;
    setsockopt (socket_fd, SOL_SOCKET, SO_REUSEADDR, &oval, sizeof oval);
  }

  udp_ev_watcher.start (socket_fd, POLLIN);

  tap = new tap_device ();
  if (!tap) //D this, of course, never catches
    {
      slog (L_ERR, _("cannot create network interface '%s'"), conf.ifname);
      exit (1);
    }
  
  run_script (this, &vpn::script_if_up, true);

  vpn_ev_watcher.start (tap->fd, POLLIN);

  reconnect_all ();

  return 0;
}

void
vpn::send_vpn_packet (vpn_packet *pkt, SOCKADDR *sa, int tos)
{
  setsockopt (socket_fd, SOL_IP, IP_TOS, &tos, sizeof tos);
  sendto (socket_fd, &((*pkt)[0]), pkt->len, 0, (sockaddr *)sa, sizeof (*sa));
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
vpn::udp_ev (short revents)
{
  if (revents & (POLLIN | POLLERR))
    {
      vpn_packet *pkt = new vpn_packet;
      struct sockaddr_in sa;
      socklen_t sa_len = sizeof (sa);
      int len;

      len = recvfrom (socket_fd, &((*pkt)[0]), MAXSIZE, 0, (sockaddr *)&sa, &sa_len);

      if (len > 0)
        {
          pkt->len = len;

          unsigned int src = pkt->src ();
          unsigned int dst = pkt->dst ();

          slog (L_NOISE, _("<<?/%s received possible vpn packet type %d from %d to %d, length %d"),
                (const char *)sockinfo (sa), pkt->typ (), pkt->src (), pkt->dst (), pkt->len);

          if (dst > conns.size () || pkt->typ () >= vpn_packet::PT_MAX)
            slog (L_WARN, _("<<? received CORRUPTED packet type %d from %d to %d"),
                  pkt->typ (), pkt->src (), pkt->dst ());
          else if (dst == 0 && !THISNODE->routerprio)
            slog (L_WARN, _("<<%d received broadcast, but we are no router"), dst);
          else if (dst != 0 && dst != THISNODE->id)
            slog (L_WARN,
                 _("received frame for node %d ('%s') from %s, but this is node %d ('%s')"),
                 dst, conns[dst - 1]->conf->nodename,
                 (const char *)sockinfo (sa),
                 THISNODE->id, THISNODE->nodename);
          else if (src == 0 || src > conns.size ())
            slog (L_WARN, _("received frame from unknown node %d (%s)"), src, (const char *)sockinfo (sa));
          else
            conns[src - 1]->recv_vpn_packet (pkt, &sa);
        }
      else
        {
          // probably ECONNRESET or somesuch
          slog (L_DEBUG, _("%s: %s"), (const char *)sockinfo(sa), strerror (errno));
        }

      delete pkt;
    }
  else if (revents & POLLHUP)
    {
      // this cannot ;) happen on udp sockets
      slog (L_ERR, _("FATAL: POLLHUP on socket fd, terminating."));
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
vpn::vpn_ev (short revents)
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
          shutdown_all ();

          remove_pid (pidfilename);

          slog (L_INFO, _("vped terminating"));

          exit (0);
        }

      if (events & EVENT_RECONNECT)
        reconnect_all ();

      events = 0;
    }

  ts = TSTAMP_CANCEL;
}

#include <sys/time.h>//D
vpn::vpn (void)
: udp_ev_watcher (this, &vpn::udp_ev)
, vpn_ev_watcher (this, &vpn::vpn_ev)
, event (this, &vpn::event_cb)
{
}

vpn::~vpn ()
{
}

