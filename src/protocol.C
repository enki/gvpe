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
  static time_t challenge_ttl;	// time this challenge needs to be recreated

  if (now > challenge_ttl)
    {
      RAND_bytes ((unsigned char *)&challenge, sizeof (challenge));
      challenge_ttl = now + CHALLENGE_TTL;
    }

  return challenge;
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

    crypto_ctx (rsachallenge &challenge, int enc);
    ~crypto_ctx ();
  };

crypto_ctx::crypto_ctx (rsachallenge &challenge, int enc)
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
      //printf ("compressed packet, %d => %d\n", l, cl);//D
      type = PT_DATA_COMPRESSED;
      d = cdata;
      l = cl + 2;

      d[0] = cl >> 8;
      d[1] = cl;
    }
#endif

  EVP_EncryptInit_ex (cctx, 0, 0, 0, 0);

#if RAND_SIZE
  struct {
    u8 rnd[RAND_SIZE];
    u32 seqno;
  } datahdr;

  datahdr.seqno = seqno;
  RAND_pseudo_bytes ((unsigned char *) datahdr.rnd, RAND_SIZE);

  EVP_EncryptUpdate (cctx,
                     (unsigned char *) data + outl, &outl2,
                     (unsigned char *) &datahdr, DATAHDR);
  outl += outl2;
#else
  EVP_EncryptUpdate (cctx,
                     (unsigned char *) data + outl, &outl2,
                     (unsigned char *) &seqno, DATAHDR);
  outl += outl2;
#endif

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
  
  seqno = *(u32 *)(d + RAND_SIZE);

  id2mac (dst () ? dst() : THISNODE->id, p->dst);
  id2mac (src (),                        p->src);

#if ENABLE_COMPRESSION
  if (type == PT_DATA_COMPRESSED)
    {
      u32 cl = (d[DATAHDR] << 8) | d[DATAHDR + 1];
      p->len = lzf_decompress (d + DATAHDR + 2, cl, &(*p)[6 + 6], MAX_MTU) + 6 + 6;
      //printf ("decompressxed %d(%d) => %d\n", cl, len - data_hdr_size (), p->len);//D
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
             | (ENABLE_COMPRESSION ? 0x01 : 0x00)
             | (ENABLE_TRUST       ? 0x02 : 0x00);
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
  vpn->send_vpn_packet (pkt, dsa);

  delete pkt;
}

void
connection::send_reset (SOCKADDR *dsa)
{
  static net_rate_limiter limiter(1);

  if (limiter.can (dsa))
    {
      config_packet *pkt = new config_packet;

      pkt->setup (vpn_packet::PT_RESET, conf->id);
      vpn->send_vpn_packet (pkt, dsa);

      delete pkt;
    }
}

static rsachallenge *
gen_challenge (SOCKADDR *sa)
{
  static rsachallenge k;

  memcpy (&k, &challenge_bytes (), sizeof (k));
  RAND_bytes ((unsigned char *)&k[CHG_SEQNO], sizeof (u32));
  xor_sa (k, sa);

  return &k;
}

void
connection::send_auth (auth_subtype subtype, SOCKADDR *sa, rsachallenge *k)
{
  static net_rate_limiter limiter(2);

  if (subtype != AUTH_INIT || limiter.can (sa))
    {
      auth_packet *pkt = new auth_packet (conf->id, subtype);

      //printf ("send auth_packet subtype %d\n", subtype);//D

      if (!k)
        k = gen_challenge (sa);

#if ENABLE_TRUST
      if (0 > RSA_public_encrypt (sizeof (*k),
                                  (unsigned char *)k, (unsigned char *)&pkt->challenge,
                                  conf->rsa_key, RSA_PKCS1_OAEP_PADDING))
        fatal ("RSA_public_encrypt error");
#else
# error untrusted mode not yet implemented: programemr does not know how to
      rsaencrdata enc;

      if (0 > RSA_private_encrypt (sizeof (*k),
                                   (unsigned char *)k, (unsigned char *)&enc,
                                   ::conf.rsa_key, RSA_PKCS1_OAEP_PADDING))
        fatal ("RSA_private_encrypt error");

      if (0 > RSA_public_encrypt (sizeof (enc),
                                  (unsigned char *)enc, (unsigned char *)&pkt->challenge,
                                  conf->rsa_key, RSA_NO_PADDING))
        fatal ("RSA_public_encrypt error");
#endif

      slog (L_TRACE, ">>%d PT_AUTH(%d) [%s]", conf->id, subtype, (const char *)sockinfo (sa));

      vpn->send_vpn_packet (pkt, sa);

      delete pkt;
    }
}

void
connection::establish_connection ()
{
  if (!ictx && conf != THISNODE && conf->connectmode != conf_node::C_NEVER)
    {
      if (now >= next_retry)
        {
          int retry_int = retry_cnt & 3 ? (retry_cnt & 3) : 1 << (retry_cnt >> 2);

          if (retry_cnt < (17 << 2) | 3)
            retry_cnt++;

          if (conf->connectmode == conf_node::C_ONDEMAND
              && retry_int > ::conf.keepalive)
            retry_int = ::conf.keepalive;

          next_retry = now + retry_int;
          next_wakeup (next_retry);

          if (conf->hostname)
            {
              reset_dstaddr ();
              if (sa.sin_addr.s_addr)
                if (retry_cnt < 4)
                  send_auth (AUTH_INIT, &sa);
                else
                  send_ping (&sa, 0);
            }
          else
            vpn->connect_request (conf->id);
        }
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

  delete ictx;
  ictx = 0;

  delete octx;
  octx = 0;

  sa.sin_port = 0;
  sa.sin_addr.s_addr = 0;

  next_retry = 0;
  next_rekey = 0;
  last_activity = 0;
}

void
connection::shutdown ()
{
  if (ictx && octx)
    send_reset (&sa);

  reset_connection ();
}

void
connection::rekey ()
{
  reset_connection ();
  establish_connection ();
}

void
connection::send_data_packet (tap_packet * pkt, bool broadcast)
{
  vpndata_packet *p = new vpndata_packet;

  p->setup (this, broadcast ? 0 : conf->id, &((*pkt)[6 + 6]), pkt->len - 6 - 6, ++oseqno); // skip 2 macs
  vpn->send_vpn_packet (p, &sa);

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
  last_activity = now;

  slog (L_NOISE, "<<%d received packet type %d from %d to %d", 
        conf->id, pkt->typ (), pkt->src (), pkt->dst ());

  switch (pkt->typ ())
    {
    case vpn_packet::PT_PING:
      send_ping (ssa, 1); // pong
      break;

    case vpn_packet::PT_PONG:
      // we send pings instead of auth packets after some retries,
      // so reset the retry counter and establish a conenction
      // when we receive a pong.
      if (!ictx && !octx)
        {
          retry_cnt = 0;
          next_retry = 0;
          establish_connection ();
        }

      break;

    case vpn_packet::PT_RESET:
      {
        reset_connection ();

        config_packet *p = (config_packet *) pkt;
        if (p->chk_config ())
          if (conf->connectmode == conf_node::C_ALWAYS)
            establish_connection ();

        //D slog the protocol mismatch?
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

            rsachallenge k;

#if ENABLE_TRUST
            if (0 > RSA_private_decrypt (sizeof (rsaencrdata),
                                         (unsigned char *)&p->challenge, (unsigned char *)&k,
                                         ::conf.rsa_key, RSA_PKCS1_OAEP_PADDING))
              // continued below
#else
            rsaencrdata j;
            
            if (0 > RSA_private_decrypt (sizeof (rsaencrdata),
                                         (unsigned char *)&p->challenge, (unsigned char *)&j,
                                         ::conf.rsa_key, RSA_NO_PADDING))
              fatal ("RSA_private_decrypt error");

            if (0 > RSA_public_decrypt (sizeof (k),
                                        (unsigned char *)&j, (unsigned char *)&k,
                                        conf->rsa_key, RSA_PKCS1_OAEP_PADDING))
              // continued below
#endif
              {
                slog (L_ERR, _("challenge from %s (%s) illegal or corrupted"),
                      conf->nodename, (const char *)sockinfo (ssa));
                break;
              }

            retry_cnt = 0;
            next_retry = now + 8;

            switch (p->subtype)
              {
              case AUTH_INIT:
              case AUTH_INITREPLY:
                delete ictx;
                ictx = 0;

                delete octx;

                octx   = new crypto_ctx (k, 1);
                oseqno = *(u32 *)&k[CHG_SEQNO] & 0x7fffffff;

                send_auth (AUTH_REPLY, ssa, &k);
                break;

              case AUTH_REPLY:

                if (!memcmp ((u8 *)gen_challenge (ssa) + sizeof (u32), (u8 *)&k + sizeof (u32),
                             sizeof (rsachallenge) - sizeof (u32)))
                  {
                    delete ictx;

                    ictx   = new crypto_ctx (k, 0);
                    iseqno = *(u32 *)&k[CHG_SEQNO] & 0x7fffffff;	// at least 2**31 sequence numbers are valid
                    ismask = 0xffffffff;				// initially, all lower sequence numbers are invalid

                    sa = *ssa;

                    next_rekey = now + ::conf.rekey;
                    next_wakeup (next_rekey);

                    // send queued packets
                    while (tap_packet *p = queue.get ())
                      {
                        send_data_packet (p);
                        delete p;
                      }

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

                  if (seqno <= iseqno - 32)
                    slog (L_ERR, _("received duplicate or outdated packet (received %08lx, expected %08lx)\n"
                                   "possible replay attack, or just massive packet reordering"), seqno, iseqno + 1);//D
                  else if (seqno > iseqno + 32)
                    slog (L_ERR, _("received duplicate or out-of-sync packet (received %08lx, expected %08lx)\n"
                                   "possible replay attack, or just massive packet loss"), seqno, iseqno + 1);//D
                  else
                    {
                      if (seqno > iseqno)
                        {
                          ismask <<= seqno - iseqno;
                          iseqno = seqno;
                        }

                      u32 mask = 1 << (iseqno - seqno);

                      //printf ("received seqno %08lx, iseqno %08lx, mask %08lx is %08lx\n", seqno, iseqno, mask, ismask);
                      if (ismask & mask)
                        slog (L_ERR, _("received duplicate packet (received %08lx, expected %08lx)\n"
                                       "possible replay attack, or just packet duplication"), seqno, iseqno + 1);//D
                      else
                        {
                          ismask |= mask;

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
              sockinfo si(sa);
              
              slog (L_TRACE, ">>%d PT_CONNECT_INFO(%d,%s)\n",
                             c->conf->id, p->id, (const char *)si);

              connect_info_packet *r = new connect_info_packet (c->conf->id, conf->id, si);

              r->hmac_set (c->octx);
              vpn->send_vpn_packet (r, &c->sa);

              delete r;
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

void connection::timer ()
{
  if (conf != THISNODE)
    {
      if (now >= next_retry && conf->connectmode == conf_node::C_ALWAYS)
        establish_connection ();

      if (ictx && octx)
        {
          if (now >= next_rekey)
            rekey ();
          else if (now >= last_activity + ::conf.keepalive + 30)
            {
              reset_connection ();
              establish_connection ();
            }
          else if (now >= last_activity + ::conf.keepalive)
            if (conf->connectmode != conf_node::C_ONDEMAND
                || THISNODE->connectmode != conf_node::C_ONDEMAND)
              send_ping (&sa);
            else
              reset_connection ();

        }
    }
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

/////////////////////////////////////////////////////////////////////////////

vpn::vpn (void)
{}

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

  tap = new tap_device ();
  if (!tap) //D this, of course, never catches
    {
      slog (L_ERR, _("cannot create network interface '%s'"), conf.ifname);
      exit (1);
    }

  run_script (this, &vpn::script_if_up, true);

  return 0;
}

void
vpn::send_vpn_packet (vpn_packet *pkt, SOCKADDR *sa)
{
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

      if (conn->conf->connectmode == conf_node::C_ALWAYS)
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
          && c->conf->connectmode == conf_node::C_ALWAYS
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
}

void
vpn::main_loop ()
{
  struct pollfd pollfd[2];

  pollfd[0].fd = tap->fd;
  pollfd[0].events = POLLIN;
  pollfd[1].fd = socket_fd;
  pollfd[1].events = POLLIN;

  events = 0;
  now = time (0);
  next_timecheck = now + 1;

  reconnect_all ();

  for (;;)
    {
      int npoll = poll (pollfd, 2, (next_timecheck - now) * 1000);
      
      now = time (0);

      if (npoll > 0)
        {
          if (pollfd[1].revents)
            {
              if (pollfd[1].revents & (POLLIN | POLLERR))
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
              else if (pollfd[1].revents & POLLHUP)
                {
                  // this cannot ;) happen on udp sockets
                  slog (L_ERR, _("FATAL: POLLHUP on socket fd, terminating."));
                  exit (1);
                }
              else
                {
                  slog (L_ERR,
                          _("FATAL: unknown revents %08x in socket, terminating\n"),
                          pollfd[1].revents);
                  exit (1);
                }
            }

          // I use else here to give vpn_packets absolute priority
          else if (pollfd[0].revents)
            {
              if (pollfd[0].revents & POLLIN)
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
              else if (pollfd[0].revents & (POLLHUP | POLLERR))
                {
                  slog (L_ERR, _("FATAL: POLLHUP or POLLERR on network device fd, terminating."));
                  exit (1);
                }
              else
                abort ();
            }
        }

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

      // very very very dumb and crude and inefficient timer handling, or maybe not?
      if (now >= next_timecheck)
        {
          next_timecheck = now + TIMER_GRANULARITY;

          for (conns_vector::iterator c = conns.begin ();
               c != conns.end (); ++c)
            (*c)->timer ();
        }
    }
}

vpn::~vpn ()
{}

