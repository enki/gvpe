/*
    vpn_dns.C -- handle the dns tunnel part of the protocol.
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

#include "config.h"

#if ENABLE_DNS

// dns processing is EXTREMELY ugly. For obvious(?) reasons.
// it's a hack, use only in emergency situations please.

#include <cstring>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include <map>

#include <gmp.h>

#include "netcompat.h"

#include "vpn.h"

#define MIN_POLL_INTERVAL .02  // how often to poll minimally when the server has data
#define MAX_POLL_INTERVAL 6.  // how often to poll minimally when the server has no data
#define ACTIVITY_INTERVAL 5.

#define INITIAL_TIMEOUT     1. // retry timeouts
#define INITIAL_SYN_TIMEOUT 2. // retry timeout for initial syn

#define MIN_SEND_INTERVAL 0.01 // wait at least this time between sending requests
#define MAX_SEND_INTERVAL 0.5 // optimistic?

#define MAX_OUTSTANDING 40 // max. outstanding requests
#define MAX_WINDOW      100 // max. for MAX_OUTSTANDING
#define MAX_BACKLOG     (100*1024) // size of gvpe protocol backlog (bytes), must be > MAXSIZE

#define MAX_DOMAIN_SIZE 220 // 255 is legal limit, but bind doesn't compress well
// 240 leaves about 4 bytes of server reply data
// every two request bytes less give room for one reply byte

#define SEQNO_MASK 0xffff
#define SEQNO_EQ(a,b) ( 0 == ( ((a) ^ (b)) & SEQNO_MASK) )

#define MAX_LBL_SIZE 63
#define MAX_PKT_SIZE 512

#define RR_TYPE_A     1
#define RR_TYPE_NULL 10
#define RR_TYPE_TXT  16
#define RR_TYPE_ANY 255

#define RR_CLASS_IN   1

#define CMD_IP_1   207
#define CMD_IP_2    46
#define CMD_IP_3   236
#define CMD_IP_RST  29
#define CMD_IP_SYN 113
#define CMD_IP_REJ  32

// works for cmaps up to 255 (not 256!)
struct charmap
{
  enum { INVALID = (u8)255 };

  char encode [256]; // index => char
  u8 decode [256]; // char => index
  unsigned int size;

  charmap (const char *cmap);
};

charmap::charmap (const char *cmap)
{
  char *enc = encode;
  u8 *dec = decode;

  memset (enc, (char)      0, 256);
  memset (dec, (char)INVALID, 256);

  for (size = 0; cmap [size]; size++)
    {
      enc [size] = cmap [size];
      dec [(u8)enc [size]] = size;
    }

  assert (size < 256);
}

#define MAX_DEC_LEN 500
#define MAX_ENC_LEN (MAX_DEC_LEN * 2)
#define MAX_LIMBS ((MAX_DEC_LEN * 8 + GMP_NUMB_BITS - 1) / GMP_NUMB_BITS)

// ugly. minimum base is 16(!)
struct basecoder
{
  charmap cmap;
  unsigned int enc_len [MAX_DEC_LEN];
  unsigned int dec_len [MAX_ENC_LEN];

  unsigned int encode_len (unsigned int len);
  unsigned int decode_len (unsigned int len);

  unsigned int encode (char *dst, u8 *src, unsigned int len);
  unsigned int decode (u8 *dst, char *src, unsigned int len);

  basecoder (const char *cmap);
};

basecoder::basecoder (const char *cmap)
: cmap (cmap)
{
  for (unsigned int len = 0; len < MAX_DEC_LEN; ++len)
    {
      u8 src [MAX_DEC_LEN];
      u8 dst [MAX_ENC_LEN];

      memset (src, 255, len);

      mp_limb_t m [MAX_LIMBS];
      mp_size_t n;

      n = mpn_set_str (m, src, len, 256);
      n = mpn_get_str (dst, this->cmap.size, m, n);

      for (int i = 0; !dst [i]; ++i)
        n--;

      enc_len [len] = n;
      dec_len [n] = len;
    }
}

unsigned int basecoder::encode_len (unsigned int len)
{
  return enc_len [len];
}

unsigned int basecoder::decode_len (unsigned int len)
{
  while (len && !dec_len [len])
    --len;

  return dec_len [len];
}

unsigned int basecoder::encode (char *dst, u8 *src, unsigned int len)
{
  if (!len || len > MAX_DEC_LEN)
    return 0;

  int elen = encode_len (len);

  mp_limb_t m [MAX_LIMBS];
  mp_size_t n;

  u8 dst_ [MAX_ENC_LEN];

  n = mpn_set_str (m, src, len, 256);
  n = mpn_get_str (dst_, cmap.size, m, n);

  int plen = elen; // for padding

  while (n < plen)
    {
      *dst++ = cmap.encode [0];
      plen--;
    }

  for (unsigned int i = n - plen; i < n; ++i)
    *dst++ = cmap.encode [dst_ [i]];

  return elen;
}

unsigned int basecoder::decode (u8 *dst, char *src, unsigned int len)
{
  if (!len || len > MAX_ENC_LEN)
    return 0;

  u8 src_ [MAX_ENC_LEN];
  unsigned int elen = 0;

  while (len--)
    {
      u8 val = cmap.decode [(u8)*src++];

      if (val != charmap::INVALID)
        src_ [elen++] = val;
    }

  int dlen = decode_len (elen);

  mp_limb_t m [MAX_LIMBS];
  mp_size_t n;

  u8 dst_ [MAX_DEC_LEN];

  n = mpn_set_str (m, src_, elen, cmap.size);
  n = mpn_get_str (dst_, 256, m, n);

  if (n < dlen)
    {
      memset (dst, 0, dlen - n);
      memcpy (dst + dlen - n, dst_, n);
    }
  else
    memcpy (dst, dst_ + n - dlen, dlen);

  return dlen;
}

#if 0
struct test { test (); } test;

test::test ()
{
  basecoder cdc ("0123456789abcdefghijklmnopqrstuvwxyz");

  u8 in[] = "0123456789abcdefghijklmnopqrstuvwxyz";
  static char enc[200];
  static u8 dec[200];

  for (int i = 1; i < 20; i++)
   {
     int elen = cdc.encode (enc, in, i);
     int dlen = cdc.decode (dec, enc, elen);

     printf ("%d>%d>%d (%s>%s)\n", i, elen, dlen, enc, dec);
   }
  abort ();
}
#endif

//static basecoder cdc64 ("_dDpPhHzZrR06QqMmjJkKBb34TtSsvVlL81xXaAeEFf92WwGgYyoO57UucCNniI-");
//static basecoder cdc63 ("_dDpPhHzZrR06QqMmjJkKBb34TtSsvVlL81xXaAeEFf92WwGgYyoO57UucCNniI");
static basecoder cdc62 ("dDpPhHzZrR06QqMmjJkKBb34TtSsvVlL81xXaAeEFf92WwGgYyoO57UucCNniI");
//static basecoder cdc36 ("dphzr06qmjkb34tsvl81xaef92wgyo57ucni"); // unused as of yet
static basecoder cdc26 ("dPhZrQmJkBtSvLxAeFwGyO");

/////////////////////////////////////////////////////////////////////////////

#define HDRSIZE 6

inline void encode_header (char *data, int clientid, int seqno)
{
  u8 hdr[3] = { clientid, seqno >> 8, seqno };

  assert (clientid < 256);

  cdc26.encode (data, hdr, 3);
}

inline void decode_header (char *data, int &clientid, int &seqno)
{
  u8 hdr[3];

  cdc26.decode (hdr, data, HDRSIZE);

  clientid = hdr[0];
  seqno = (hdr[1] << 8) | hdr[2];
}

/////////////////////////////////////////////////////////////////////////////

struct byte_stream
{
  u8 *data;
  int maxsize;
  int fill;

  byte_stream (int maxsize);
  ~byte_stream ();

  bool empty () { return !fill; }
  int size () { return fill; }

  bool put (u8 *data, unsigned int datalen);
  bool put (vpn_packet *pkt);
  vpn_packet *get ();

  u8 *begin () { return data; }
  void remove (int count);
};

byte_stream::byte_stream (int maxsize)
: maxsize (maxsize), fill (0)
{
  data = new u8 [maxsize];
}

byte_stream::~byte_stream ()
{
  delete data;
}

void byte_stream::remove (int count)
{
  if (count > fill)
    abort ();

  memmove (data, data + count, fill -= count);
}

bool byte_stream::put (u8 *data, unsigned int datalen)
{
  if (maxsize - fill < datalen)
    return false;

  memcpy (this->data + fill, data, datalen); fill += datalen;

  return true;
}

bool byte_stream::put (vpn_packet *pkt)
{
  if (maxsize - fill < pkt->len + 2)
    return false;

  data [fill++] = pkt->len >> 8;
  data [fill++] = pkt->len;

  memcpy (data + fill, pkt->at (0), pkt->len); fill += pkt->len;

  return true;
}

vpn_packet *byte_stream::get ()
{
  unsigned int len = (data [0] << 8) | data [1];

  if (len > MAXSIZE && fill >= 2)
    abort (); // TODO handle this gracefully, connection reset

  if (fill < len + 2)
    return 0;

  vpn_packet *pkt = new vpn_packet;

  pkt->len = len;
  memcpy (pkt->at (0), data + 2, len);
  remove (len + 2);

  return pkt;
}

/////////////////////////////////////////////////////////////////////////////

#define FLAG_QUERY    ( 0 << 15)
#define FLAG_RESPONSE ( 1 << 15)
#define FLAG_OP_MASK  (15 << 11)
#define FLAG_OP_QUERY ( 0 << 11)
#define FLAG_AA       ( 1 << 10)
#define FLAG_TC       ( 1 <<  9)
#define FLAG_RD       ( 1 <<  8)
#define FLAG_RA       ( 1 <<  7)
#define FLAG_AUTH     ( 1 <<  5)
#define FLAG_RCODE_MASK     (15 << 0)
#define FLAG_RCODE_OK       ( 0 << 0)
#define FLAG_RCODE_FORMERR  ( 1 << 0)
#define FLAG_RCODE_SERVFAIL ( 2 << 0)
#define FLAG_RCODE_NXDOMAIN ( 3 << 0)
#define FLAG_RCODE_REFUSED  ( 5 << 0)

#define DEFAULT_CLIENT_FLAGS (FLAG_QUERY | FLAG_OP_QUERY | FLAG_RD)
#define DEFAULT_SERVER_FLAGS (FLAG_RESPONSE | FLAG_OP_QUERY | FLAG_AA | FLAG_RD | FLAG_RA)

struct dns_cfg
{
  static int next_uid;

  u8 id1, id2, id3, id4;
  u8 version;
  u8 rrtype;
  u8 flags;
  u8 def_ttl;
  u8 rcv_cdc;
  u8 snd_cdc;
  u16 max_size;
  u16 client;
  u16 uid; // to make request unique

  u8 reserved[8];

  void reset (int clientid);
  bool valid ();
};

int dns_cfg::next_uid;

void dns_cfg::reset (int clientid)
{
  id1 = 'G';
  id2 = 'V';
  id3 = 'P';
  id4 = 'E';

  version  = 1;

  rrtype   = RR_TYPE_TXT;
  flags    = 0;
  def_ttl  = 0;
  rcv_cdc  = 0;
  snd_cdc  = 62;
  max_size = ntohs (MAX_PKT_SIZE);
  client   = ntohs (clientid);
  uid      = next_uid++;

  memset (reserved, 0, 8);
}

bool dns_cfg::valid ()
{
  return id1 == 'G'
      && id2 == 'V'
      && id3 == 'P'
      && id4 == 'E'
      && version == 1
      && flags == 0
      && rcv_cdc == 0
      && snd_cdc == 62
      && max_size == ntohs (MAX_PKT_SIZE);
}

struct dns_packet : net_packet
{
  u16 id;
  u16 flags; // QR:1 Opcode:4 AA:1 TC:1 RD:1 RA:1 Z:3 RCODE:4
  u16 qdcount, ancount, nscount, arcount;

  u8 data[MAXSIZE - 6 * 2];

  int decode_label (char *data, int size, int &offs);
};

int dns_packet::decode_label (char *data, int size, int &offs)
{
  char *orig = data;

  memset (data, 0, size);

  while (offs < size - 1)
    {
      u8 len = (*this)[offs++];

      if (!len)
        break;
      else if (len < 64)
        {
          if (size < len + 1 || offs + len >= MAXSIZE - 1)
            break;

          memcpy (data, &((*this)[offs]), len);

          data += len; size -= len; offs += len;
          *data++ = '.'; size--;
        }
      else
        {
          int offs2 = ((len & 63) << 8) + (*this)[offs++];

          data += decode_label (data, size, offs2);
          break;
        }
    }

  return data - orig;
}

/////////////////////////////////////////////////////////////////////////////

struct dns_snd
{
  dns_packet *pkt;
  tstamp timeout, sent;
  int retry;
  struct dns_connection *dns;
  int seqno;

  void gen_stream_req (int seqno, byte_stream &stream);
  void gen_syn_req (const dns_cfg &cfg);

  dns_snd (dns_connection *dns);
  ~dns_snd ();
};

static u16 dns_id = 12098; // TODO: should be per-vpn

static u16 next_id ()
{
  // the simplest lsfr with periodicity 65535 i could find
  dns_id = (dns_id << 1)
           | (((dns_id >> 1)
               ^ (dns_id >> 2)
               ^ (dns_id >> 4)
               ^ (dns_id >> 15)) & 1);

  return dns_id;
}

dns_snd::dns_snd (dns_connection *dns)
: dns (dns)
{
  timeout = 0;
  retry = 0;
  seqno = 0;
  sent = NOW;

  pkt = new dns_packet;

  pkt->id = next_id ();
}

dns_snd::~dns_snd ()
{
  delete pkt;
}

static void append_domain (dns_packet &pkt, int &offs, const char *domain)
{
  // add tunnel domain
  for (;;)
    {
      const char *end = strchr (domain, '.');

      if (!end)
        end = domain + strlen (domain);

      int len = end - domain;

      pkt [offs++] = len;
      memcpy (pkt.at (offs), domain, len);
      offs += len;

      if (!*end)
        break;

      domain = end + 1;
    }
}

void dns_snd::gen_stream_req (int seqno, byte_stream &stream)
{
  this->seqno = seqno;

  timeout = NOW + INITIAL_TIMEOUT;

  pkt->flags = htons (DEFAULT_CLIENT_FLAGS);
  pkt->qdcount = htons (1);

  int offs = 6*2;
  int dlen = MAX_DOMAIN_SIZE - (strlen (THISNODE->domain) + 2);
  // MAX_DOMAIN_SIZE is technically 255, but bind doesn't compress responses well,
  // so we need to have space for 2*MAX_DOMAIN_SIZE + header + extra

  char enc[256], *encp = enc;
  encode_header (enc, THISNODE->id, seqno);

  int datalen = cdc62.decode_len (dlen - (dlen + MAX_LBL_SIZE - 1) / MAX_LBL_SIZE - HDRSIZE);

  if (datalen > stream.size ())
    datalen = stream.size ();

  int enclen = cdc62.encode (enc + HDRSIZE, stream.begin (), datalen) + HDRSIZE;
  stream.remove (datalen);

  while (enclen)
    {
      int lbllen = enclen < MAX_LBL_SIZE ? enclen : MAX_LBL_SIZE;

      (*pkt)[offs++] = lbllen;
      memcpy (pkt->at (offs), encp, lbllen);

      offs += lbllen;
      encp += lbllen;

      enclen -= lbllen;
    }

  append_domain (*pkt, offs, THISNODE->domain);

  (*pkt)[offs++] = 0;
  (*pkt)[offs++] = RR_TYPE_ANY >> 8; (*pkt)[offs++] = RR_TYPE_ANY;
  (*pkt)[offs++] = RR_CLASS_IN >> 8; (*pkt)[offs++] = RR_CLASS_IN;

  pkt->len = offs;
}

void dns_snd::gen_syn_req (const dns_cfg &cfg)
{
  timeout = NOW + INITIAL_SYN_TIMEOUT;

  pkt->flags = htons (DEFAULT_CLIENT_FLAGS);
  pkt->qdcount = htons (1);

  int offs = 6*2;

  int elen = cdc26.encode ((char *)pkt->at (offs + 1), (u8 *)&cfg, sizeof (dns_cfg));

  assert (elen <= MAX_LBL_SIZE);

  (*pkt)[offs] = elen;
  offs += elen + 1;
  append_domain (*pkt, offs, THISNODE->domain);

  (*pkt)[offs++] = 0;
  (*pkt)[offs++] = RR_TYPE_A   >> 8; (*pkt)[offs++] = RR_TYPE_A;
  (*pkt)[offs++] = RR_CLASS_IN >> 8; (*pkt)[offs++] = RR_CLASS_IN;

  pkt->len = offs;
}

struct dns_rcv
{
  int seqno;
  dns_packet *pkt; // reply packet
  u8 data [MAXSIZE]; // actually part of the reply packet...
  int datalen;

  dns_rcv (int seqno, u8 *data, int datalen);
  ~dns_rcv ();
};

dns_rcv::dns_rcv (int seqno, u8 *data, int datalen)
: seqno (seqno), pkt (new dns_packet), datalen (datalen)
{
  memcpy (this->data, data, datalen);
}

dns_rcv::~dns_rcv ()
{
  delete pkt;
}

/////////////////////////////////////////////////////////////////////////////
    
struct dns_connection
{
  connection *c;
  struct vpn *vpn;

  dns_cfg cfg;

  bool established;

  tstamp last_received;
  tstamp last_sent;
  double poll_interval, send_interval;

  vector<dns_rcv *> rcvpq;

  byte_stream rcvdq; int rcvseq;
  byte_stream snddq; int sndseq;

  void time_cb (time_watcher &w); time_watcher tw;
  void receive_rep (dns_rcv *r);

  dns_connection (connection *c);
  ~dns_connection ();
};

dns_connection::dns_connection (connection *c)
: c (c)
, rcvdq (MAX_BACKLOG * 2)
, snddq (MAX_BACKLOG * 2)
, tw (this, &dns_connection::time_cb)
{
  vpn = c->vpn;

  established = false;

  rcvseq = sndseq = 0;

  last_sent = last_received = 0;
  poll_interval = MIN_POLL_INTERVAL;
  send_interval = 0.2; // starting rate
}

dns_connection::~dns_connection ()
{
  for (vector<dns_rcv *>::iterator i = rcvpq.begin ();
       i != rcvpq.end ();
       ++i)
    delete *i;
}

void dns_connection::receive_rep (dns_rcv *r)
{
  if (r->datalen)
    {
      last_received = NOW;
      tw.trigger ();
      
      poll_interval = send_interval;
    }
  else
    {
      poll_interval *= 1.1;
      if (poll_interval > MAX_POLL_INTERVAL)
        poll_interval = MAX_POLL_INTERVAL;
    }

  rcvpq.push_back (r);

  redo:

  // find next packet
  for (vector<dns_rcv *>::iterator i = rcvpq.end (); i-- != rcvpq.begin (); )
    if (SEQNO_EQ (rcvseq, (*i)->seqno))
      {
        // enter the packet into our input stream
        r = *i;

        // remove the oldest packet, look forward, as it's oldest first
        for (vector<dns_rcv *>::iterator j = rcvpq.begin (); j != rcvpq.end (); ++j)
          if (SEQNO_EQ ((*j)->seqno, rcvseq - MAX_WINDOW))
            {
              delete *j;
              rcvpq.erase (j);
              break;
            }

        rcvseq = (rcvseq + 1) & SEQNO_MASK;

        if (!rcvdq.put (r->data, r->datalen))
          abort (); // MUST never overflow, can be caused by data corruption, TODO

        while (vpn_packet *pkt = rcvdq.get ())
          {
            sockinfo si;
            si.host = 0; si.port = 0; si.prot = PROT_DNSv4;

            vpn->recv_vpn_packet (pkt, si);

            delete pkt;
          }

        // check for further packets
        goto redo;
      }
}

void
vpn::dnsv4_server (dns_packet &pkt)
{
  u16 flags = ntohs (pkt.flags);

  int offs = 6 * 2; // skip header

  pkt.flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_FORMERR);

  if (0 == (flags & (FLAG_RESPONSE | FLAG_OP_MASK))
      && pkt.qdcount == htons (1))
    {
      char qname[MAXSIZE];
      int qlen = pkt.decode_label ((char *)qname, MAXSIZE - offs, offs);

      u16 qtype  = pkt [offs++] << 8; qtype  |= pkt [offs++];
      u16 qclass = pkt [offs++] << 8; qclass |= pkt [offs++];

      pkt.qdcount = htons (1);
      pkt.ancount = 0;
      pkt.nscount = 0; // should be self, as other nameservers reply like this
      pkt.arcount = 0; // a record for self, as other nameservers reply like this

      pkt.flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_NXDOMAIN);

      int dlen = strlen (THISNODE->domain);

      if (qclass == RR_CLASS_IN
          && qlen > dlen + 1
          && !memcmp (qname + qlen - dlen - 1, THISNODE->domain, dlen))
        {
          // now generate reply
          pkt.ancount = htons (1); // one answer RR
          pkt.flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_OK);

          if ((qtype == RR_TYPE_ANY
               || qtype == RR_TYPE_TXT
               || qtype == RR_TYPE_NULL)
              && qlen > dlen + 1 + HDRSIZE)
            {
              // correct class, domain: parse
              int client, seqno;
              decode_header (qname, client, seqno);

              u8 data[MAXSIZE];
              int datalen = cdc62.decode (data, qname + HDRSIZE, qlen - (dlen + 1 + HDRSIZE));

              if (0 < client && client <= conns.size ())
                {
                  connection *c = conns [client - 1];
                  dns_connection *dns = c->dns;
                  dns_rcv *rcv;

                  if (dns)
                    {
                      for (vector<dns_rcv *>::iterator i = dns->rcvpq.end (); i-- != dns->rcvpq.begin (); )
                        if (SEQNO_EQ ((*i)->seqno, seqno))
                          {
                            // already seen that request: simply reply with the cached reply
                            dns_rcv *r = *i;

                            slog (L_DEBUG, "DUPLICATE %d\n", htons (r->pkt->id));

                            memcpy (pkt.at (0), r->pkt->at (0), offs  = r->pkt->len);
                            pkt.id = r->pkt->id;
                            goto duplicate_request;
                          }

                      // new packet, queue
                      rcv = new dns_rcv (seqno, data, datalen);
                      dns->receive_rep (rcv);
                    }

                  pkt [offs++] = 0xc0; pkt [offs++] = 6 * 2; // refer to name in query section

                  int rtype = dns ? dns->cfg.rrtype : RR_TYPE_A;
                  pkt [offs++] = rtype       >> 8; pkt [offs++] = rtype;       // type
                  pkt [offs++] = RR_CLASS_IN >> 8; pkt [offs++] = RR_CLASS_IN; // class
                  pkt [offs++] = 0; pkt [offs++] = 0;
                  pkt [offs++] = 0; pkt [offs++] = dns ? dns->cfg.def_ttl : 0; // TTL

                  int rdlen_offs = offs += 2;

                  int dlen = (dns ? ntohs (dns->cfg.max_size) : MAX_PKT_SIZE) - offs;
                  // bind doesn't compress well, so reduce further by one label length
                  dlen -= qlen;

                  if (dns)
                    {
                      while (dlen > 1 && !dns->snddq.empty ())
                        {
                          int txtlen = dlen <= 255 ? dlen - 1 : 255;

                          if (txtlen > dns->snddq.size ())
                            txtlen = dns->snddq.size ();

                          pkt[offs++] = txtlen;
                          memcpy (pkt.at (offs), dns->snddq.begin (), txtlen);
                          offs += txtlen;
                          dns->snddq.remove (txtlen);

                          dlen -= txtlen + 1;
                        }

                      // avoid empty TXT rdata
                      if (offs == rdlen_offs)
                        pkt[offs++] = 0;

                      slog (L_NOISE, "snddq %d", dns->snddq.size ());
                    }
                  else
                    {
                      // send RST
                      pkt [offs++] = CMD_IP_1; pkt [offs++] = CMD_IP_2; pkt [offs++] = CMD_IP_3;
                      pkt [offs++] = CMD_IP_RST;
                    }

                  int rdlen = offs - rdlen_offs;

                  pkt [rdlen_offs - 2] = rdlen >> 8;
                  pkt [rdlen_offs - 1] = rdlen;

                  if (dns)
                    {
                      // now update dns_rcv copy
                      rcv->pkt->len = offs;
                      memcpy (rcv->pkt->at (0), pkt.at (0), offs);
                    }

                  duplicate_request: ;
                }
              else
                pkt.flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_FORMERR);
            }
          else if (qtype == RR_TYPE_A
                   && qlen > dlen + 1 + cdc26.encode_len (sizeof (dns_cfg)))
            {
              dns_cfg cfg;
              cdc26.decode ((u8 *)&cfg, qname, cdc26.encode_len (sizeof (dns_cfg)));
              int client = ntohs (cfg.client);

              pkt [offs++] = 0xc0; pkt [offs++] = 6 * 2; // refer to name in query section

              pkt [offs++] = RR_TYPE_A   >> 8; pkt [offs++] = RR_TYPE_A;   // type
              pkt [offs++] = RR_CLASS_IN >> 8; pkt [offs++] = RR_CLASS_IN; // class
              pkt [offs++] = 0; pkt [offs++] = 0;
              pkt [offs++] = 0; pkt [offs++] = cfg.def_ttl; // TTL
              pkt [offs++] = 0; pkt [offs++] = 4; // rdlength

              slog (L_INFO, _("DNS tunnel: client %d tries to connect"), client);

              pkt [offs++] = CMD_IP_1; pkt [offs++] = CMD_IP_2; pkt [offs++] = CMD_IP_3;
              pkt [offs++] = CMD_IP_REJ;

              if (0 < client && client <= conns.size ())
                {
                  connection *c = conns [client - 1];

                  if (cfg.valid ())
                    {
                      pkt [offs - 1] = CMD_IP_SYN;

                      delete c->dns;
                      c->dns = new dns_connection (c);
                      c->dns->cfg = cfg;
                    }
                }
            }
        }

      pkt.len = offs;
    }
}

void
vpn::dnsv4_client (dns_packet &pkt)
{
  u16 flags = ntohs (pkt.flags);
  int offs = 6 * 2; // skip header

  pkt.qdcount = ntohs (pkt.qdcount);
  pkt.ancount = ntohs (pkt.ancount);

  // go through our request list and find the corresponding request
  for (vector<dns_snd *>::iterator i = dns_sndpq.begin ();
       i != dns_sndpq.end ();
       ++i)
    if ((*i)->pkt->id == pkt.id)
      {
        dns_connection *dns = (*i)->dns;
        connection *c = dns->c;
        int seqno = (*i)->seqno;
        u8 data[MAXSIZE], *datap = data;

        if ((*i)->retry)
          {
            dns->send_interval *= 1.001;
            if (dns->send_interval > MAX_SEND_INTERVAL)
              dns->send_interval = MAX_SEND_INTERVAL;
          }
        else
          {
#if 1
            dns->send_interval *= 0.9999;
#endif
            if (dns->send_interval < MIN_SEND_INTERVAL)
              dns->send_interval = MIN_SEND_INTERVAL;

            // the latency surely puts an upper bound on
            // the minimum send interval
            double latency = NOW - (*i)->sent;

            if (dns->send_interval > latency)
              dns->send_interval = latency;
          }

        delete *i;
        dns_sndpq.erase (i);

        if (flags & FLAG_RESPONSE && !(flags & FLAG_OP_MASK))
          {
            char qname[MAXSIZE];

            while (pkt.qdcount-- && offs < MAXSIZE - 4)
              {
                int qlen = pkt.decode_label ((char *)qname, MAXSIZE - offs, offs);
                offs += 4; // skip qtype, qclass
              }

            while (pkt.ancount-- && offs < MAXSIZE - 10 && datap)
              {
                int qlen = pkt.decode_label ((char *)qname, MAXSIZE - offs, offs);

                u16 qtype  = pkt [offs++] << 8; qtype  |= pkt [offs++];
                u16 qclass = pkt [offs++] << 8; qclass |= pkt [offs++];
                u32 ttl  = pkt [offs++] << 24;
                    ttl |= pkt [offs++] << 16;
                    ttl |= pkt [offs++] <<  8;
                    ttl |= pkt [offs++];
                u16 rdlen = pkt [offs++] << 8; rdlen |= pkt [offs++];

                if (qtype == RR_TYPE_NULL || qtype == RR_TYPE_TXT)
                  {
                    if (rdlen <= MAXSIZE - offs)
                      {
                        // decode bytes, finally

                        while (rdlen)
                          {
                            int txtlen = pkt [offs++];

                            assert (txtlen + offs < MAXSIZE - 1);

                            memcpy (datap, pkt.at (offs), txtlen);
                            datap += txtlen; offs += txtlen;

                            rdlen -= txtlen + 1;
                          }
                      }
                  }
                else if (qtype == RR_TYPE_A)
                  {
                    u8 ip [4];

                    ip [0] = pkt [offs++];
                    ip [1] = pkt [offs++];
                    ip [2] = pkt [offs++];
                    ip [3] = pkt [offs++];

                    if (ip [0] == CMD_IP_1
                        && ip [1] == CMD_IP_2
                        && ip [2] == CMD_IP_3)
                      {
                        slog (L_TRACE, _("got tunnel meta command %02x"), ip [3]);

                        if (ip [3] == CMD_IP_RST)
                          {
                            slog (L_DEBUG, _("got tunnel RST request"));

                            delete dns; c->dns = 0;

                            return;
                          }
                        else if (ip [3] == CMD_IP_SYN)
                          {
                            slog (L_DEBUG, _("got tunnel SYN reply, server likes us."));
                            dns->established = true;
                          }
                        else if (ip [3] == CMD_IP_REJ)
                          {
                            slog (L_DEBUG, _("got tunnel REJ reply, server does not like us, aborting."));
                            abort ();
                          }
                        else
                          slog (L_INFO, _("got unknown meta command %02x"), ip [3]);
                      }
                    else
                      slog (L_INFO, _("got spurious a record %d.%d.%d.%d"),
                            ip [0], ip [1], ip [2], ip [3]);

                    return;
                  }

                int client, rseqno;
                decode_header (qname, client, rseqno);

                if (client != THISNODE->id)
                  {
                    slog (L_INFO, _("got dns tunnel response with wrong clientid, ignoring"));
                    datap = 0;
                  }
                else if (rseqno != seqno)
                  {
                    slog (L_DEBUG, _("got dns tunnel response with wrong seqno, badly caching nameserver?"));
                    datap = 0;
                  }
              }
          }

        // todo: pkt now used
        if (datap)
          dns->receive_rep (new dns_rcv (seqno, data, datap - data));

        break;
      }
}

void
vpn::dnsv4_ev (io_watcher &w, short revents)
{
  if (revents & EVENT_READ)
    {
      dns_packet *pkt = new dns_packet;
      struct sockaddr_in sa;
      socklen_t sa_len = sizeof (sa);

      pkt->len = recvfrom (w.fd, pkt->at (0), MAXSIZE, 0, (sockaddr *)&sa, &sa_len);

      if (pkt->len > 0)
        {
          if (THISNODE->dns_port)
            {
              dnsv4_server (*pkt);
              sendto (w.fd, pkt->at (0), pkt->len, 0, (sockaddr *)&sa, sa_len);
            }
          else
            dnsv4_client (*pkt);

          delete pkt;
        }
    }
}

bool
connection::send_dnsv4_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
  if (!dns)
    dns = new dns_connection (this);
  
  if (!dns->snddq.put (pkt))
    return false;

  dns->tw.trigger ();

  return true;
}

void
connection::dnsv4_reset_connection ()
{
  //delete dns; dns = 0; //TODO
}

#define NEXT(w) do { if (next > (w)) next = w; } while (0)

void
dns_connection::time_cb (time_watcher &w)
{
  // servers have to be polled
  if (THISNODE->dns_port)
    return;

  // check for timeouts and (re)transmit
  tstamp next = NOW + poll_interval;
  dns_snd *send = 0;
  
  for (vector<dns_snd *>::iterator i = vpn->dns_sndpq.begin ();
       i != vpn->dns_sndpq.end ();
       ++i)
    {
      dns_snd *r = *i;

      if (r->timeout <= NOW)
        {
          if (!send)
            {
              send = r;

              r->retry++;
              r->timeout = NOW + r->retry;
            }
        }
      else
        NEXT (r->timeout);
    }

  if (last_sent + send_interval <= NOW)
    {
      if (!send)
        {
          // generate a new packet, if wise

          if (!established)
            {
              if (vpn->dns_sndpq.empty ())
                {
                  send = new dns_snd (this);

                  cfg.reset (THISNODE->id);
                  send->gen_syn_req (cfg);
                }
            }
          else if (vpn->dns_sndpq.size () < MAX_OUTSTANDING)
            {
              send = new dns_snd (this);
              send->gen_stream_req (sndseq, snddq);

              sndseq = (sndseq + 1) & SEQNO_MASK;
            }

          if (send)
            vpn->dns_sndpq.push_back (send);
        }

      if (send)
        {
          last_sent = NOW;
          sendto (vpn->dnsv4_fd,
                  send->pkt->at (0), send->pkt->len, 0,
                  vpn->dns_forwarder.sav4 (), vpn->dns_forwarder.salenv4 ());
        }
    }
  else
    NEXT (last_sent + send_interval);

  slog (L_NOISE, "pi %f si %f N %f (%d:%d)",
        poll_interval, send_interval, next - NOW,
        vpn->dns_sndpq.size (), snddq.size ());

  // TODO: no idea when this happens, but when next < NOW, we have a problem
  if (next < NOW + 0.0001)
    next = NOW + 0.1;

  w.start (next);
}

#endif

