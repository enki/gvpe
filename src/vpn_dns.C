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

#define MIN_RETRY 1.
#define MAX_RETRY 60.

#define MAX_OUTSTANDING 400 // max. outstanding requests
#define MAX_WINDOW      1000 // max. for MAX_OUTSTANDING
#define MAX_RATE        10000 // requests/s
#define MAX_BACKLOG     (10*1024) // size of protocol backlog, must be > MAXSIZE

#define MAX_DOMAIN_SIZE 220 // 255 is legal limit, but bind doesn't compress well
// 240 leaves about 4 bytes of server reply data
// every two request byte sless give room for one reply byte

// seqno has 12 bits (3 bytes a 4 bits in the header)
#define SEQNO_MASK 0x7fff
#define SEQNO_EQ(a,b) ( 0 == ( ((a) ^ (b)) & SEQNO_MASK) )

#define MAX_LBL_SIZE 63
#define MAX_PKT_SIZE 512

#define RR_TYPE_TXT 16
#define RR_TYPE_ANY 255
#define RR_CLASS_IN 1

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
  if (!len)
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
  if (!len)
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

// the following sequence has been crafted to
// a) look somewhat random
// b) the even (and odd) indices never share the same character as upper/lowercase
// the "_" is not valid but widely accepted (all octets should be supported, but let's be conservative)
// the other sequences are obviously derived
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

  printf ("DEC %02x %02x %02x %02x\n", hdr[0], hdr[1], hdr[2], hdr[3]);

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

  memcpy (data + fill, &((*pkt)[0]), pkt->len); fill += pkt->len;

  return true;
}

vpn_packet *byte_stream::get ()
{
  int len = (data [0] << 8) | data [1];

  if (len > MAXSIZE && fill >= 2)
    abort (); // TODO handle this gracefully, connection reset

  if (fill < len + 2)
    return 0;

  vpn_packet *pkt = new vpn_packet;

  pkt->len = len;
  memcpy (&((*pkt)[0]), data + 2, len);
  remove (len + 2);

  return pkt;
}

/////////////////////////////////////////////////////////////////////////////

#define FLAG_QUERY    ( 0 << 15)
#define FLAG_RESPONSE ( 1 << 15)
#define FLAG_OP_MASK  (15 << 14)
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

struct dns_req
{
  dns_packet *pkt;
  tstamp next;
  int retry;
  connection *conn;
  int seqno;

  dns_req (connection *c);
  void gen_stream_req (int seqno, byte_stream *stream);
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

dns_req::dns_req (connection *c)
: conn (c)
{
  next = 0;
  retry = 0;

  pkt = new dns_packet;

  pkt->id = next_id ();
}

void dns_req::gen_stream_req (int seqno, byte_stream *stream)
{
  this->seqno = seqno;

  pkt->flags = htons (DEFAULT_CLIENT_FLAGS);
  pkt->qdcount = htons (1);

  int offs = 6*2;
  int dlen = MAX_DOMAIN_SIZE - (strlen (THISNODE->domain) + 2);
  // MAX_DOMAIN_SIZE is technically 255, but bind doesn't compress responses well,
  // so we need to have space for 2*MAX_DOMAIN_SIZE + header + extra

  char enc[256], *encp = enc;
  encode_header (enc, THISNODE->id, seqno);

  int datalen = cdc62.decode_len (dlen - (dlen + MAX_LBL_SIZE - 1) / MAX_LBL_SIZE - HDRSIZE);

  if (datalen > stream->size ())
    datalen = stream->size ();

  int enclen = cdc62.encode (enc + HDRSIZE, stream->begin (), datalen) + HDRSIZE;

  printf ("cdc62.encode %d->%d:%02x %02x %02x %02x\n", datalen, enclen,
      stream->begin ()[0],
      stream->begin ()[1],
      stream->begin ()[2],
      stream->begin ()[3]);
  
  stream->remove (datalen);

  while (enclen)
    {
      int lbllen = enclen < MAX_LBL_SIZE ? enclen : MAX_LBL_SIZE;

      (*pkt)[offs++] = lbllen;
      memcpy (pkt->at (offs), encp, lbllen);

      offs += lbllen;
      encp += lbllen;

      enclen -= lbllen;
    }

  const char *suffix = THISNODE->domain;

  // add tunnel domain
  for (;;)
    {
      const char *end = strchr (suffix, '.');

      if (!end)
        end = suffix + strlen (suffix);

      int len = end - suffix;

      (*pkt)[offs++] = len;
      memcpy (&((*pkt)[offs]), suffix, len);
      offs += len;

      if (!*end)
        break;

      suffix = end + 1;
    }

  (*pkt)[offs++] = 0;
  (*pkt)[offs++] = RR_TYPE_ANY >> 8; (*pkt)[offs++] = RR_TYPE_ANY;
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

struct dns_cfg
{
  u8 id1, id2, id3;
  u8 def_ttl;
  u8 unused1;
  u16 max_size;
  u8 flags1, flags2;
};

void connection::dnsv4_receive_rep (struct dns_rcv *r)
{
  dns_rcvpq.push_back (r);

  printf ("%d got inketc %d (%02x %02x %02x %02x)\n", THISNODE->id, r->seqno
      ,r->data[0]
      ,r->data[1]
      ,r->data[2]
      ,r->data[3]
      );
  redo:

  // find next packet
  for (vector<dns_rcv *>::iterator i = dns_rcvpq.end (); i-- != dns_rcvpq.begin (); )
    if (SEQNO_EQ (dns_rcvseq, (*i)->seqno))
      {
        // enter the packet into our input stream
        r = *i;

        printf ("%d checking for older packet %d\n", THISNODE->id, dns_rcvseq);
        // remove the oldest packet, look forward, as it's oldest first
        for (vector<dns_rcv *>::iterator j = dns_rcvpq.begin (); j != dns_rcvpq.end (); ++j)
          if (SEQNO_EQ ((*j)->seqno, dns_rcvseq - MAX_WINDOW))
            {
              printf ("%d removing %d\n", THISNODE->id, (*j)->seqno);
              delete *j;
              dns_rcvpq.erase (j);
              break;
            }

        dns_rcvseq = (dns_rcvseq + 1) & SEQNO_MASK;

        if (!dns_snddq && !dns_rcvdq)
          {
            dns_rcvdq = new byte_stream (MAX_BACKLOG * 2);
            dns_snddq = new byte_stream (MAX_BACKLOG);

            dns_si.set (::conf.dns_forw_host, ::conf.dns_forw_port, PROT_DNSv4);
          }

        if (!dns_rcvdq->put (r->data, r->datalen))
          abort (); // MUST never overflow, can be caused by data corruption, TODO

        while (vpn_packet *pkt = dns_rcvdq->get ())
          {
            sockinfo si;
            si.host = 0; si.port = 0; si.prot = PROT_DNSv4;

            vpn->recv_vpn_packet (pkt, si);
          }

        // check for further packets
        goto redo;
      }
}

dns_packet *
vpn::dnsv4_server (dns_packet *pkt)
{
  u16 flags = ntohs (pkt->flags);

  //memcpy (&((*rep)[0]), &((*pkt)[0]), pkt->len);
  int offs = 6 * 2; // skip header

  pkt->flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_FORMERR);

  if (!(flags & (FLAG_RESPONSE | FLAG_OP_MASK | FLAG_TC))
      && pkt->qdcount == htons (1))
    {
      char qname[MAXSIZE];
      int qlen = pkt->decode_label ((char *)qname, MAXSIZE - offs, offs);

      u16 qtype  = (*pkt) [offs++] << 8; qtype  |= (*pkt) [offs++];
      u16 qclass = (*pkt) [offs++] << 8; qclass |= (*pkt) [offs++];

      pkt->qdcount = htons (1);
      pkt->ancount = 0;
      pkt->nscount = 0; // should be self, as other nameservers reply like this
      pkt->arcount = 0; // a record for self, as other nameservers reply like this

      pkt->flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_NXDOMAIN);

      int dlen = strlen (THISNODE->domain);

      if (qclass == RR_CLASS_IN
          && (qtype == RR_TYPE_ANY || qtype == RR_TYPE_TXT)
          && qlen > dlen + 1 + HDRSIZE
          && !memcmp (qname + qlen - dlen - 1, THISNODE->domain, dlen))
        {
          // correct class, domain: parse
          int client, seqno;
          decode_header (qname, client, seqno);

          u8 data[MAXSIZE];
          int datalen = cdc62.decode (data, qname + HDRSIZE, qlen - (dlen + 1 + HDRSIZE));

          printf ("cdc62.decode %d(%d): %02x %02x %02x %02x\n",
              qlen - (dlen + 1 + HDRSIZE), datalen
              ,data[0]
              ,data[1]
              ,data[2]
              ,data[3]);

          printf ("SRV got %d <%.*s>\n", seqno, qlen, qname + HDRSIZE);//D
          printf ("SRV got %d <%.*s>\n", seqno, qlen - (dlen + 1 + HDRSIZE), qname + HDRSIZE);//D

          if (0 < client && client <= conns.size ())
            {
              connection *c = conns [client - 1];

              for (vector<dns_rcv *>::iterator i = c->dns_rcvpq.end (); i-- != c->dns_rcvpq.begin (); )
                if (SEQNO_EQ ((*i)->seqno, seqno))
                  {
                    // already seen that request: simply reply with the cached reply
                    dns_rcv *r = *i;

                    printf ("DUPLICATE %d\n", htons (r->pkt->id));//D

                    memcpy (pkt->at (0), r->pkt->at (0), offs  = r->pkt->len);
                    pkt->id = r->pkt->id;
                    goto duplicate_request;
                  }

              // new packet, queue
              dns_rcv *rcv = new dns_rcv (seqno, data, datalen);
              c->dnsv4_receive_rep (rcv);

              // now generate reply
              pkt->ancount = htons (1); // one answer RR
              pkt->flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_OK);

              (*pkt) [offs++] = 0xc0;
              (*pkt) [offs++] = 6 * 2; // same as in query section

              (*pkt) [offs++] = RR_TYPE_TXT >> 8; (*pkt) [offs++] = RR_TYPE_TXT;
              (*pkt) [offs++] = RR_CLASS_IN >> 8; (*pkt) [offs++] = RR_CLASS_IN;

              (*pkt) [offs++] = 0; (*pkt) [offs++] = 0;
              (*pkt) [offs++] = 0; (*pkt) [offs++] = 0; // TTL

              int dlen = MAX_PKT_SIZE - offs - 2;

              // bind doesn't compress well, so reduce further by one label length
              dlen -= qlen;

              int rdlen_offs = offs += 2;

              while (c->dns_snddq
                     && !c->dns_snddq->empty ()
                     && dlen > 1)
                {
                  int txtlen = dlen <= 255 ? dlen - 1 : 255;

                  if (txtlen > c->dns_snddq->size ())
                    txtlen = c->dns_snddq->size ();

                  (*pkt)[offs++] = txtlen;
                  memcpy (pkt->at (offs), c->dns_snddq->begin (), txtlen);
                  offs += txtlen;
                  c->dns_snddq->remove (txtlen);

                  dlen -= txtlen + 1;
                }

              // avoid empty TXT rdata
              if (offs == rdlen_offs)
                (*pkt)[offs++] = 0;

              int rdlen = offs - rdlen_offs;

              (*pkt) [rdlen_offs - 2] = rdlen >> 8;
              (*pkt) [rdlen_offs - 1] = rdlen;

              // now update dns_rcv copy
              rcv->pkt->len = offs;
              memcpy (rcv->pkt->at (0), pkt->at (0), offs);

              duplicate_request: ;
            }
          else
            pkt->flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_FORMERR);
        }

      pkt->len = offs;
    }

  return pkt;
}

void
vpn::dnsv4_client (dns_packet *pkt)
{
  u16 flags = ntohs (pkt->flags);
  int offs = 6 * 2; // skip header

  pkt->qdcount = ntohs (pkt->qdcount);
  pkt->ancount = ntohs (pkt->ancount);

  // go through our request list and find the corresponding request
  for (vector<dns_req *>::iterator i = dns_sndpq.begin ();
       i != dns_sndpq.end ();
       ++i)
    if ((*i)->pkt->id == pkt->id)
      {
        connection *c = (*i)->conn;
        int seqno = (*i)->seqno;
        u8 data[MAXSIZE], *datap = data;

        delete *i;
        dns_sndpq.erase (i);

        if (flags & (FLAG_RESPONSE | FLAG_OP_MASK | FLAG_TC))
          {
            char qname[MAXSIZE];

            while (pkt->qdcount-- && offs < MAXSIZE - 4)
              {
                int qlen = pkt->decode_label ((char *)qname, MAXSIZE - offs, offs);
                offs += 4; // skip qtype, qclass
              }

            while (pkt->ancount-- && offs < MAXSIZE - 10)
              {
               int qlen = //D
                pkt->decode_label ((char *)qname, MAXSIZE - offs, offs);

                printf ("got reply to <%.*s>\n", qlen, qname);//D

                u16 qtype  = (*pkt) [offs++] << 8; qtype  |= (*pkt) [offs++];
                u16 qclass = (*pkt) [offs++] << 8; qclass |= (*pkt) [offs++];
                u32 ttl  = (*pkt) [offs++] << 24;
                    ttl |= (*pkt) [offs++] << 16;
                    ttl |= (*pkt) [offs++] <<  8;
                    ttl |= (*pkt) [offs++];

                u16 rdlen = (*pkt) [offs++] << 8; rdlen |= (*pkt) [offs++];

                if (rdlen <= MAXSIZE - offs)
                  {
                    // decode bytes, finally

                    while (rdlen)
                      {
                        int txtlen = (*pkt) [offs++];

                        assert (txtlen + offs < MAXSIZE - 1);

                        memcpy (datap, pkt->at (offs), txtlen);
                        datap += txtlen; offs += txtlen;

                        rdlen -= txtlen + 1;
                      }

                  }

              }
          }

        // todo: pkt now used
        c->dnsv4_receive_rep (new dns_rcv (seqno, data, datap - data));

        break;
      }

  delete pkt;
}

void
vpn::dnsv4_ev (io_watcher &w, short revents)
{
  if (revents & EVENT_READ)
    {
      dns_packet *pkt = new dns_packet;
      struct sockaddr_in sa;
      socklen_t sa_len = sizeof (sa);

      pkt->len = recvfrom (w.fd, &((*pkt)[0]), MAXSIZE, 0, (sockaddr *)&sa, &sa_len);

      if (pkt->len > 0)
        {
          if (pkt->flags & htons (FLAG_TC))
            {
              slog (L_WARN, _("DNS request/response truncated, check protocol settings."));
              //TODO connection reset
            }

          if (THISNODE->dns_port)
            {
              pkt = dnsv4_server (pkt);
              sendto (w.fd, &((*pkt)[0]), pkt->len, 0, (sockaddr *)&sa, sa_len);
            }
          else
            dnsv4_client (pkt);
        }
    }
}

bool
connection::send_dnsv4_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
  // never initialized
  if (!dns_snddq && !dns_rcvdq)
    {
      dns_rcvdq = new byte_stream (MAX_BACKLOG * 2);
      dns_snddq = new byte_stream (MAX_BACKLOG);

      //dns_rcvseq = dns_sndseq = 0;

      dns_si.set (::conf.dns_forw_host, ::conf.dns_forw_port, PROT_DNSv4);
    }
  
  if (!dns_snddq->put (pkt))
    return false;

  // start timer if neccessary
  if (!THISNODE->dns_port && !dnsv4_tw.active)
    dnsv4_cb (dnsv4_tw);

  return true;
}

void
connection::dnsv4_cb (time_watcher &w)
{
  // check for timeouts and (re)transmit
  tstamp next = NOW + 60;
  dns_req *send = 0;
  
  for (vector<dns_req *>::iterator i = vpn->dns_sndpq.begin ();
       i != vpn->dns_sndpq.end ();
       ++i)
    {
      dns_req *r = *i;

      if (r->next <= NOW)
        {
          if (!send)
            {
              send = r;

              if (r->retry)//D
                printf ("req %d:%d, retry %d\n", r->seqno, r->pkt->id, r->retry);
              r->retry++;
              r->next = NOW + r->retry;
            }
        }

      if (r->next < next)
        next = r->next;
    }

  if (!send
      && vpn->dns_sndpq.size () < MAX_OUTSTANDING)
    {
      send = new dns_req (this);
      send->gen_stream_req (dns_sndseq, dns_snddq);
      vpn->dns_sndpq.push_back (send);

      dns_sndseq = (dns_sndseq + 1) & SEQNO_MASK;
    }

  tstamp min_next = NOW + (1. / (tstamp)MAX_RATE);

  if (send)
    {
      dns_packet *pkt = send->pkt;

      next = min_next;

      sendto (vpn->dnsv4_fd, &((*pkt)[0]), pkt->len, 0, dns_si.sav4 (), dns_si.salenv4 ());
    }
  else if (next < min_next)
    next = min_next;

  w.start (next);
}

#endif

