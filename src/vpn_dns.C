/*
    vpn_dns.C -- handle the dns tunnel part of the protocol.
    Copyright (C) 2003-2004 Marc Lehmann <pcg@goof.com>
 
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

#include "netcompat.h"

#include "vpn.h"

#define MIN_RETRY 1.
#define MAX_RETRY 60.

#define MAX_OUTSTANDING 40 // max. outstanding requests
#define MAX_WINDOW      100 // max. for MAX_OUTSTANDING
#define MAX_RATE        1000 // requests/s
#define MAX_BACKLOG     (10*1024) // size of protocol backlog, must be > MAXSIZE

#define MAX_DOMAIN_SIZE 220 // 255 is legal limit, but bind doesn't compress well
// 240 leaves about 4 bytes of server reply data
// every two request byte sless give room for one reply byte

#define SEQNO_MASK 0xffff

/*

protocol, in shorthand :)

client -> server <req>	ANY?
server -> client <req>  TXT <rep>

<req> is dns64-encoded <client-id:12><recv-seqno:10>[<send-seqno:10><data>]
<rep> is dns64-encoded <0:12><recv-seqno:10>[<send-seqno:10><data>]

if <client-id> is zero, the connection will be configured:

<0:12><0:4>client-id:12><default-ttl:8><max-size:16><flags:16>

*/

#define MAX_LBL_SIZE 63
#define MAX_PKT_SIZE 512

#define RR_TYPE_TXT 16
#define RR_TYPE_ANY 255
#define RR_CLASS_IN 1

// the "_" is not valid but widely accepted (all octets should be supported, but let's be conservative)
struct dns64
{
  static const char encode_chars[64 + 1];
  static s8 decode_chars[256];

  static int encode_len (int bytes) { return (bytes * 8 + 5) / 6; }
  static int decode_len (int bytes) { return (bytes * 6) / 8; }
  static int encode (char *dst, u8 *src, int len);
  static int decode (u8 *dst, char *src, int len);

  dns64 ();
} dns64;

const char dns64::encode_chars[64 + 1] = "_4B9dLphHzrqQmGjkTbJt5svlZX8xSaReEYfwKgF1DP2W6NyVOU70IouACcMn3i-";
s8 dns64::decode_chars[256];

dns64::dns64 ()
{
  for (int i = 0; i < 64; i++)
    decode_chars [encode_chars [i]] = i + 1;
}

int dns64::encode (char *dst, u8 *src, int len)
{
  // slow, but easy to debug
  char *beg = dst;
  unsigned int accum, bits = 0;

  while (len--)
    {
      accum <<= 8;
      accum  |= *src++;
      bits   += 8;

      while (bits >= 6)
        {
          *dst++ = encode_chars [(accum >> (bits - 6)) & 63];
          bits  -= 6;
        }
    }

  if (bits)
    *dst++ = encode_chars [(accum << (6 - bits)) & 63];

  return dst - beg;
}

int dns64::decode (u8 *dst, char *src, int len)
{
  // slow, but easy to debug
  u8 *beg = dst;
  unsigned int accum, bits = 0;

  while (len--)
    {
      s8 chr = decode_chars [(u8)*src++];

      if (!chr)
        continue;

      accum <<= 6;
      accum  |= chr - 1;
      bits   += 6;

      while (bits >= 8)
        {
          *dst++ = accum >> (bits - 8);
          bits  -= 8;
        }
    }

  return dst - beg;
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

  printf ("get len %d, fill %d\n", len, fill);//D

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
  int dlen = MAX_DOMAIN_SIZE - strlen (THISNODE->domain) - 2;
  // MAX_DOMAIN_SIZE is technically 255, but bind doesn't compress responses well,
  // so we need to have space for 2*MAX_DOMAIN_SIZE + header + extra

  u8 data[256]; //TODO

  data[0] = THISNODE->id; //TODO
  data[1] = seqno >> 8; //TODO
  data[2] = seqno; //TODO

  int datalen = dns64::decode_len (dlen - (dlen + MAX_LBL_SIZE - 1) / MAX_LBL_SIZE) - 3;

  if (datalen > stream->size ())
    datalen = stream->size ();

  char enc[256], *encp = enc;
  
  memcpy (data + 3, stream->begin (), datalen);
  int enclen = dns64::encode (enc, data, datalen + 3);
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

  dns_rcv (int seqno, dns_packet *req, u8 *data, int datalen);
  ~dns_rcv ();
};

dns_rcv::dns_rcv (int seqno, dns_packet *req, u8 *data, int datalen)
: seqno (seqno), pkt (new dns_packet), datalen (datalen)
{
  memcpy (this->data, data, datalen);
  pkt->len = req->len;
  memcpy (pkt->at (0), req->at (0), req->len);
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

  redo:

  for (vector<dns_rcv *>::iterator i = dns_rcvpq.begin ();
       i != dns_rcvpq.end ();
       ++i)
    if (dns_rcvseq == (*i)->seqno)
      {
        dns_rcv *r = *i;

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
      }
    else if ((u32)dns_rcvseq - MAX_WINDOW - (u32)(*i)->seqno < MAX_WINDOW * 2)
      {
        dns_rcvpq.erase (i);
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
          && qlen > dlen + 1
          && !memcmp (qname + qlen - dlen - 1, THISNODE->domain, dlen))
        {
          // correct class, domain: parse
          u8 data[MAXSIZE];
          int datalen = dns64::decode (data, qname, qlen - dlen - 1);

          int client = data[0];
          int seqno  = ((data[1] << 8) | data[2]) & SEQNO_MASK;

          if (0 < client && client <= conns.size ())
            {
              connection *c = conns [client - 1];

              for (vector<dns_rcv *>::iterator i = c->dns_rcvpq.begin ();
                   i != c->dns_rcvpq.end ();
                   ++i)
                if ((*i)->seqno == seqno)
                  {
                    // already seen that request, just reply with the original reply
                    dns_rcv *r = *i;

                    offs = r->pkt->len;
                    memcpy (pkt->at (0), r->pkt->at (0), offs);
                    goto duplicate_request;
                  }

              // new packet, queue
              c->dnsv4_receive_rep (new dns_rcv (seqno, pkt, data + 3, datalen - 3));

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

              duplicate_request: ;
            }
          else
            pkt->flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_FORMERR);
        }
    }
  else
    offs = pkt->len;

  pkt->len = offs;
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
                pkt->decode_label ((char *)qname, MAXSIZE - offs, offs);

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

        if (datap != data)
          printf ("%02x %02x %02x %02x\n",
              data[0],
              data[1],
              data[2],
              data[3]);

        printf ("recv %d,%d\n", pkt->id, seqno, datap - data);//D
        c->dnsv4_receive_rep (new dns_rcv (seqno, pkt, data, datap - data));

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
                printf ("req %d, retry %d\n", r->pkt->id, r->retry);
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

