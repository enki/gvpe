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

#define MAX_OUTSTANDING 10 // max. outstanding requests
#define MAX_WINDOW      100 // max. for MAX_OUTSTANDING
#define MAX_RATE        1 // requests/s
#define MAX_BACKLOG     (10*1024) // size of protocol backlog

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

const char dns64::encode_chars[64 + 1] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-";
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
        break;

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

  if (fill < len + 2)
    return 0;

  vpn_packet *pkt = new vpn_packet;
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
#define FLAG_RCODE_MASK     (15 << 0)
#define FLAG_RCODE_OK       ( 0 << 0)
#define FLAG_RCODE_FORMERR  ( 1 << 0)
#define FLAG_RCODE_SERVFAIL ( 2 << 0)
#define FLAG_RCODE_NXDOMAIN ( 3 << 0)
#define FLAG_RCODE_REFUSED  ( 5 << 0)

#define DEFAULT_CLIENT_FLAGS (FLAG_QUERY | FLAG_OP_QUERY | FLAG_RD)
#define DEFAULT_SERVER_FLAGS (FLAG_RESPONSE | FLAG_OP_QUERY | FLAG_AA | FLAG_RD)

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

  dns_req (connection *c, int seqno, byte_stream *stream);
};

struct dns_rep
{
};

static u16 dns_id; // TODO: should be per-vpn

dns_req::dns_req (connection *c, int seqno, byte_stream *stream)
: conn (c)
{
  next = 0;
  retry = 0;

  pkt = new dns_packet;

  pkt->id = dns_id++;
  pkt->flags = DEFAULT_CLIENT_FLAGS;
  pkt->qdcount = htons (1);
  pkt->ancount = 0;
  pkt->nscount = 0;
  pkt->arcount = 0;

  int offs = 6*2;
  int dlen = 255 - strlen (THISNODE->domain) - 1; // here we always have room for the max. label length

  u8 lbl[64]; //D
  char enc[65];
  int lbllen = 3;
  lbl[0] = c->conf->id; //D
  lbl[1] = seqno >> 8; //D
  lbl[2] = seqno; //D

  while (dlen > 0)
    {
      int sndlen = dlen;

      if (sndlen + lbllen > dns64::decode_len (MAX_LBL_SIZE))
        sndlen = dns64::decode_len (MAX_LBL_SIZE) - lbllen;

      if (sndlen > stream->size ())
        sndlen = stream->size ();

      if (sndlen + lbllen == 0)
        break;

      memcpy (lbl + lbllen, stream->begin (), sndlen);
      stream->remove (sndlen);
      lbllen += sndlen;

      dns64::encode (enc, lbl, lbllen);

      int elen = dns64::encode_len (lbllen);
      (*pkt)[offs++] = elen;
      memcpy (&((*pkt)[offs]), enc, elen);
      offs += elen;
      dlen -= elen + 1;

      lbllen = 0;
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

  c->vpn->dns_sndpq.push_back (this);
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

      printf ("rcvd packet len %d, id%04x flags%04x q%04x a%04x n%04x a%04x <%s>\n", pkt->len,
          pkt->id, flags, pkt->qdcount, pkt->ancount, pkt->nscount, pkt->arcount, qname);//D

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
          // correct class, domain, parse
          u8 data[MAXSIZE];
          int datalen = dns64::decode (data, qname, qlen - dlen - 1);

          for (int i = 0; i < datalen; i++)
            printf ("%02x ", data[i]);
          printf ("\n");

          


#if 0
          // now generate reply
          rep->ancount = htons (1); // one answer RR
          rep->flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_OK);

          (*rep) [offs++] = 0xc0;
          (*rep) [offs++] = 6 * 2; // same as in query section

          (*rep) [offs++] = RR_TYPE_TXT >> 8; (*rep) [offs++] = RR_TYPE_TXT;
          (*rep) [offs++] = RR_CLASS_IN >> 8; (*rep) [offs++] = RR_CLASS_IN;

          (*rep) [offs++] = 0; (*rep) [offs++] = 0;
          (*rep) [offs++] = 0; (*rep) [offs++] = 0; // TTL

          int dlen = MAX_PKT_SIZE - offs - 2;

          printf ("we have room for %d bytes\n", dlen);

          int rdlen_offs = offs += 2;

          u8 txt[255];
          txt[0] = 0;
          txt[1] = 0;

          int txtlen = 2;

          while (dlen > 1)
            {
              int sndlen = --dlen;

              if (sndlen + txtlen > 255)
                sndlen = 255 - txtlen;

              sndlen = 0;

              (*rep)[offs++] = sndlen + txtlen;
              memcpy (&((*rep)[offs]), txt, txtlen);
              offs += txtlen;

              //if (sndlen + txtlen > dns_snddq.
            }

          int rdlen = offs - rdlen_offs;

          (*rep) [rdlen_offs - 2] = rdlen >> 8;
          (*rep) [rdlen_offs - 1] = rdlen;
#endif
        }
    }

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

  for (vector<dns_req *>::iterator i = dns_sndpq.begin ();
       i != dns_sndpq.end ();
       ++i)
    if ((*i)->pkt->id == pkt->id)
      {
        connection *c = (*i)->conn;
        printf ("GOT RESPONSE id %x %p\n", pkt->id, c);//D
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

                printf ("REPLY %d:%d TTL %d RD %d\n", qtype, qclass, ttl, rdlen);

                offs += rdlen;

                if (MAXSIZE - offs < rdlen)
                  {
                    // decode bytes, finally
                  }
              }
          }

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

      pkt->len = recvfrom (w.fd, &((*pkt)[0]), MAXSIZE, 0, (sockaddr *)&sa, &sa_len);

      if (pkt->len > 0)
        if (THISNODE->dns_port)
          {
            pkt = dnsv4_server (pkt);
            sendto (w.fd, &((*pkt)[0]), pkt->len, 0, (sockaddr *)&sa, sa_len);
          }
        else
          dnsv4_client (pkt);
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

      dns_rcvseq = dns_sndseq = 0;

      dns_si.set (::conf.dns_forw_host, ::conf.dns_forw_port, PROT_DNSv4);
    }
  
  if (!dns_snddq->put (pkt))
    return false;

  // start timer if neccessary
  if (!dnsv4_tw.active)
    dnsv4_cb (dnsv4_tw);

  return true;
}

void
connection::dnsv4_cb (time_watcher &w)
{
  // check for timeouts and (re)transmit
  tstamp next = NOW + 60;
  dns_req *send = 0;
  
  slog (L_NOISE, _("dnsv4, %d packets in send queue\n"), vpn->dns_sndpq.size ());

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

              slog (L_NOISE, _("dnsv4, send req %d\n"), r->pkt->id);
              r->retry++;
              r->next = NOW + r->retry;
            }
        }

      if (r->next < next)
        next = r->next;
    }

  if (!send
      && vpn->dns_sndpq.size () < MAX_OUTSTANDING)
    send = new dns_req (this, dns_sndseq++, dns_snddq);

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

