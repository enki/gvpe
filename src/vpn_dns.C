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

#if ENABLE_HTTP_PROXY
# include "conf.h"
#endif

#define MIN_RETRY 1.
#define MAX_RETRY 60.

#define SERVER conf.dns_port

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
  static void encode (char *dst, u8 *src, int len);
  static void decode (u8 *dst, char *src, int len);

  dns64 ();
} dns64;

const char dns64::encode_chars[64 + 1] = "0123456789-abcdefghijklmnopqrstuvwxyz_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
s8 dns64::decode_chars[256];

dns64::dns64 ()
{
  for (int i = 0; i < 64; i++)
    decode_chars [encode_chars [i]] = i + 1;
}

void dns64::encode (char *dst, u8 *src, int len)
{
  // slow, but easy to debug
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
}

void dns64::decode (u8 *dst, char *src, int len)
{
  // slow, but easy to debug
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
}

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

struct dns_cfg
{
  u8 id1, id2, id3;
  u8 def_ttl;
  u8 unused1;
  u16 max_size;
  u8 flags1, flags2;
};

// reply to client-poll
void dnsv4_poll (dns_packet *pkt, int &offs)
{
  int dlen = MAX_PKT_SIZE - offs - 2;

  (*pkt) [offs++] = 0;
  (*pkt) [offs++] = 5;
  memcpy (&((*pkt)[offs]), "\01H\02\xff\x00", 5);
  offs += 5;

  pkt->ancount = htons (1);
  pkt->flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_OK);

  printf ("we have room for %d bytes\n", dlen);
}

void
vpn::dnsv4_ev (io_watcher &w, short revents)
{
  if (revents & EVENT_READ)
    {
      dns_packet *pkt = new dns_packet;
      struct sockaddr_in sa;
      socklen_t sa_len = sizeof (sa);

      int len = recvfrom (w.fd, &((*pkt)[0]), MAXSIZE, 0, (sockaddr *)&sa, &sa_len);
      pkt->len = len;

      u16 flags = ntohs (pkt->flags);

      if (THISNODE->dns_port)
        {
          // server
          pkt->flags = htons (DEFAULT_SERVER_FLAGS | FLAG_RCODE_FORMERR);

          int offs = 6 * 2; // skip header

          if (!(flags & (FLAG_RESPONSE | FLAG_OP_MASK | FLAG_TC))
              && pkt->qdcount == htons (1))
            {
              char qname[MAXSIZE];
              int qlen = pkt->decode_label ((char *)qname, MAXSIZE, offs);

              printf ("rcvd packet len %d, id%04x flags%04x q%04x a%04x n%04x a%04x <%s>\n", len,
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
                  // correct class, now generate reply
                  pkt->ancount = htons (1); // one answer RR

                  (*pkt) [offs++] = 0xc0;
                  (*pkt) [offs++] = 6 * 2; // same as in query section

                  (*pkt) [offs++] = RR_TYPE_TXT >> 8; (*pkt) [offs++] = RR_TYPE_TXT;
                  (*pkt) [offs++] = RR_CLASS_IN >> 8; (*pkt) [offs++] = RR_CLASS_IN;

                  (*pkt) [offs++] = 0; (*pkt) [offs++] = 0;
                  (*pkt) [offs++] = 0; (*pkt) [offs++] = 0; // TTL

                  dnsv4_poll (pkt, offs);
                  printf ("correct class\n");
                }
            }

          sendto (w.fd, &((*pkt)[0]), offs, 0, (sockaddr *)&sa, sa_len);
        }
      else
        {
          // client
        }
    }
}

bool
vpn::send_dnsv4_packet (vpn_packet *pkt, const sockinfo &si, int tos)
{
  //return i->send_packet (pkt, tos);
}

#endif

