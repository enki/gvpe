/*
    conf.h -- configuration database
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

#ifndef GVPE_CONF_H__
#define GVPE_CONF_H__

#include <vector>

#include <openssl/rsa.h>

#include "slog.h"
#include "global.h"

#define DEFAULT_REKEY	       		3600
#define DEFAULT_KEEPALIVE      		60	// one keepalive/minute (it's just 8 bytes...)
#define DEFAULT_UDPPORT	       		655	// same as tinc, conflicts would be rare
#define DEFAULT_MTU	       		1500	// let's ether-net
#define DEFAULT_MAX_RETRY      		3600	// retry at least this often
 
#define DEFAULT_DNS_TIMEOUT_FACTOR	8.F	// initial retry timeout multiple
#define DEFAULT_DNS_SEND_INTERVAL	.01F	// minimum send interval
#define DEFAULT_DNS_OVERLAP_FACTOR	.5F	// RTT * LATENCY_FACTOR == sending rate
#define DEFAULT_DNS_MAX_OUTSTANDING	100	// max. number of outstanding requests

enum {
  PROT_UDPv4  = 0x01, // udp over ipv4
  PROT_IPv4   = 0x02, // generic ip protocol
  PROT_TCPv4  = 0x04, // tcp over ipv4 (server)
  PROT_ICMPv4 = 0x08, // icmp over ipv4
  PROT_DNSv4  = 0x10, // dns tunnel ipv4 (server)
};

#define PROT_RELIABLE (PROT_TCPv4 | PROT_DNSv4)
#define PROT_SLOW     PROT_DNSv4

// select the "best" protocol of the available ones
u8 best_protocol (u8 protset);
const char *strprotocol (u8 protocol);

struct conf_node {
  int id;         // the id of this node, a 12-bit-number

  RSA *rsa_key;   // his public key
  char *nodename; // nodename, an internal nickname.
  char *hostname; // hostname, if known, or NULL.
  char *if_up_data;
#if ENABLE_DNS
  char *domain;   // dns tunnel domain
#endif
  char *dns_hostname;
  u16 dns_port;

  u8 protocols;   // protocols this host can send & receive
  u16 udp_port, tcp_port;   // the port to bind to
  int max_retry;

  enum connectmode { C_ONDEMAND, C_NEVER, C_ALWAYS, C_DISABLED } connectmode;
  bool compress;
  bool inherit_tos; // inherit TOS in packets send to this destination

  u32 routerprio;

  void print ();

  ~conf_node ();
};

struct configuration {
  typedef vector<conf_node *> node_vector;
  node_vector nodes;
  conf_node default_node;
  conf_node *thisnode;
  int mtu;          // the mtu used for outgoing tunnel packets
  double rekey;     // rekey interval
  double keepalive; // keepalive probes interval
  char *ifname;     // the interface name (tap0 ...)
  bool ifpersist;   // should the interface be persistent
  char *prikeyfile;
  RSA *rsa_key;     // our private rsa key
  loglevel llevel;
  u8 ip_proto;      // the ip protocol to use
#if ENABLE_ICMP
  u8 icmp_type;     // the icmp type for the icmp-protocol
#endif

  char *script_if_up;
  char *script_node_up;
  char *script_node_down;
  char *pidfilename;

#if ENABLE_HTTP_PROXY
  char *proxy_auth;	// login:password
  char *proxy_host;	// the proxy hostname, e.g. proxy1.example.net
  u16 proxy_port;	// the proxy port, e.g. 3128
#endif

#if ENABLE_DNS
  char *dns_forw_host;
  u16 dns_forw_port;
  float dns_timeout_factor;
  float dns_send_interval;
  float dns_overlap_factor;
  int dns_max_outstanding;
#endif

  void init ();
  void cleanup ();
  void read_config (bool need_keys);
  void clear_config ();

  // create a filename from string, replacing %s by the nodename
  // and using relative paths under confbase.
  char *config_filename (const char *name, const char *dflt);

  void print ();

  configuration ();
  ~configuration ();
};

extern struct configuration conf;

#define THISNODE ::conf.thisnode

#endif

