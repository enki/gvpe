/*
    conf.c -- configuration code
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
    Foundation, Inc. 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "config.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <errno.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "netcompat.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include "conf.h"
#include "slog.h"
#include "util.h"

char *confbase;
char *thisnode;
char *identname;

struct configuration conf;

u8 best_protocol (u8 protset)
{
  if (protset & PROT_IPv4  ) return PROT_IPv4;
  if (protset & PROT_ICMPv4) return PROT_ICMPv4;
  if (protset & PROT_UDPv4 ) return PROT_UDPv4;
  if (protset & PROT_TCPv4 ) return PROT_TCPv4;
  if (protset & PROT_DNSv4 ) return PROT_DNSv4;

  return 0;
}

const char *strprotocol (u8 protocol)
{
  if (protocol & PROT_IPv4  ) return "rawip";
  if (protocol & PROT_ICMPv4) return "icmp";
  if (protocol & PROT_UDPv4 ) return "udp";
  if (protocol & PROT_TCPv4 ) return "tcp";
  if (protocol & PROT_DNSv4 ) return "dns";

  return "<unknown>";
}

static bool
match_list (const vector<const char *> &list, const char *str)
{
   for (vector<const char *>::const_iterator i = list.end (); i-- > list.begin (); )
     if ((*i)[0] == '*' && !(*i)[1])
       return true;
     else if (!strcmp (*i, str))
       return true;

   return false;
}

bool
conf_node::can_direct (struct conf_node *other)
{
  if (match_list (allow_direct, other->nodename))
    return true;

  if (match_list (deny_direct, other->nodename))
    return false;

  return true;
}

void
conf_node::print ()
{
  printf ("%4d  fe:fd:80:00:0%1x:%02x  %c  %-8.8s  %-10.10s  %s%s%d\n",
          id,
          id >> 8, id & 0xff,
          compress ? 'Y' : 'N',
          connectmode   == C_ONDEMAND ? "ondemand" :
            connectmode == C_NEVER    ? "never" :
            connectmode == C_ALWAYS   ? "always" : "",
          nodename,
          hostname ? hostname : "",
          hostname ? ":" : "",
          hostname ? udp_port : 0
          );
}

conf_node::~conf_node ()
{
#if 0
  // does not work, because string pointers etc. are shared
  // is not called, however
  if (rsa_key)
    RSA_free (rsa_key);

  free (nodename);
  free (hostname);
  free (if_up_data);
#if ENABLE_DNS
  free (domain);
  free (dns_hostname);
#endif
#endif
}

void configuration::init ()
{
  memset (this, 0, sizeof (*this));

  mtu       = DEFAULT_MTU;
  rekey     = DEFAULT_REKEY;
  keepalive = DEFAULT_KEEPALIVE;
  llevel    = L_INFO;
  ip_proto  = IPPROTO_GRE;
#if ENABLE_ICMP
  icmp_type = ICMP_ECHOREPLY;
#endif

  default_node.udp_port    = DEFAULT_UDPPORT;
  default_node.tcp_port    = DEFAULT_UDPPORT; // ehrm
  default_node.connectmode = conf_node::C_ALWAYS;
  default_node.compress    = true;
  default_node.protocols   = 0;
  default_node.max_retry   = DEFAULT_MAX_RETRY;
  default_node.max_ttl     = DEFAULT_MAX_TTL;
  default_node.max_queue   = DEFAULT_MAX_QUEUE;
  default_node.if_up_data  = strdup ("");

#if ENABLE_DNS
  default_node.dns_port    = 0; // default is 0 == client

  dns_forw_host       = strdup ("127.0.0.1");
  dns_forw_port       = 53;
  dns_timeout_factor  = DEFAULT_DNS_TIMEOUT_FACTOR;
  dns_send_interval   = DEFAULT_DNS_SEND_INTERVAL;
  dns_overlap_factor  = DEFAULT_DNS_OVERLAP_FACTOR;
  dns_max_outstanding = DEFAULT_DNS_MAX_OUTSTANDING;
#endif

  conf.pidfilename = strdup (LOCALSTATEDIR "/run/gvpe.pid");
}

void configuration::cleanup()
{
  if (rsa_key)
    RSA_free (rsa_key);

  rsa_key = 0;

  free (pidfilename);   pidfilename   = 0;
  free (ifname);        ifname        = 0;
#if ENABLE_HTTP_PROXY
  free (proxy_host);    proxy_host    = 0;
  free (proxy_auth);    proxy_auth    = 0;
#endif
#if ENABLE_DNS
  free (dns_forw_host); dns_forw_host = 0;
#endif
}

void
configuration::clear ()
{
  for (configuration::node_vector::iterator i = nodes.begin(); i != nodes.end(); ++i)
    delete *i;

  nodes.clear ();

  cleanup ();
  init ();
}

#define parse_bool(target,name,trueval,falseval) do {		\
  if      (!strcmp (val, "yes"))	target = trueval;	\
  else if (!strcmp (val, "no"))		target = falseval;	\
  else if (!strcmp (val, "true"))	target = trueval;	\
  else if (!strcmp (val, "false"))	target = falseval;	\
  else if (!strcmp (val, "on"))		target = trueval;	\
  else if (!strcmp (val, "off"))	target = falseval;	\
  else								\
    return _("illegal boolean value, only 'yes|true|on' or 'no|false|off' allowed. (ignored)"); \
} while (0)

const char *
configuration_parser::parse_line (char *line)
{
  {
    char *end = line + strlen (line);

    while (*end < ' ' && end >= line)
      end--;

    *++end = 0;
  }

  char *tok = line;
  const char *var = strtok (tok, "\t =");
  tok = 0;

  if (!var || !var[0])
    return 0;		/* no tokens on this line */

  if (var[0] == '#')
    return 0;		/* comment: ignore */

  char *val = strtok (NULL, "\t\n\r =");

  if (!val || val[0] == '#')
    return _("no value given for variable. (ignored)");

  if (!strcmp (var, "on"))
    {
      if (!::thisnode
          || (val[0] == '!' && strcmp (val + 1, ::thisnode))
          || !strcmp (val, ::thisnode))
        return parse_line (strtok (NULL, "\n\r"));
      else
        return 0;
    }

  // truly global
  if (!strcmp (var, "loglevel"))
    {
      loglevel l = string_to_loglevel (val);

      if (l == L_NONE)
        return _("unknown loglevel. (skipping)");
    }
  else if (!strcmp (var, "ip-proto"))
    conf.ip_proto = atoi (val);
  else if (!strcmp (var, "icmp-type"))
    {
#if ENABLE_ICMP
      conf.icmp_type = atoi (val);
#endif
    }

  // per config
  else if (!strcmp (var, "node"))
    {
      parse_argv ();

      conf.default_node.id++;
      node = new conf_node (conf.default_node);
      conf.nodes.push_back (node);
      node->nodename = strdup (val);

      {
        char *fname;
        FILE *f;

        asprintf (&fname, "%s/pubkey/%s", confbase, node->nodename);

        f = fopen (fname, "r");
        if (f)
          {
            node->rsa_key = RSA_new ();

            if (!PEM_read_RSAPublicKey(f, &node->rsa_key, NULL, NULL))
              {
                ERR_load_RSA_strings (); ERR_load_PEM_strings ();
                slog (L_ERR, _("unable to open public rsa key file '%s': %s"), fname, ERR_error_string (ERR_get_error (), 0));
                exit (EXIT_FAILURE);
              }

            require (RSA_blinding_on (node->rsa_key, 0));

            fclose (f);
          }
        else
          {
            slog (need_keys ? L_ERR : L_NOTICE, _("unable to read public rsa key file '%s': %s"), fname, strerror (errno));

            if (need_keys)
              exit (EXIT_FAILURE);
          }

        free (fname);
      }

      if (::thisnode && !strcmp (node->nodename, ::thisnode))
        conf.thisnode = node;
    }
  else if (!strcmp (var, "private-key"))
    free (conf.prikeyfile), conf.prikeyfile = strdup (val);
  else if (!strcmp (var, "ifpersist"))
    parse_bool (conf.ifpersist, "ifpersist", true, false);
  else if (!strcmp (var, "ifname"))
    free (conf.ifname), conf.ifname = strdup (val);
  else if (!strcmp (var, "rekey"))
    conf.rekey = atoi (val);
  else if (!strcmp (var, "keepalive"))
    conf.keepalive = atoi (val);
  else if (!strcmp (var, "mtu"))
    conf.mtu = atoi (val);
  else if (!strcmp (var, "if-up"))
    free (conf.script_if_up), conf.script_if_up = strdup (val);
  else if (!strcmp (var, "node-up"))
    free (conf.script_node_up), conf.script_node_up = strdup (val);
  else if (!strcmp (var, "node-down"))
    free (conf.script_node_down), conf.script_node_down = strdup (val);
  else if (!strcmp (var, "pid-file"))
    free (conf.pidfilename), conf.pidfilename = strdup (val);
  else if (!strcmp (var, "dns-forw-host"))
    {
#if ENABLE_DNS
      free (conf.dns_forw_host), conf.dns_forw_host = strdup (val);
#endif
    }
  else if (!strcmp (var, "dns-forw-port"))
    {
#if ENABLE_DNS
      conf.dns_forw_port = atoi (val);
#endif
    }
  else if (!strcmp (var, "dns-timeout-factor"))
    {
#if ENABLE_DNS
      conf.dns_timeout_factor = atof (val);
#endif
    }
  else if (!strcmp (var, "dns-send-interval"))
    {
#if ENABLE_DNS
      conf.dns_send_interval = atoi (val);
#endif
    }
  else if (!strcmp (var, "dns-overlap-factor"))
    {
#if ENABLE_DNS
      conf.dns_overlap_factor = atof (val);
#endif
    }
  else if (!strcmp (var, "dns-max-outstanding"))
    {
#if ENABLE_DNS
      conf.dns_max_outstanding = atoi (val);
#endif
    }
  else if (!strcmp (var, "http-proxy-host"))
    {
#if ENABLE_HTTP_PROXY
      free (conf.proxy_host), conf.proxy_host = strdup (val);
#endif
    }
  else if (!strcmp (var, "http-proxy-port"))
    {
#if ENABLE_HTTP_PROXY
      conf.proxy_port = atoi (val);
#endif
    }
  else if (!strcmp (var, "http-proxy-auth"))
    {
#if ENABLE_HTTP_PROXY
      conf.proxy_auth = (char *)base64_encode ((const u8 *)val, strlen (val));
#endif
    }

  /* node-specific, non-defaultable */
  else if (node != &conf.default_node && !strcmp (var, "hostname"))
    free (node->hostname), node->hostname = strdup (val);

  /* node-specific, defaultable */
  else if (!strcmp (var, "udp-port"))
    node->udp_port = atoi (val);
  else if (!strcmp (var, "tcp-port"))
    node->tcp_port = atoi (val);
  else if (!strcmp (var, "dns-hostname"))
    {
#if ENABLE_DNS
      free (node->dns_hostname), node->dns_hostname = strdup (val);
#endif
    }
  else if (!strcmp (var, "dns-port"))
    {
#if ENABLE_DNS
      node->dns_port = atoi (val);
#endif
    }
  else if (!strcmp (var, "dns-domain"))
    {
#if ENABLE_DNS
      free (node->domain), node->domain = strdup (val);
#endif
    }
  else if (!strcmp (var, "if-up-data"))
    free (node->if_up_data), node->if_up_data = strdup (val);
  else if (!strcmp (var, "router-priority"))
    node->routerprio = atoi (val);
  else if (!strcmp (var, "max-retry"))
    node->max_retry = atoi (val);
  else if (!strcmp (var, "connect"))
    {
      if (!strcmp (val, "ondemand"))
        node->connectmode = conf_node::C_ONDEMAND;
      else if (!strcmp (val, "never"))
        node->connectmode = conf_node::C_NEVER;
      else if (!strcmp (val, "always"))
        node->connectmode = conf_node::C_ALWAYS;
      else if (!strcmp (val, "disabled"))
        node->connectmode = conf_node::C_DISABLED;
      else
        return _("illegal value for 'connectmode', use one of 'ondemand', 'never', 'always' or 'disabled'. (ignored)");
    }
  else if (!strcmp (var, "inherit-tos"))
    parse_bool (node->inherit_tos, "inherit-tos", true, false);
  else if (!strcmp (var, "compress"))
    parse_bool (node->compress, "compress", true, false);
  // all these bool options really really cost a lot of executable size!
  else if (!strcmp (var, "enable-tcp"))
    {
#if ENABLE_TCP
      u8 v; parse_bool (v, "enable-tcp" , PROT_TCPv4, 0); node->protocols = (node->protocols & ~PROT_TCPv4) | v;
#endif
    }
  else if (!strcmp (var, "enable-icmp"))
    {
#if ENABLE_ICMP
      u8 v; parse_bool (v, "enable-icmp" , PROT_ICMPv4, 0); node->protocols = (node->protocols & ~PROT_ICMPv4) | v;
#endif
    }
  else if (!strcmp (var, "enable-dns"))
    {
#if ENABLE_DNS
      u8 v; parse_bool (v, "enable-dns" , PROT_DNSv4, 0); node->protocols = (node->protocols & ~PROT_DNSv4) | v;
#endif
    }
  else if (!strcmp (var, "enable-udp"))
    {
      u8 v; parse_bool (v, "enable-udp" , PROT_UDPv4, 0); node->protocols = (node->protocols & ~PROT_UDPv4) | v;
    }
  else if (!strcmp (var, "enable-rawip"))
    {
      u8 v; parse_bool (v, "enable-rawip", PROT_IPv4, 0); node->protocols = (node->protocols & ~PROT_IPv4 ) | v;
    }
  else if (!strcmp (var, "allow-direct"))
    node->allow_direct.push_back (strdup (val));
  else if (!strcmp (var, "deny-direct"))
    node->deny_direct.push_back (strdup (val));
  else if (!strcmp (var, "max-ttl"))
    node->max_ttl = atof (val);
  else if (!strcmp (var, "max-queue"))
    node->max_queue = atoi (val);

  // unknown or misplaced
  else
    return _("unknown configuration directive. (ignored)");

  return 0;
}

void configuration_parser::parse_argv ()
{
  for (int i = 0; i < argc; ++i)
    {
      char *v = argv [i];

      if (!*v)
        continue;

      char *enode = v;

      while (*enode != '.' && *enode > ' ' && *enode != '=' && *enode)
        enode++;

      if (*enode != '.')
        enode = 0;

      char *wnode = node == &conf.default_node
                    ? 0
                    : node->nodename;

      if ((!wnode && !enode)
          || (wnode && enode && !strncmp (wnode, v, enode - v)))
        {
          const char *warn = parse_line (enode ? enode + 1 : v);

          if (warn)
            slog (L_WARN, _("%s, while parsing command line option '%s'."), warn, v);

          *v = 0;
        }
    }
}

configuration_parser::configuration_parser (configuration &conf,
                                            bool need_keys,
                                            int argc,
                                            char **argv)
: conf (conf),need_keys (need_keys), argc (argc), argv (argv)
{
  char *fname;
  FILE *f;

  conf.clear ();

  asprintf (&fname, "%s/gvpe.conf", confbase);
  f = fopen (fname, "r");

  if (f)
    {
      char line[16384];
      int lineno = 0;
      node = &conf.default_node;

      while (fgets (line, sizeof (line), f))
        {
          lineno++;

          const char *warn = parse_line (line);

          if (warn)
            slog (L_WARN, _("%s, at '%s', line %d."), warn, fname, lineno);
        }

      fclose (f);

      parse_argv ();
    }
  else
    {
      slog (L_ERR, _("unable to read config file '%s': %s"), fname, strerror (errno));
      exit (EXIT_FAILURE);
    }

  free (fname);

  fname = conf.config_filename (conf.prikeyfile, "hostkey");

  f = fopen (fname, "r");
  if (f)
    {
      conf.rsa_key = RSA_new ();

      if (!PEM_read_RSAPrivateKey (f, &conf.rsa_key, NULL, NULL))
        {
          ERR_load_RSA_strings (); ERR_load_PEM_strings ();
          slog (L_ERR, _("unable to read private rsa key file '%s': %s"), fname, ERR_error_string (ERR_get_error (), 0));
          exit (EXIT_FAILURE);
        }

      require (RSA_blinding_on (conf.rsa_key, 0));

      fclose (f);
    }
  else
    {
      slog (need_keys ? L_ERR : L_NOTICE, _("unable to open private rsa key file '%s': %s"), fname, strerror (errno));

      if (need_keys)
        exit (EXIT_FAILURE);
    }

  if (need_keys && ::thisnode
      && conf.rsa_key && conf.thisnode && conf.thisnode->rsa_key)
    if (BN_cmp (conf.rsa_key->n, conf.thisnode->rsa_key->n) != 0
        || BN_cmp (conf.rsa_key->e, conf.thisnode->rsa_key->e) != 0)
      {
        slog (L_NOTICE, _("private hostkey and public node key mismatch: is '%s' the correct node?"), ::thisnode);
        exit (EXIT_FAILURE);
      }

  free (fname);
}

char *configuration::config_filename (const char *name, const char *dflt)
{
  char *fname;

  asprintf (&fname, name ? name : dflt, ::thisnode);

  if (!ABSOLUTE_PATH (fname))
    {
      char *rname = fname;
      asprintf (&fname, "%s/%s", confbase, rname);
      free (rname);
    }

  return fname;
}

void
configuration::print ()
{
  printf (_("\nConfiguration\n\n"));
  printf (_("# of nodes:         %d\n"), nodes.size ());
  printf (_("this node:          %s\n"), thisnode ? thisnode->nodename : "<unset>");
  printf (_("MTU:                %d\n"), mtu);
  printf (_("rekeying interval:  %d\n"), rekey);
  printf (_("keepalive interval: %d\n"), keepalive);
  printf (_("interface:          %s\n"), ifname);
  printf (_("primary rsa key:    %s\n"), prikeyfile ? prikeyfile : "<default>");
  printf (_("rsa key size:       %d\n"), rsa_key ? RSA_size (rsa_key) * 8 : -1);
  printf ("\n");

  printf ("%4s  %-17s %s %-8.8s  %-10.10s  %s\n",
          _("ID#"), _("MAC"), _("Com"), _("Conmode"), _("Node"), _("Host:Port"));

  for (node_vector::iterator i = nodes.begin (); i != nodes.end (); ++i)
    (*i)->print ();

  printf ("\n");
}

configuration::configuration ()
{
  asprintf (&confbase, "%s/gvpe", CONFDIR);

  init ();
}

configuration::~configuration ()
{
  cleanup ();
}


