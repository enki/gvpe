/*
    conf.c -- configuration code
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

#include "gettext.h"

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
  if (rsa_key)
    RSA_free (rsa_key);

  free (nodename);
  free (hostname);
#if ENABLE_DNS
  free (domain);
  free (dns_hostname);
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

#if ENABLE_DNS
  default_node.dns_port    = 53;
  dns_forw_port            = 53;
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
configuration::clear_config ()
{
  for (configuration::node_vector::iterator i = nodes.begin(); i != nodes.end(); ++i)
    delete *i;

  nodes.clear ();

  cleanup ();
  init ();
}

#define parse_bool(target,name,trueval,falseval)		\
  if (!strcmp (val, "yes"))		target = trueval;	\
  else if (!strcmp (val, "no"))		target = falseval;	\
  else if (!strcmp (val, "true"))	target = trueval;	\
  else if (!strcmp (val, "false"))	target = falseval;	\
  else if (!strcmp (val, "on"))		target = trueval;	\
  else if (!strcmp (val, "off"))	target = falseval;	\
  else								\
    slog (L_WARN,						\
            _("illegal value for '%s', only 'yes|true|on' or 'no|false|off' allowed, at '%s' line %d"), \
            name, var, fname, lineno);

void configuration::read_config (bool need_keys)
{
  char *fname;
  FILE *f;

  clear_config ();

  asprintf (&fname, "%s/gvpe.conf", confbase);
  f = fopen (fname, "r");

  if (f)
    {
      char line[16384];
      int lineno = 0;
      char *var, *val;
      conf_node *node = &default_node;

      while (fgets (line, sizeof (line), f))
        {
          lineno++;

          {
            char *end = line + strlen (line);

            while (*end < ' ' && end >= line)
              end--;

            *++end = 0;
          }

          char *tok = line;

retry:
          var = strtok (tok, "\t =");
          tok = 0;

          if (!var || !var[0])
            continue;		/* no tokens on this line */

          if (var[0] == '#')
            continue;		/* comment: ignore */

          val = strtok (NULL, "\t\n\r =");

          if (!val || val[0] == '#')
            {
              slog (L_WARN,
                      _("no value for variable `%s', at '%s' line %d"),
                      var, fname, lineno);
              break;
            }

          if (!strcmp (var, "on"))
            {
              if (!::thisnode
                  || (val[0] == '!' && strcmp (val + 1, ::thisnode))
                  || !strcmp (val, ::thisnode))
                goto retry;

              continue;
            }

          // truly global
          if (!strcmp (var, "loglevel"))
            {
              loglevel l = string_to_loglevel (val);

              if (l != L_NONE)
                llevel = l;
              else
                slog (L_WARN, "'%s': %s, at '%s' line %d", val, UNKNOWN_LOGLEVEL, fname, line);
            }
          else if (!strcmp (var, "ip-proto"))
            ip_proto = atoi (val);
          else if (!strcmp (var, "icmp-type"))
            {
#if ENABLE_ICMP
              icmp_type = atoi (val);
#endif
            }

          // per config
          else if (!strcmp (var, "node"))
            {
              default_node.id++;

              node = new conf_node (default_node);

              nodes.push_back (node);

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
                thisnode = node;
            }
          else if (!strcmp (var, "private-key"))
            free (prikeyfile), prikeyfile = strdup (val);
          else if (!strcmp (var, "ifpersist"))
            {
              parse_bool (ifpersist, "ifpersist", true, false);
            }
          else if (!strcmp (var, "ifname"))
            free (ifname), ifname = strdup (val);
          else if (!strcmp (var, "rekey"))
            rekey = atoi (val);
          else if (!strcmp (var, "keepalive"))
            keepalive = atoi (val);
          else if (!strcmp (var, "mtu"))
            mtu = atoi (val);
          else if (!strcmp (var, "if-up"))
            free (script_if_up), script_if_up = strdup (val);
          else if (!strcmp (var, "node-up"))
            free (script_node_up), script_node_up = strdup (val);
          else if (!strcmp (var, "node-down"))
            free (script_node_down), script_node_down = strdup (val);
          else if (!strcmp (var, "pid-file"))
            free (pidfilename), pidfilename = strdup (val);
#if ENABLE_DNS
          else if (!strcmp (var, "dns-forw-host"))
            free (dns_forw_host), dns_forw_host = strdup (val);
          else if (!strcmp (var, "dns-forw-port"))
            dns_forw_port = atoi (val);
#endif
          else if (!strcmp (var, "http-proxy-host"))
            {
#if ENABLE_HTTP_PROXY
              free (proxy_host), proxy_host = strdup (val);
#endif
            }
          else if (!strcmp (var, "http-proxy-port"))
            {
#if ENABLE_HTTP_PROXY
              proxy_port = atoi (val);
#endif
            }
          else if (!strcmp (var, "http-proxy-auth"))
            {
#if ENABLE_HTTP_PROXY
              proxy_auth = (char *)base64_encode ((const u8 *)val, strlen (val));
#endif
            }

          /* node-specific, non-defaultable */
          else if (node != &default_node && !strcmp (var, "hostname"))
            free (node->hostname), node->hostname = strdup (val);

          /* node-specific, defaultable */
          else if (!strcmp (var, "udp-port"))
            node->udp_port = atoi (val);
          else if (!strcmp (var, "tcp-port"))
            node->tcp_port = atoi (val);
#if ENABLE_DNS
          else if (!strcmp (var, "dns-hostname"))
            free (node->dns_hostname), node->dns_hostname = strdup (val);
          else if (!strcmp (var, "dns-port"))
            node->dns_port = atoi (val);
#endif
          else if (!strcmp (var, "dns-domain"))
            {
#if ENABLE_DNS
              free (node->domain), node->domain = strdup (val);
#endif
            }
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
                slog (L_WARN,
                      _("illegal value for 'connectmode', use one of 'ondemand', 'never', 'always' or 'disabled', at '%s' line %d"),
                      var, fname, lineno);
            }
          else if (!strcmp (var, "inherit-tos"))
            {
              parse_bool (node->inherit_tos, "inherit-tos", true, false);
            }
          else if (!strcmp (var, "compress"))
            {
              parse_bool (node->compress, "compress", true, false);
            }
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

          // unknown or misplaced
          else
            slog (L_WARN,
                    _("unknown or misplaced variable `%s', at '%s' line %d"),
                    var, fname, lineno);
        }

      fclose (f);
    }
  else
    {
      slog (L_ERR, _("unable to read config file '%s': %s"), fname, strerror (errno));
      exit (EXIT_FAILURE);
    }

  free (fname);

  fname = config_filename (prikeyfile, "hostkey");

  f = fopen (fname, "r");
  if (f)
    {
      rsa_key = RSA_new ();

      if (!PEM_read_RSAPrivateKey (f, &rsa_key, NULL, NULL))
        {
          ERR_load_RSA_strings (); ERR_load_PEM_strings ();
          slog (L_ERR, _("unable to read private rsa key file '%s': %s"), fname, ERR_error_string (ERR_get_error (), 0));
          exit (EXIT_FAILURE);
        }

      require (RSA_blinding_on (rsa_key, 0));

      fclose (f);
    }
  else
    {
      slog (need_keys ? L_ERR : L_NOTICE, _("unable to open private rsa key file '%s': %s"), fname, strerror (errno));

      if (need_keys)
        exit (EXIT_FAILURE);
    }

  if (need_keys && ::thisnode
      && rsa_key && thisnode && thisnode->rsa_key)
    if (BN_cmp (rsa_key->n, thisnode->rsa_key->n) != 0
        || BN_cmp (rsa_key->e, thisnode->rsa_key->e) != 0)
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


