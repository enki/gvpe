/*
    conf.h -- configuration database
 
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

#ifndef VPE_CONF_H__
#define VPE_CONF_H__

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifdef HAVE_OPENSSL_RSA_H
# include <openssl/rsa.h>
#else
# include <rsa.h>
#endif

#include <vector>

#include "slog.h"
#include "global.h"

#define DEFAULT_REKEY		3600
#define DEFAULT_KEEPALIVE	60	// one keepalive/minute (it's just 48 bytes...)
#define DEFAULT_PORT		655	// same as tinc, conflicts would be rara

struct conf_node {
  int id;         // the id of this node, a 12-bit-number

  RSA *rsa_key;   // his public key
  char *nodename; // nodename, an internal nickname.

  char *hostname; // hostname, if known, or NULL.
  u16 port;       // the port to bind to

  enum connectmode { C_ONDEMAND, C_NEVER, C_ALWAYS, C_DISABLED } connectmode;
  bool compress;
  bool inherit_tos; // inherit TOS in packets send to this destination
  u32 can_recv, can_send;

  u32 routerprio;

  void print ();

  conf_node()
  {
    memset (this, 0, sizeof *this);
  }

  ~conf_node ()
    {
      if (rsa_key)
        RSA_free (rsa_key);

      free (nodename);
      free (hostname);
    }
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
  loglevel llevel;
  RSA *rsa_key;     // our private rsa key

  char *script_if_up;
  char *script_node_up;
  char *script_node_down;

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

