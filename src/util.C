/*
    util.C -- process management and other utility functions
    
    Most of these are taken from tinc, see the AUTHORS file.
 
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
#include <cstring>

#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/mman.h>

#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "gettext.h"
#include "pidfile.h"
#include "dropin.h"

#include "global.h"
#include "conf.h"
#include "slog.h"
#include "protocol.h"

time_t now;

int
write_pidfile (void)
{
  int pid;

  pid = check_pid (pidfilename);

  if (pid)
    {
      fprintf (stderr, _("A vped is already running with pid %d.\n"), pid);
      return 1;
    }

  /* if it's locked, write-protected, or whatever */
  if (!write_pid (pidfilename))
    return 1;

  return 0;
}

int
kill_other (int signal)
{
  int pid;

  pid = read_pid (pidfilename);

  if (!pid)
    {
      fprintf (stderr, _("No other vped is running.\n"));
      return 1;
    }

  errno = 0;			/* No error, sometimes errno is only changed on error */

  /* ESRCH is returned when no process with that pid is found */
  if (kill (pid, signal) && errno == ESRCH)
    {
      fprintf (stderr, _("The vped is no longer running. "));

      fprintf (stderr, _("Removing stale lock file.\n"));
      remove_pid (pidfilename);
    }

  return 0;
}

int
detach (int do_detach)
{
  /* First check if we can open a fresh new pidfile */

  if (write_pidfile ())
    return -1;

  /* If we succeeded in doing that, detach */

  log_to (0);

  if (do_detach)
    {
      if (daemon (0, 0) < 0)
        {
          log_to (LOGTO_SYSLOG | LOGTO_STDERR);

          slog (L_ERR, _("couldn't detach from terminal: %s"), strerror (errno));
          return -1;
        }

      /* Now UPDATE the pid in the pidfile, because we changed it... */

      if (!write_pid (pidfilename))
        return -1;

      log_to (LOGTO_SYSLOG);
    }
  else
    log_to (LOGTO_SYSLOG | LOGTO_STDERR);

  slog (L_INFO, _("vped %s (%s %s) starting"), VERSION, __DATE__, __TIME__);

  return 0;
}

void
make_names (void)
{
  if (!pidfilename)
    pidfilename = LOCALSTATEDIR "/run/vped.pid";

  if (!confbase)
    asprintf (&confbase, "%s/vpe", CONFDIR);
}

void pkt_queue::put (tap_packet *p)
{
  if (queue[i])
    {
      delete queue[i];
      j = (j + 1) % QUEUEDEPTH;
    }

  queue[i] = p;

  i = (i + 1) % QUEUEDEPTH;
}

tap_packet *pkt_queue::get ()
{
  tap_packet *p = queue[j];

  if (p)
    {
      queue[j] = 0;
      j = (j + 1) % QUEUEDEPTH;
    }

  return p;
}

pkt_queue::pkt_queue ()
{
  memset (queue, 0, sizeof (queue));
  i = 0;
  j = 0;
}

pkt_queue::~pkt_queue ()
{
  for (i = QUEUEDEPTH; --i > 0; )
    delete queue[i];
}

sockinfo::operator const char *()
{
  static char hostport[15 + 1 + 5 + 1];
  in_addr ia = { host };

  sprintf (hostport, "%.15s:%d", inet_ntoa (ia), ntohs (port) & 0xffff);

  return hostport;
}

bool u32_rate_limiter::can (u32 host)
{
  iterator i;

  for (i = begin (); i != end (); )
    if (i->second <= now)
      {
        erase (i);
        i = begin ();
      }
    else
      ++i;

  i = find (host);

  if (i != end ())
    return false;

  insert (value_type (host, now + every));

  return true;
}

