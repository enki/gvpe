/*
    util.C -- process management and other utility functions
    
    Some of these are taken from tinc, see the AUTHORS file.
 
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
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>

#include "netcompat.h"

#include "gettext.h"
#include "pidfile.h"
#include "dropin.h"

#include "global.h"
#include "conf.h"
#include "util.h"
#include "slog.h"

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

void run_script (const run_script_cb &cb, bool wait)
{
  int pid;

  if ((pid = fork ()) == 0)
    {
      char *filename;
      asprintf (&filename, "%s/%s", confbase, cb());
      execl (filename, filename, (char *) 0);
      exit (255);
    }
  else if (pid > 0)
    {
      if (wait)
        {
          waitpid (pid, 0, 0);
          /* TODO: check status */
        }
    }
}

#if ENABLE_HTTP_PROXY
// works like strdup
u8 *
base64_encode (const u8 *data, unsigned int len)
{
  const static char base64[65] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  unsigned int t, i;
  const u8 *end = data + len;
  u8 *res = new u8 [4 * ((len + 2) / 3) + 1];
  u8 *out = res;

  while (data <= end - 3)
    {
      t = (((data[0] << 8) | data[1]) << 8) | data[2];
      data += 3;
      
      *out++ = base64[(t >> 18) & 0x3f];
      *out++ = base64[(t >> 12) & 0x3f];
      *out++ = base64[(t >>  6) & 0x3f];
      *out++ = base64[(t      ) & 0x3f];
    }

  for (t = 0, i = 0; data < end; i++)
    t = (t << 8) | *data++;

  switch (i)
    {
      case 2:
        *out++ = base64[(t >> 10) & 0x3f];
        *out++ = base64[(t >>  4) & 0x3f];
        *out++ = base64[(t <<  2) & 0x3f];
        *out++ = '=';
        break;
      case 1:
        *out++ = base64[(t >>  2) & 0x3f];
        *out++ = base64[(t <<  4) & 0x3f];
        *out++ = '=';
        *out++ = '=';
        break;
    }

  *out++ = 0;

  return res;
}
#endif

