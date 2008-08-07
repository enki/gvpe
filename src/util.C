/*
    util.C -- process management and other utility functions
    Copyright (C) 2003-2008 Marc Lehmann <gvpe@schmorp.de>
    
    Some of these are taken from tinc, see the AUTHORS file.
 
    This file is part of GVPE.

    GVPE is free software; you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by the
    Free Software Foundation; either version 3 of the License, or (at your
    option) any later version.
   
    This program is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
    Public License for more details.
   
    You should have received a copy of the GNU General Public License along
    with this program; if not, see <http://www.gnu.org/licenses/>.
   
    Additional permission under GNU GPL version 3 section 7
   
    If you modify this Program, or any covered work, by linking or
    combining it with the OpenSSL project's OpenSSL library (or a modified
    version of that library), containing parts covered by the terms of the
    OpenSSL or SSLeay licenses, the licensors of this Program grant you
    additional permission to convey the resulting work.  Corresponding
    Source for a non-source form of such a combination shall include the
    source code for the parts of OpenSSL used as well as that of the
    covered work.
*/

#include "config.h"

#include <cstdio>
#include <cstdlib>
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

  pid = check_pid (conf.pidfilename);

  if (pid)
    {
      fprintf (stderr, _("A gvpe daemon is already running with pid %d.\n"), pid);
      return 1;
    }

  /* if it's locked, write-protected, or whatever */
  if (!write_pid (conf.pidfilename))
    return 1;

  return 0;
}

int
kill_other (int signal)
{
  int pid;

  pid = read_pid (conf.pidfilename);

  if (!pid)
    {
      fprintf (stderr, _("No other gvpe daemon is running.\n"));
      return 1;
    }

  errno = 0;			/* No error, sometimes errno is only changed on error */

  /* ESRCH is returned when no process with that pid is found */
  if (kill (pid, signal) && errno == ESRCH)
    {
      fprintf (stderr, _("The gvpe daemon is no longer running. "));

      fprintf (stderr, _("Removing stale lock file.\n"));
      remove_pid (conf.pidfilename);
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

      if (!write_pid (conf.pidfilename))
        return -1;

      log_to (LOGTO_SYSLOG);
    }
  else
    log_to (LOGTO_SYSLOG | LOGTO_STDERR);

  slog (L_INFO, _("gvpe daemon %s (%s %s) starting"), VERSION, __DATE__, __TIME__);

  return 0;
}

pid_t
run_script (const run_script_cb &cb, bool wait)
{
  sigset_t oldset;

  if (wait)
    {
      sigset_t sigchld;
      sigemptyset (&sigchld);
      sigaddset (&sigchld, SIGCHLD);
      sigprocmask (SIG_BLOCK, &sigchld, &oldset);
    }

  pid_t pid = fork ();

  if (pid == 0)
    {
      sigprocmask (SIG_SETMASK, &oldset, 0);

      execl ("/bin/sh", "/bin/sh", "-c", cb (), (char *) 0);
      exit (EXIT_FAILURE);
    }
  else if (pid > 0)
    {
      if (wait)
        {
          int status;
          int res = waitpid (pid, &status, 0);

          sigprocmask (SIG_SETMASK, &oldset, 0);

          if (res < 0)
            {
              slog (L_WARN, _("waiting for an external command failed: %s."),
                    strerror (errno));
              return 0;
            }
          else if (!WIFEXITED (status) || WEXITSTATUS (status) != EXIT_SUCCESS)
            {
              slog (L_WARN, _("external command returned with exit status %d (%04x)."),
                    WEXITSTATUS (status), status);
              return 0;
            }
        }
    }
  else
    {
      slog (L_ERR, _("unable to fork, exiting: %s"), strerror (errno));
      exit (EXIT_FAILURE);
    }

  return pid;
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

void
id2mac (unsigned int id, void *m)
{
  mac &p = *(mac *)m;

  if (id)
    {
      p[0] = 0xfe;
      p[1] = 0xfd;
      p[2] = 0x80;
      p[3] = 0x00;
      p[4] = id >> 8;
      p[5] = id;
    }
  else
    {
      p[0] = 0xff;
      p[1] = 0xff;
      p[2] = 0xff;
      p[3] = 0xff;
      p[4] = 0xff;
      p[5] = 0xff;
    }
}

