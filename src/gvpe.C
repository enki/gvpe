/*
    vped.C -- the main file for gvpe
    Copyright (C) 1998-2002 Ivo Timmermans <ivo@o2w.nl>
                  2000-2002 Guus Sliepen <guus@sliepen.eu.org>
                  2003-2005 Marc Lehmann <gvpe@schmorp.de>
 
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

#include "config.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>

#if HAVE_SYS_MMAN_H
# include <sys/mman.h>
#endif

#include <openssl/err.h>
#include <openssl/rand.h>

#include "gettext.h"
#include "pidfile.h"

#include "conf.h"
#include "slog.h"
#include "util.h"
#include "vpn.h"
#include "iom.h"

static loglevel llevel = L_NONE;

/* If nonzero, display usage information and exit. */
static int show_help;

/* If nonzero, print the version on standard output and exit.  */
static int show_version;

/* If nonzero, disable swapping for this process. */
static int do_mlock = 0;

/* If zero, don't detach from the terminal. */
static int do_detach = 1;

static struct option const long_options[] =
    {
      {"config", required_argument, NULL, 'c'},
      {"help", no_argument, &show_help, 1},
      {"version", no_argument, &show_version, 1},
      {"no-detach", no_argument, &do_detach, 0},
      {"log-level", required_argument, NULL, 'l'},
      {"mlock", no_argument, &do_mlock, 1},
      {NULL, 0, NULL, 0}
    };

static void
usage (int status)
{
  if (status != 0)
    fprintf (stderr, _("Try `%s --help\' for more information.\n"), get_identity ());
  else
    {
      printf (_("Usage: %s [option]... NODENAME\n\n"), get_identity ());
      printf (_
              ("  -c, --config=DIR           Read configuration options from DIR.\n"
               "  -D, --no-detach            Don't fork and detach.\n"
               "  -l, --log-level=LEVEL      Set logging level (info, notice, warn are common).\n"
               "  -L, --mlock                Lock tinc into main memory.\n"
               "      --help                 Display this help and exit.\n"
               "      --version              Output version information and exit.\n\n"));
      printf (_("Report bugs to <vpe@plan9.de>.\n"));
    }

  exit (status);
}

void
parse_options (int argc, char **argv, char **envp)
{
  int r;
  int option_index = 0;

  while ((r = getopt_long (argc, argv, "-c:DLl:", long_options, &option_index)) != EOF)
    {
      switch (r)
        {
        case 0:		/* long option */
          break;

        case 1:		/* this node name */
          thisnode = strdup (optarg);
          break;

        case 'c':		/* config file */
          confbase = strdup (optarg);
          break;

        case 'D':		/* no detach */
          do_detach = 0;
          break;

        case 'L':		/* lock into memory */
          do_mlock = 1;
          break;

        case 'l':		/* inc debug level */
          {
            llevel = string_to_loglevel (optarg);

            if (llevel == L_NONE)
              slog (L_WARN, "'%s': %s", optarg, UNKNOWN_LOGLEVEL);
          }
          break;

        case '?':
          usage (1);

        default:
          break;
        }
    }
}

/*
  Close network connections, and terminate neatly
*/
void cleanup_and_exit(int c)
{
  network.shutdown_all ();

  if (conf.pidfilename)
    remove_pid (conf.pidfilename);

  slog (L_INFO, _("terminating with exit code %d"), c);

  exit (c);
}

/*
  Signal handlers.
*/
RETSIGTYPE
sigterm_handler (int a)
{
  network.events |= vpn::EVENT_SHUTDOWN;
  network.event.start (0);
}

RETSIGTYPE
sighup_handler (int a)
{
  network.events |= vpn::EVENT_RECONNECT;
  network.event.start (0);
}

RETSIGTYPE
sigusr1_handler (int a)
{
  network.dump_status ();
}

RETSIGTYPE
sigusr2_handler (int a)
{
}

void
setup_signals (void)
{
  struct sigaction act;

  sigfillset (&act.sa_mask);
  act.sa_flags = 0;

  act.sa_handler = sighup_handler;  sigaction (SIGHUP , &act, NULL);
  act.sa_handler = sigusr1_handler; sigaction (SIGUSR1, &act, NULL);
  act.sa_handler = sigusr2_handler; sigaction (SIGUSR2, &act, NULL);
  act.sa_handler = SIG_IGN;         sigaction (SIGCHLD, &act, NULL);
  act.sa_handler = SIG_IGN;         sigaction (SIGPIPE, &act, NULL);
  act.sa_flags = SA_RESETHAND;
  act.sa_handler = sigterm_handler; sigaction (SIGINT , &act, NULL);
  act.sa_handler = sigterm_handler; sigaction (SIGTERM, &act, NULL);
}

int
main (int argc, char **argv, char **envp)
{
  ERR_load_crypto_strings (); // we have the RAM

  set_loglevel (L_INFO);
  set_identity (argv[0]);
  log_to (LOGTO_SYSLOG | LOGTO_STDERR);

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);

  parse_options (argc, argv, envp);

  if (show_version)
    {
      printf (_("%s version %s (built %s %s, protocol %d.%d)\n"), get_identity (),
              VERSION, __DATE__, __TIME__, PROTOCOL_MAJOR, PROTOCOL_MINOR);
      printf (_("Built with kernel interface %s/%s.\n"), IFTYPE, IFSUBTYPE);
      printf (_
              ("Copyright (C) 2003 Marc Lehmann <vpe@plan9.de> and others.\n"
               "See the AUTHORS file for a complete list.\n\n"
               "tinc comes with ABSOLUTELY NO WARRANTY.  This is free software,\n"
               "and you are welcome to redistribute it under certain conditions;\n"
               "see the file COPYING for details.\n"));

      return 0;
    }

  if (show_help)
    usage (0);

  log_to (LOGTO_SYSLOG | LOGTO_STDERR);

  /* Lock all pages into memory if requested */

#if HAVE_MLOCKALL && HAVE_SYS_MMAN_H && _POSIX_MEMLOCK
  if (do_mlock)
    if (mlockall (MCL_CURRENT | MCL_FUTURE))
      slog (L_ERR, _("system call `%s' failed: %s"), "mlockall", strerror (errno));
#endif

  conf.read_config (true);

  set_loglevel (llevel != L_NONE ? llevel : conf.llevel);

  RAND_load_file ("/dev/urandom", 1024);

  if (!THISNODE)
    {
      slog (L_ERR, _("current node not set, or node '%s' not found in configfile, specify the nodename when starting gvpe."),
            thisnode ? thisnode : "<unset>");
      exit (EXIT_FAILURE);
    }

  if (detach (do_detach))
    exit (EXIT_SUCCESS);

  setup_signals ();

  if (!network.setup ())
    {
      io_manager::loop ();
      cleanup_and_exit (EXIT_FAILURE);
    }

  slog (L_ERR, _("unable to setup network, unrecoverable error, exiting."));
  cleanup_and_exit (EXIT_FAILURE);
}

