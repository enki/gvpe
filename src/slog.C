/*
    slog.C -- logging
    Copyright (C) 2003 Marc Lehmann <pcg@goof.com>
 
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

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <unistd.h>
#include <syslog.h>

#include "slog.h"

loglevel log_level = L_INFO;
const char *log_identity = "";
static int logto = LOGTO_STDERR;

loglevel string_to_loglevel (const char *s)
{
  if (!strcmp (s, "noise"))    return L_NOISE;
  if (!strcmp (s, "trace"))    return L_TRACE;
  if (!strcmp (s, "debug"))    return L_DEBUG;
  if (!strcmp (s, "info"))     return L_INFO;
  if (!strcmp (s, "notice"))   return L_NOTICE;
  if (!strcmp (s, "warn"))     return L_WARN;
  if (!strcmp (s, "error"))    return L_ERR;
  if (!strcmp (s, "critical")) return L_CRIT;

  return L_NONE;
}

void log_to (int mask)
{
  if (logto & LOGTO_SYSLOG)
    closelog ();

  logto = mask;

  if (logto & LOGTO_SYSLOG)
    openlog (log_identity, LOG_CONS | LOG_PID, LOG_DAEMON);
}

void slog_ (const loglevel l, const char *m, ...)
{
  if (l >= log_level)
    {
      va_list ap;
      va_start (ap, m);
      char *msg = new char [2048];

      vsnprintf (msg, 2048, m, ap);

      if (logto & LOGTO_SYSLOG)
        {
          int lvl = l == L_TRACE  ? LOG_DEBUG
                  : l == L_DEBUG  ? LOG_DEBUG
                  : l == L_INFO   ? LOG_INFO
                  : l == L_NOTICE ? LOG_NOTICE
                  : l == L_ERR    ? LOG_ERR
                  : l == L_CRIT   ? LOG_CRIT
                  :                 LOG_ERR;

          syslog (lvl, "%s", msg);
        }

      if (logto & LOGTO_STDERR)
        {
          write (2, msg, strlen (msg));
          write (2, "\n", 1);
        }

      delete msg;
    }
}

void fatal (const char *m)
{
  slog (L_CRIT, m);
  exit (EXIT_FAILURE);
}

extern void require_failed (const char *file, int line, const char *info)
{
  slog (L_CRIT, "FATAL: This program encountered a SHOULD NOT HAPPEN condition and will exit:");
  slog (L_CRIT, "FATAL+ %s:%d '%s' is false", file, line, info);
  slog (L_CRIT, "FATAL+ This might indicates a bug in this program, a bug in your libraries,");
  slog (L_CRIT, "FATAL+ your system setup or operating system. Or it might indicate a very");
  slog (L_CRIT, "FATAL+ unusual, unanticipated operating condition, library version mismatch");
  slog (L_CRIT, "FATAL+ or similar problem. If it's not obvious to you what was causing it,");
  slog (L_CRIT, "FATAL+ then please report this to the program author(s).");
  exit (126);
}

