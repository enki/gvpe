/*
    slog.h -- logging
    Copyright (C) 2003-2008 Marc Lehmann <gvpe@schmorp.de>
 
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

#ifndef SLOG_H__
#define SLOG_H__

enum loglevel {
  L_NONE,
  L_NOISE,
  L_TRACE,
  L_DEBUG,
  L_INFO,
  L_NOTICE,
  L_WARN,
  L_ERR,
  L_CRIT
};

enum {
  LOGTO_SYSLOG = 1,
  LOGTO_STDERR = 2
};

extern loglevel log_level;
extern const char *log_identity;

extern loglevel string_to_loglevel (const char *s);
#define UNKNOWN_LOGLEVEL _("unknown loglevel, try 'noise', 'debug', 'info', 'notice', 'warn', 'error' or 'critical'")

inline void set_loglevel (const loglevel l)
{
  log_level = l;
}

inline loglevel get_loglevel ()
{
  return log_level;
}

inline void set_identity (const char *identname)
{
  log_identity = identname;
}

inline const char *get_identity ()
{
  return log_identity;
}

extern void log_to (int mask);

extern void slog_ (const loglevel l, const char *m, ...);

#if __GNUC__ > 2
# define slog(l, ...) do { if ((l) >= log_level) slog_ (l, __VA_ARGS__); } while (0)
#else
# define slog slog_
#endif

extern void fatal (const char *m);
extern void require_failed (const char *file, int line, const char *info);

#define require(expr) if (!(expr)) require_failed (__FILE__,  __LINE__, #expr)

#endif

