/*
    dropin.h -- header file for dropin.c
    Copyright (C) 2000,2001 Ivo Timmermans <ivo@o2w.nl>,
                  2000,2001 Guus Sliepen <guus@sliepen.eu.org>

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

#ifndef __DROPIN_H__
#define __DROPIN_H__

#ifdef __cplusplus
extern "C" {
#endif

#ifndef HAVE_DAEMON
extern int daemon(int, int);
#endif

#ifndef HAVE_GET_CURRENT_DIR_NAME
extern char *get_current_dir_name(void);
#endif

#ifndef HAVE_ASPRINTF
extern int asprintf(char **, const char *, ...);
#endif

#ifdef __cplusplus
}
#endif

#endif							/* __DROPIN_H__ */
