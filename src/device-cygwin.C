/*
    device-cygwin.C -- Stub for Cygwin environment
    Copyright (C) 2003 Marc Lehmann <ocg@goof.com>

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

// unfortunately, there is be no way to set MAC addresses under windows,
// and the default cipedrvr uses a different MAC address than we do,
// so this module tries to fix mac addresses in packets and arp packets.
// this is probably not very fast, but neither is cygwin nor poll.
//
// http://cipe-win32.sourceforge.net/

#include "config.h"

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <cstring>

#include "conf.h"
#include "util.h"

tap_device::tap_device ()
{
  if ((fd = open (conf.ifname, O_RDWR)) < 0)
    {
      slog (L_CRIT, _("could not open %s: %s"), conf.ifname, strerror (errno));
      exit (1);
    }
}

tap_device::~tap_device ()
{
  close (fd);
}

tap_packet *
tap_device::recv ()
{
  tap_packet *pkt = new tap_packet;

  pkt->len = read (fd, &((*pkt)[0]), MAX_MTU);

  if (pkt->len <= 0)
    {
      slog (L_ERR, _("error while reading from %s %s: %s"),
            info (), conf.ifname, strerror (errno));
      free (pkt);
      return 0;
    }

  id2mac (THISNODE->id, &((*pkt)[6]));

  if (pkt->is_arp ())
    {
      if ((*pkt)[22] == 0x08) id2mac (THISNODE->id, &((*pkt)[22]));
      if ((*pkt)[32] == 0x08) id2mac (THISNODE->id, &((*pkt)[32]));
    }

  return pkt;
}

void
tap_device::send (tap_packet *pkt)
{
  (*pkt)[ 6] = 0x08; (*pkt)[ 7] = 0x00; (*pkt)[ 8] = 0x58;
  (*pkt)[ 9] = 0x00; (*pkt)[10] = 0x00; (*pkt)[11] = 0x01;

  if (pkt->is_arp ())
    {
      if ((*pkt)[22] == 0xfe && (*pkt)[27] == THISNODE->id) 
        memcpy (&(*pkt)[22], &(*pkt)[6], sizeof (mac));

      if ((*pkt)[32] == 0xfe && (*pkt)[37] == THISNODE->id) 
        memcpy (&(*pkt)[32], &(*pkt)[6], sizeof (mac));
    }

  if (write (fd, &((*pkt)[0]), pkt->len) < 0)
    slog (L_ERR, _("can't write to %s %s: %s"), info (), conf.ifname,
          strerror (errno));
}
