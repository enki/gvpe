/*
    device-darwin.C -- device driver for mac os x
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

// uses the kernel driver at:
// http://www-user.rhrk.uni-kl.de/~nissler/tuntap/

#include <cstdio>
#include <cstring>
#include <cerrno>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>

#include "conf.h"

// following headers used by cygwin (maybe others)
#include "netcompat.h"
#include <signal.h>

#define DEFAULT_DEVICE "/dev/tap0"

const char *
tap_device::info ()
{
  return _("darwin tap driver");
}

const char *
tap_device::if_up ()
{
  return "/sbin/ifconfig $IFNAME ether $MAC mtu $MTU";
}

tap_device::tap_device ()
{
  const char *device = conf.ifname ? conf.ifname : DEFAULT_DEVICE;

  if ((fd = open (device, O_RDWR | O_NONBLOCK)) < 0)
    {
      slog (L_ERR, _("could not open device %s: %s"), device, strerror (errno));
      exit (EXIT_FAILURE);
    }

  slog (L_DEBUG, _("interface %s on %s initialized"), info (), device);

  strcpy (ifrname, rindex(device, '/') ? rindex(device, '/') + 1 : device);
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
      delete pkt;
      slog (L_ERR, _("error while reading from %s %s: %s"),
            info (), DEFAULT_DEVICE, strerror (errno));
      return 0;
    }

  return pkt;
}

void
tap_device::send (tap_packet *pkt)
{
  if (write (fd, &((*pkt)[0]), pkt->len) < 0)
    slog (L_ERR, _("can't write to %s %s: %s"), info (), DEFAULT_DEVICE,
          strerror (errno));
}



