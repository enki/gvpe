/*
    device-linux.C -- Interaction with Linux tun/tap device
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

#include "config.h"

#include <cstdio>
#include <cstring>
#include <cstdlib>

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <net/if.h>

#ifdef LINUX_IF_TUN_H
# include LINUX_IF_TUN_H
#else
#include <linux/if_tun.h>
#endif
#define DEFAULT_DEVICE "/dev/net/tun"

#include "gettext.h"

#include "conf.h"

#if TEST_ETHEREMU
# define IF_istun
# include "ether_emu.C"
#endif

const char *
tap_device::info ()
{
  return _("Linux tun/tap device");
}

const char *
tap_device::if_up ()
{
  return "/sbin/ifconfig $IFNAME hw ether $MAC mtu $MTU";
}

tap_device::tap_device ()
{
  struct ifreq ifr;

  device = (char *)DEFAULT_DEVICE;

  fd = open (device, O_RDWR);

  if (fd < 0)
    {
      slog (L_ERR, _("could not open device %s: %s"), device, strerror (errno));
      exit (EXIT_FAILURE);
    }

  memset (&ifr, 0, sizeof (ifr));
#if TEST_ETHEREMU
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
#else
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
#endif

  if (conf.ifname)
    strncpy (ifr.ifr_name, conf.ifname, IFNAMSIZ);
  else
    ifr.ifr_name[0] = 0;

  if (!ioctl (fd, TUNSETIFF, &ifr))
    {
      strncpy (ifrname, ifr.ifr_name, IFNAMSIZ);
      ifrname [IFNAMSIZ] = 0;
    }
  else
    {
      slog (L_CRIT, _("unable to configure tun/tap interface, exiting: %s"), strerror (errno));
      exit (EXIT_FAILURE);
    }

#if 0
  does not work
  id2mac (THISNODE->id, &ifr.ifr_hwaddr.sa_data);
  if (ioctl (fd, SIOCSIFHWADDR, &ifr))
    {
      slog (L_ERR, _("cannot set MAC address for device %s, exiting: %s"), ifrname, strerror (errno));
      exit (EXIT_FAILURE);
    }
#endif

  if (ioctl (fd, TUNSETPERSIST, conf.ifpersist ? 1 : 0))
    slog (L_WARN, _("cannot set persistency mode for device %s: %s"), ifrname, strerror (errno));

  slog (L_DEBUG, _("%s is a %s"), device, info ());
}

tap_device::~tap_device ()
{
  close (fd);
}

tap_packet *
tap_device::recv ()
{
  tap_packet *pkt = new tap_packet;

#if TEST_ETHEREMU
  pkt->len = read (fd, &((*pkt)[14]), MAX_MTU - 14);
#else
  pkt->len = read (fd, &((*pkt)[0]), MAX_MTU);
#endif

  if (pkt->len <= 0)
    {
      delete pkt;
      slog (L_ERR, _("error while reading from %s %s: %s"),
            info (), DEFAULT_DEVICE, strerror (errno));
      return 0;
    }

#if TEST_ETHEREMU
  pkt->len += 14;

  // assume ipv4
  (*pkt)[12] = 0x08;
  (*pkt)[13] = 0x00;

  if (!ether_emu.tun_to_tap (pkt))
    {
      delete pkt;
      return 0;
    }
#endif

  return pkt;
}

void
tap_device::send (tap_packet *pkt)
{
#if TEST_ETHEREMU
  if (ether_emu.tap_to_tun (pkt) &&
      write (fd, &((*pkt)[14]), pkt->len - 14) < 0)
#else
  if (write (fd, &((*pkt)[0]), pkt->len) < 0)
#endif
    slog (L_ERR, _("can't write to %s %s: %s"), info (), DEFAULT_DEVICE,
          strerror (errno));
}

