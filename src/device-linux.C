/*
    device-linux.C -- Interaction with Linux tun/tap device
 
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
#include <cstdlib>

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/ioctl.h>

#ifdef LINUX_IF_TUN_H
#include LINUX_IF_TUN_H
#else
#include <linux/if_tun.h>
#endif
#define DEFAULT_DEVICE "/dev/net/tun"

#include "gettext.h"

#include "conf.h"

tap_device::tap_device ()
{
  struct ifreq ifr;

  device = DEFAULT_DEVICE;

  fd = open (device, O_RDWR);

  if (fd < 0)
    {
      slog (L_ERR, _("could not open device %s: %s"), device, strerror (errno));
      exit (1);
    }

  memset (&ifr, 0, sizeof (ifr));
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

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
      slog (L_CRIT, _("unable to configure tun/tap interface: %s"), strerror (errno));
      exit (1);
    }

  if (conf.ifpersist)
    if (ioctl (fd, TUNSETPERSIST, 1))
      slog (L_WARN, _("cannot set persistent mode for device %s: %s"), ifrname, strerror (errno));

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

  pkt->len = read (fd, &((*pkt)[0]), MAX_MTU);

  if (pkt->len <= 0)
    {
      slog (L_ERR, _("error while reading from %s %s: %s"),
            info (), DEFAULT_DEVICE, strerror (errno));
      free (pkt);
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

