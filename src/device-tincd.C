/*
    device-tincd.C -- include one of the tincd low level implementations.
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

#define xstrdup(strd) strdup(str)

/* make the tincd sources feel comfortable in our environment. */
/* this was reasonably easy to do. */
#define routing_mode 1
#define RMODE_ROUTER 0

#define LOG_TO_L(level)				\
    (level) == LOG_ERR     ? L_ERR		\
  : (level) == LOG_DEBUG   ? L_DEBUG		\
  : (level) == LOG_WARNING ? L_WARN		\
  : (level) == LOG_INFO    ? L_INFO		\
                           : L_NOTICE

#if __STDC_VERSION__ > 199900
# define logger(level, ...) slog (LOG_TO_L(level), __VA_ARGS__)
#elif __GNUC__
# define logger(level, args...) slog (LOG_TO_L(level), ## args)
#else
# error either need ISO-C 99 compliant compiler or gcc.
#endif

#define ifdebug(subsys) if (0)

#define cp()
#define lookup_config(config_tree,key) (key)

#define MTU MAX_MTU

// BIGGEST hack of 'em all
// will be casted to data_packet, due to structural similarity
struct vpn_packet_t : net_packet
{
  u8 data[MAXSIZE];
};

static bool overwrite_mac;

static bool
get_config_string(const char *key, char **res)
{
  if (!strcmp (key, "Interface"))
    *res = conf.ifname;
  else if (!strcmp (key, "Device"))
    *res = 0;
  else if (!strcmp (key, "DeviceType"))
    *res = "tap";
  else
    {
      slog (L_ERR, _("tincd layer asking for unknown config '%s'"), key);
      *res = 0;
    }

  return *res;
}

#define netname conf.ifname

#if IF_linux
# include "tincd/linux/device.c"
const char * tap_device::if_up () { return "/sbin/ifconfig $IFNAME hw ether $MAC mtu $MTU"; }

#elif IF_bsd
# include "tincd/bsd/device.c"
const char * tap_device::if_up () { return "/sbin/ifconfig $IFNAME ether $MAC mtu $MTU"; }

#elif IF_freebsd
# include "tincd/freebsd/device.c"
const char * tap_device::if_up () { return "/sbin/ifconfig $IFNAME ether $MAC mtu $MTU"; }

#elif IF_netbsd
# define IF_istun 1
# include "tincd/netbsd/device.c"
const char * tap_device::if_up () { return "/sbin/ifconfig $IFNAME mtu $MTU"; }

#elif IF_openbsd
# define IF_istun 1
# include "tincd/openbsd/device.c"
const char * tap_device::if_up () { return "/sbin/ifconfig $IFNAME mtu $MTU"; }

#elif IF_solaris
# define IF_istun 1
# include "tincd/solaris/device.c"
const char * tap_device::if_up () { return ""; }

#elif IF_cygwin
# include "tincd/cygwin/device.c"
const char * tap_device::if_up () { return ""; }

#elif IF_mingw
# include "tincd/mingw/device.c"
const char * tap_device::if_up () { return ""; }

#elif IF_darwin
# define IF_istun 1
# include "tincd/darwin/device.c"
const char * tap_device::if_up () { return "/sbin/ifconfig $IFNAME ether $MAC mtu $MTU"; }

#elif IF_raw_socket
# include "tincd/raw_socket/device.c"
const char * tap_device::if_up () { return "/sbin/ifconfig $IFNAME ether $MAC mtu $MTU"; }

#elif IF_uml_socket
# include "tincd/uml_socket/device.c"
const char * tap_device::if_up () { return 0; }

#else
# error No interface implementation for your IFTYPE/IFSUBTYPE combination.
#endif

#if IF_istun
# include "ether_emu.C"
#endif

const char *
tap_device::info ()
{
  return _("tincd compatibility layer");
}

tap_device::tap_device ()
{
  device = "(null)";

  bool ok = setup_device ();

  if (device_info)
    device = device_info;

  if (ok)
    {
      slog (L_DEBUG, _("interface %s on %s initialized"), info (), device);
      fd = device_fd;
      strcpy (ifrname, iface);
    }
  else
    {
      slog (L_ERR, _("error while configuring tincd device %s on %s"), info (), device);
      exit (EXIT_FAILURE);
    }
}

tap_device::~tap_device ()
{
  close_device ();
}

tap_packet *
tap_device::recv ()
{
  tap_packet *pkt = new tap_packet;

  if (!read_packet (reinterpret_cast<vpn_packet_t *>(pkt)))
    {
      delete pkt;
      slog (L_ERR, _("can't read from to %s %s: %s"), info (), device,
            strerror (errno));
      return 0;
    }
    
#if IF_istun
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
  if (
#if IF_istun
      ether_emu.tap_to_tun (pkt) &&
#endif
      !write_packet (reinterpret_cast<vpn_packet_t *>(pkt)))
    slog (L_ERR, _("can't write to %s %s: %s"), info (), device,
          strerror (errno));
}
    
