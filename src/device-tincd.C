/*
    device-tincd.C -- include one of the tincd low level implementations.
 
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

#define routing_mode 1
#define RMODE_ROUTER 0

/* need iso c-90 or ugly workaround :( */
#define logger(level, ...) slog (		\
    (level) == LOG_ERR     ? L_ERR		\
  : (level) == LOG_DEBUG   ? L_DEBUG		\
  : (level) == LOG_WARNING ? L_WARN		\
  : (level) == LOG_INFO    ? L_INFO		\
                           : L_NOTICE, __VA_ARGS__)

#define ifdebug(subsys) if (0)

#define cp()
#define lookup_config(config_tree,key) (key)

#define MTU MAXSIZE

// BIGGEST hack of 'em all
// will be casted to data_packet, due to structural similarity
struct vpn_packet_t : net_packet {
  u8 data[MAXSIZE];
};

static tap_device *self;

static bool overwrite_mac;

static bool
get_config_string(const char *key, char **res)
{
  if (!strcmp (key, "Interface"))
    *res = conf.ifname;
  else if (!strcmp (key, "Device"))
    *res = 0;
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
#elif IF_freebsd
# include "tincd/freebsd/device.c"
#elif IF_netbsd
# include "tincd/netbsd/device.c"
#elif IF_solaris
# include "tincd/solaris/device.c"
#elif IF_cygwin
# include "tincd/cygwin/device.c"
#elif IF_mingw
# include "tincd/mingw/device.c"
#elif IF_darwin
# include "tincd/darwin/device.c"
#elif IF_raw_socket
# include "tincd/raw_socket/device.c"
#else
# error No interface implementation for your IFTYPE/IFSUBTYPE combination.
#endif

const char *
tap_device::info ()
{
  return _("tincd compatibility layer");
}

tap_device::tap_device ()
{
  self = this;

  if (setup_device ())
    {
      //slog (L_DEBUG, _("%s is a %s"), device, info ());
      fd = device_fd;
      strcpy (ifrname, iface);
    }
  else
    {
      slog (L_ERR, _("error while configuring tincd device (%s/%s)"), device, info ());
      exit (1);
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
      slog (L_ERR, _("can't read from to %s %s: %s"), info (), DEFAULT_DEVICE,
            strerror (errno));
      return 0;
    }
    
  return pkt;
}

void
tap_device::send (tap_packet *pkt)
{
  if (!write_packet (reinterpret_cast<vpn_packet_t *>(pkt)))
    slog (L_ERR, _("can't write to %s %s: %s"), info (), DEFAULT_DEVICE,
          strerror (errno));
}
    

