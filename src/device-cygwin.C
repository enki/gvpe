/*
    device-cygwin.C -- Stub for Cygwin environment
    Copyright (C) 2003 Marc Lehmann <ocg@goof.com>
    Copyright (C) 2002-2003 Ivo Timmermans <ivo@o2w.nl>,
                  2002-2003 Guus Sliepen <guus@sliepen.eu.org>

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
// a newer driver is available as part of the openvpn package:
// http://openvpn.sf.net/

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

#include <w32api/windows.h>
#include <w32api/winioctl.h>

#define REG_CONTROL_NET      "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define USERMODEDEVICEDIR "\\\\.\\"
#define USERDEVICEDIR "\\??\\"
#define TAPSUFFIX     ".tap"

#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD | 8000, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_LASTMAC    TAP_CONTROL_CODE(0, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MAC        TAP_CONTROL_CODE(1, METHOD_BUFFERED)
#define TAP_IOCTL_SET_STATISTICS TAP_CONTROL_CODE(2, METHOD_BUFFERED)

static HANDLE device_handle = INVALID_HANDLE_VALUE;

static const char *
wstrerror (int err)
{
  static char buf[1024];

  if (!FormatMessage
      (FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err,
       MAKELANGID (LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof (buf), NULL))
    {
      strncpy (buf, _("(unable to format errormessage)"), sizeof (buf));
    };

  if ((char *newline = strchr (buf, '\r')))
    *newline = '\0';

  return buf;
}

const char *
tap_device::info ()
{
  return _("cygwin cipe/openvpn tap device");
}

tap_device::tap_device ()
{
  HKEY key, key2;
  int i;

  char regpath[1024];
  char adapterid[1024];
  char adaptername[1024];
  char tapname[1024];
  long len;

  bool found = false;

  int sock, err;

  /* Open registry and look for network adapters */

  if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, REG_CONTROL_NET, 0, KEY_READ, &key))
    {
      slog (L_ERR, _("Unable to read registry: %s"),
	    wstrerror (GetLastError ()));
      return false;
    }

  for (i = 0;; i++)
    {
      len = sizeof (adapterid);
      if (RegEnumKeyEx (key, i, adapterid, &len, 0, 0, 0, NULL))
	break;

      /* Find out more about this adapter */

      snprintf (regpath, sizeof (regpath), "%s\\%s\\Connection",
		REG_CONTROL_NET, adapterid);

      if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, regpath, 0, KEY_READ, &key2))
	continue;

      len = sizeof (adaptername);
      err = RegQueryValueEx (key2, "Name", 0, 0, adaptername, &len);

      RegCloseKey (key2);

      if (err)
	continue;

      if (strcmp (conf.ifname, adapterid))
        continue;

      found = true;
      break;

      snprintf (tapname, sizeof (tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX,
		adapterid);
      device_handle = CreateFile (tapname, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, indent: Standard input: 237: Error:Stmt nesting error.FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
				  0);
      if (device_handle != INVALID_HANDLE_VALUE)
	{
	  found = true;
	  break;
	}
    }

  RegCloseKey (key);

  if (!found)
    {
      slog (L_ERR, _("No Windows tap device found!"));
      return false;
    }

  if (!device)
    device = xstrdup (adapterid);

  if (!iface)
    iface = xstrdup (adaptername);

  /* Try to open the corresponding tap device */

  if (device_handle == INVALID_HANDLE_VALUE)
    {
      snprintf (tapname, sizeof (tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX,
		device);
      device_handle =
	CreateFile (tapname, GENERIC_WRITE | GENERIC_READ, 0, 0,
		    OPEN_EXISTING,
		    FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
    }

  if (device_handle == INVALID_HANDLE_VALUE)
    {
      slog (L_ERR, _("%s (%s) is not a usable Windows tap device: %s"),
	      device, iface, wstrerror (GetLastError ()));
      return false;
    }

  /* Get MAC address from tap device */

  if (!DeviceIoControl
      (device_handle, TAP_IOCTL_GET_MAC, mymac.x, sizeof (mymac.x), mymac.x,
       sizeof (mymac.x), &len, 0))
    {
      slog (L_ERR,
	      _
	      ("Could not get MAC address from Windows tap device %s (%s): %s"),
	      device, iface, wstrerror (GetLastError ()));
      return false;
    }

  if (routing_mode == RMODE_ROUTER)
    {
      overwrite_mac = 1;
    }

  /* Create a listening socket */

  err = getaddrinfo (NULL, myport, &hint, &ai);

  if (err || !ai)
    {
      slog (L_ERR, _("System call `%s' failed: %s"), "getaddrinfo",
	      gai_strerror (errno));
      return false;
    }

  sock = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol);

  if (sock < 0)
    {
      slog (L_ERR, _("System call `%s' failed: %s"), "socket",
	      strerror (errno));
      return false;
    }

  if (bind (sock, ai->ai_addr, ai->ai_addrlen))
    {
      slog (L_ERR, _("System call `%s' failed: %s"), "bind",
	      strerror (errno));
      return false;
    }

  freeaddrinfo (ai);

  if (listen (sock, 1))
    {
      slog (L_ERR, _("System call `%s' failed: %s"), "listen",
	      strerror (errno));
      return false;
    }

  /* Start the tap reader */

  thread = CreateThread (NULL, 0, tapreader, NULL, 0, NULL);

  if (!thread)
    {
      slog (L_ERR, _("System call `%s' failed: %s"), "CreateThread",
	      wstrerror (GetLastError ()));
      return false;
    }

  /* Wait for the tap reader to connect back to us */

  if ((device_fd = accept (sock, NULL, 0)) == -1)
    {
      slog (L_ERR, _("System call `%s' failed: %s"), "accept",
	      strerror (errno));
      return false;
    }

  closesocket (sock);

  device_info = _("Windows tap device");

  slog (L_INFO, _("%s (%s) is a %s"), device, iface, device_info);

  return true;
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
      if ((*pkt)[22] == 0x08)
	id2mac (THISNODE->id, &((*pkt)[22]));
      if ((*pkt)[32] == 0x08)
	id2mac (THISNODE->id, &((*pkt)[32]));
    }

  return pkt;
}

void
tap_device::send (tap_packet * pkt)
{
  (*pkt)[6] = 0x08;
  (*pkt)[7] = 0x00;
  (*pkt)[8] = 0x58;
  (*pkt)[9] = 0x00;
  (*pkt)[10] = 0x00;
  (*pkt)[11] = 0x01;

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

#if 0

slog (L_DEBUG, _indent: Standard input:377: Error:Stmt nesting error.
("Tap reader running"));

	/* Read from tap device and send to parent */

overlapped.hEvent = CreateEvent (NULL, TRUE, FALSE, NULL);

for indent
: Standard input: 320: Error:Stmt nesting error.(;;
  )
{
  overlapped.Offset = 0;
  overlapped.OffsetHigh = 0;
  ResetEvent (overlapped.hEvent);

  status = ReadFile (device_handle, buf, sizeof (buf), &len, &overlapped);

  if (!status)
    {
      if (GetLastError () == ERROR_IO_PENDING)
	{
	  WaitForSingleObject (overlapped.hEvent, INFINITE);
	  if (!GetOverlappedResult (device_handle, &overlapped, &len, FALSE))
	    continue;
	}
      else
	{
	  slog (L_ERR, _("Error while reading from %s %s: %s"),
		  device_info, device, strerror (errno));
	  return -1;
	}
    }

  if (send (sock, buf, len, 0) <= 0)
    return -1;
}
}

void
close_device (void)
{
  cp ();

  CloseHandle (device_handle);
}

bool
read_packet (vpn_packet_t * packet)
{
  int lenin;

  cp ();

  if ((lenin = recv (device_fd, packet->data, MTU, 0)) <= 0)
    {
      slog (L_ERR, _("Error while reading from %s %s: %s"), device_info,
	      device, strerror (errno));
      return false;
    }

  packet->len = lenin;

  device_total_in += packet->len;

  ifdebug (TRAFFIC) slog (L_DEBUG, _("Read packet of %d bytes from %s"),
			    packet->len, device_info);

  return true;
}

bool
write_packet (vpn_packet_t * packet)
{
  long lenout;
  OVERLAPPED overlapped = { 0 };

  cp ();

  ifdebug (TRAFFIC) slog (L_DEBUG, _("Writing packet of %d bytes to %s"),
			    packet->len, device_info);

  if (!WriteFile
      (device_handle, packet->data, packet->len, &lenout, &overlapped))
    {
      slog (L_ERR, _("Error while writing to %s %s: %s"), device_info,
	      device, wstrerror (GetLastError ()));
      return false;
    }

  device_total_out += packet->len;

  return true;
}

void
dump_device_stats (void)
{
  cp ();

  slog (L_DEBUG, _("Statistics for %s %s:"), device_info, device);
  slog (L_DEBUG, _(" total bytes in:  %10d"), device_total_in);
  slog (L_DEBUG, _(" total bytes out: %10d"), device_total_out);
}
#endif
