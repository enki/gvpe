/*
    device-cygwin.C -- Stub for Cygwin environment
    Copyright (C) 2003-2004 Marc Lehmann <ocg@goof.com>
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
#include <cstring>

#include "conf.h"
#include "util.h"

#include <io.h>
#include <w32api/windows.h>
#include <w32api/winioctl.h>

#define REG_CONTROL_NET      "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}"

#define USERMODEDEVICEDIR "\\\\.\\"
#define USERDEVICEDIR "\\??\\"
#define TAPSUFFIX     ".tap"

#define TAP_CONTROL_CODE(request,method) CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD | 8000, request, method, FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_LASTMAC      TAP_CONTROL_CODE(0, METHOD_BUFFERED)
#define TAP_IOCTL_GET_MAC          TAP_CONTROL_CODE(1, METHOD_BUFFERED)
#define TAP_IOCTL_SET_STATISTICS   TAP_CONTROL_CODE(2, METHOD_BUFFERED)
#define TAP_IOCTL_SET_MEDIA_STATUS TAP_CONTROL_CODE(7, METHOD_BUFFERED)

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

  char *nl;
  if ((nl = strchr (buf, '\r')))
    *nl = '\0';

  return buf;
}

static HANDLE device_handle = INVALID_HANDLE_VALUE;
static mac local_mac;
static tap_packet *rcv_pkt;
static int iopipe[2];
static HANDLE pipe_handle, send_event, thread;

static DWORD WINAPI
read_thread(void *)
{
  static OVERLAPPED overlapped;
  static DWORD dlen;
  static u32 len;
  static u8 data[MAX_MTU];

  overlapped.hEvent = CreateEvent (NULL, FALSE, FALSE, NULL);

  for (;;)
    {
      if (!ReadFile (device_handle, data, MAX_MTU, &dlen, &overlapped))
        {
          if (GetLastError () == ERROR_IO_PENDING)
            GetOverlappedResult (device_handle, &overlapped, &dlen, TRUE);
          else
            {
              slog (L_ERR, "WIN32 TAP: ReadFile returned error: %s", wstrerror (GetLastError ()));
              exit (1);
            }
        }

      if (dlen > 0)
        {
          len = dlen;
          WriteFile (pipe_handle, &len, sizeof (len), &dlen, NULL);
          WriteFile (pipe_handle, data, len, &dlen, NULL);
        }
    }
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
  BYTE adaptername[1024];
  char tapname[1024];
  DWORD len;

  bool found = false;

  int sock, err;

  /* Open registry and look for network adapters */

  if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, REG_CONTROL_NET, 0, KEY_READ, &key))
    {
      slog (L_ERR, _("WIN32 TAP: unable to read registry: %s"),
	    wstrerror (GetLastError ()));
      exit (1);
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

      if (conf.ifname)
        {
          if (strcmp (conf.ifname, adapterid))
            continue;
        }
      else
        {
          found = true;
          break;
        }

      snprintf (tapname, sizeof (tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX, adapterid);
      device_handle = CreateFile(tapname, GENERIC_WRITE | GENERIC_READ, 0, 0,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
      if (device_handle != INVALID_HANDLE_VALUE)
	{
	  found = true;
	  break;
	}
    }

  RegCloseKey (key);

  if (!found)
    {
      slog (L_ERR, _("WIN32 TAP: no windows tap device found!"));
      exit (1);
    }

  /* Try to open the corresponding tap device */

  if (device_handle == INVALID_HANDLE_VALUE)
    {
      snprintf (tapname, sizeof (tapname), USERMODEDEVICEDIR "%s" TAPSUFFIX, adapterid);
      device_handle =
	CreateFile (tapname, GENERIC_WRITE | GENERIC_READ, 0, 0,
		    OPEN_EXISTING,
		    FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0);
    }

  if (device_handle == INVALID_HANDLE_VALUE)
    {
      slog (L_ERR, _("WIN32 TAP: %s is not a usable windows tap device %s: %s"),
	      adaptername, tapname, wstrerror (GetLastError ()));
      exit (1);
    }

  strcpy (ifrname, (char *)tapname);

  /* Get MAC address from tap device */

  if (!DeviceIoControl (device_handle, TAP_IOCTL_GET_MAC,
                        &local_mac, sizeof (local_mac), &local_mac, sizeof (local_mac),
                        &len, 0))
    {
      slog (L_ERR,
	      _("WIN32 TAP: could not get MAC address from windows tap device %s: %s"),
	      adaptername, wstrerror (GetLastError ()));
      exit (1);
    }

  pipe (iopipe);
  fd = iopipe[0];
  pipe_handle = (HANDLE) get_osfhandle (iopipe[1]);

  send_event = CreateEvent (NULL, FALSE, FALSE, NULL);

  thread = CreateThread (NULL, 0, read_thread, NULL, 0, NULL);

  /* try to set driver media status to 'connected' */
  ULONG status = TRUE;
  DeviceIoControl (device_handle, TAP_IOCTL_SET_MEDIA_STATUS,
                   &status, sizeof (status),
                   &status, sizeof (status), &len, NULL);
  // ignore error here on purpose
}

tap_device::~tap_device ()
{
  close (iopipe[0]);
  close (iopipe[1]);
  CloseHandle (device_handle);
  CloseHandle (send_event);
}

tap_packet *
tap_device::recv ()
{
  tap_packet *pkt = new tap_packet;

  if (sizeof (u32) != read (iopipe[0], &pkt->len, sizeof (u32)))
    {
      slog (L_ERR, _("WIN32 TAP: i/o thread delivered incomplete pkt length"));
      delete pkt;
      return 0;
    }
    
  if (pkt->len != read (iopipe[0], &((*pkt)[0]), pkt->len))
    {
      slog (L_ERR, _("WIN32 TAP: i/o thread delivered incomplete pkt"));
      delete pkt;
      return 0;
    }
    
  id2mac (THISNODE->id, &((*pkt)[6]));

  if (pkt->is_arp ())
    {
      if (!memcmp (&(*pkt)[22], &local_mac, sizeof (mac))) id2mac (THISNODE->id, &((*pkt)[22]));
      if (!memcmp (&(*pkt)[32], &local_mac, sizeof (mac))) id2mac (THISNODE->id, &((*pkt)[32]));
    }

  return pkt;
}

void
tap_device::send (tap_packet * pkt)
{
  memcpy (&(*pkt)[6], &local_mac, sizeof (mac));

  if (pkt->is_arp ())
    {
      if ((*pkt)[22] == 0xfe && (*pkt)[27] == THISNODE->id)
	memcpy (&(*pkt)[22], &local_mac, sizeof (mac));

      if ((*pkt)[32] == 0xfe && (*pkt)[37] == THISNODE->id)
	memcpy (&(*pkt)[32], &local_mac, sizeof (mac));
    }

  DWORD dlen;
  OVERLAPPED overlapped;
  overlapped.hEvent = send_event;

  if (!WriteFile (device_handle, &((*pkt)[0]), pkt->len, &dlen, &overlapped))
    {
      if (GetLastError () == ERROR_IO_PENDING)
        GetOverlappedResult (device_handle, &overlapped, &dlen, TRUE);
      else
        slog (L_ERR, _("WIN32 TAP: can't write to %s %s: %s"), info (), conf.ifname,
              wstrerror (GetLastError ()));
    }
}
