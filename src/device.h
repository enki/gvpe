/*
    device.h -- generic header for device.c
 
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

#ifndef VPE_DEVICE_H__
#define VPE_DEVICE_H__

#include "config.h"

#include <cstdlib>

#include <net/if.h>

#include "gettext.h"

#include "global.h"

struct net_packet {
  u32 len; // actually u16, but padding...

  u8 &operator[] (u16 offset);

  bool is_arp ()
    {
      return (*this)[12] == 0x08 && (*this)[13] == 0x06		// 0806 protocol
          && (*this)[14] == 0x00 && (*this)[15] == 0x01		// 0001 hw_format
          && (*this)[16] == 0x08 && (*this)[17] == 0x00		// 0800 prot_format
          && (*this)[18] == 0x06 && (*this)[19] == 0x04;	// 06 hw_len 04 prot_len
    }

  void *operator new (size_t s);
  void operator delete (void *p);
};

struct data_packet : net_packet {
  u8 data_[MAXSIZE];
};

inline 
u8 &net_packet::operator[] (u16 offset)
{
  return ((data_packet *)this)->data_[offset];
}

typedef u8 mac[6];

struct tap_packet : net_packet {
  mac dst;
  mac src;
  u8 data[MAXSIZE - 12];
};

struct tap_device {
  int fd;

  // linux tuntap
  char ifrname[IFNAMSIZ + 1];

  char *device;

  tap_device ();
  ~tap_device ();

  const char *interface () { return ifrname; }
  const char *info () { return _("Linux tun/tap device"); }

  tap_packet *recv ();
  void send (tap_packet *pkt);
};

#endif

