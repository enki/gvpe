/*
    device.h -- generic header for device.c
    Copyright (C) 2003-2005 Marc Lehmann <gvpe@schmorp.de>
 
    This file is part of GVPE.

    GVPE is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.
 
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
 
    You should have received a copy of the GNU General Public License
    along with gvpe; if not, write to the Free Software
    Foundation, Inc. 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef GVPE_DEVICE_H__
#define GVPE_DEVICE_H__

#include "config.h"

#define IFNAMESIZE 256 // be conservative

#include "global.h"
#include "util.h"

struct net_packet {
  u32 len; // actually u16, but padding...

  u8 &operator[] (u16 offset) const;
  u8 *at (u16 offset) const;

  void unshift_hdr (u16 hdrsize)
    {
      memmove ((void *)&(*this)[hdrsize], (void *)&(*this)[0], len);
      len += hdrsize;
    }

  void skip_hdr (u16 hdrsize)
    {
      len -= hdrsize;
      memmove ((void *)&(*this)[0], (void *)&(*this)[hdrsize], len);
    }

  void set (const net_packet &pkt)
    {
      len = pkt.len;
      memcpy (&((*this)[0]), &(pkt[0]), len);
    }

  bool is_ipv4 () const
    {
      return (*this)[12] == 0x08 && (*this)[13] == 0x00 // IP
          && ((*this)[14] & 0xf0) == 0x40;              // IPv4
    }

  u32 &ipv4_src () const
    {
      return *(u32 *)&(*this)[26];
    }
  
  u32 &ipv4_dst () const
    {
      return *(u32 *)&(*this)[30];
    }
  
  bool is_arp () const
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
u8 &net_packet::operator[] (u16 offset) const
{
  return ((data_packet *)this)->data_[offset];
}

inline 
u8 *net_packet::at (u16 offset) const
{
  return &((*this)[offset]);
}

struct tap_packet : net_packet {
  mac dst;
  mac src;
  u8 data[MAXSIZE - 12];
};

struct tap_device {
  int fd;

  // network interface name or identifier
  char ifrname[IFNAMESIZE + 1];

  char *device;

  tap_device ();
  ~tap_device ();

  //bool open ();
  //void close ();

  const char *interface () { return ifrname; }
  const char *info ();

  tap_packet *recv ();
  void send (tap_packet *pkt);
};

//extern tap_device *tap_device ();

#endif

