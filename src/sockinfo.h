/*
    sockinfo.h -- socket address management

    Copyright (C) 2003 Marc Lehmann <pcg@goof.com>
 
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

#ifndef VPE_SOCKINFO_H__
#define VPE_SOCKINFO_H__

#include <sys/socket.h>
#include <netinet/in.h>

#include "conf.h"

// encapsulate one or more network addresses. this structure
// gets transferred over the wire, so be careful with endianness etc.
struct sockinfo
  {
    u32 host;
    u16 port;
    u8 prot;
    u8 pad1;

    void set (const sockaddr_in *sa, u8 prot_);
    void set (const conf_node *conf, u8 prot_);
    void set (const char *hostname, u16 port_, u8 prot_);

    // return the supported protocols
    u8 supported_protocols (conf_node *conf = 0);
    bool upgrade_protocol (u8 prot_, conf_node *conf = 0);

    operator const char *() const;

    const sockaddr *sav4 () const;
    const socklen_t salenv4 () const
      { return sizeof (sockaddr_in); }

    const char *ntoa () const;

    bool valid () const
      { return prot != 0 && host != 0; }

    sockinfo() { prot = 0; }

    sockinfo(const sockaddr_in &sa, u8 prot)
      { set (&sa, prot); }

    sockinfo(const conf_node *conf, u8 prot)
      { set (conf, prot); }
  };

bool operator == (const sockinfo &a, const sockinfo &b);
bool operator < (const sockinfo &a, const sockinfo &b);

#endif

