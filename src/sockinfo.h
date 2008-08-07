/*
    sockinfo.h -- socket address management
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

#ifndef GVPE_SOCKINFO_H__
#define GVPE_SOCKINFO_H__

#include "netcompat.h"

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
  {
    return sizeof (sockaddr_in);
  }

  const char *ntoa () const;

  bool valid () const
  {
    return prot != 0 && host != 0;
  }

  sockinfo() { prot = 0; }

  sockinfo(const char *hostname, u16 port, u8 prot) { set (hostname, port, prot); }
  sockinfo(const sockaddr_in &sa, u8 prot)          { set (&sa, prot);            }
  sockinfo(const conf_node *conf, u8 prot)          { set (conf, prot);           }
};

bool operator == (const sockinfo &a, const sockinfo &b);
bool operator <  (const sockinfo &a, const sockinfo &b);

inline bool operator != (const sockinfo &a, const sockinfo &b)
{
  return !(a == b);
}

#endif

