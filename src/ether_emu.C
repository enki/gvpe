/*
    ether_emu.C -- ethernet "emulator" library
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
    Foundation, Inc. 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "config.h"

#include <map>

#include "vpn.h"

extern struct vpn network;

struct ether_emu : map<u32, int> {
  typedef map<u32, int> ipv4map;
  ipv4map ipv4;

  bool tun_to_tap (tap_packet *pkt);
  bool tap_to_tun (tap_packet *pkt);

  void set_ipv4 (u32 ip, int dst)
    {
      (ipv4.insert (pair<u32, int>(ip, dst)).first)->second = dst;
    }
};

static struct ether_emu ether_emu;

bool 
ether_emu::tun_to_tap (tap_packet *pkt)
{
  int dst;

  if (pkt->is_ipv4 ())
    {
      // update arp cache for _local_ hosts
      set_ipv4 (pkt->ipv4_src (), THISNODE->id);

      ipv4map::iterator i = ipv4.find (pkt->ipv4_dst ());

      if (i == ipv4.end ())
        {
          u32 ip_src = pkt->ipv4_src ();
          u32 ip_dst = pkt->ipv4_dst ();

          // throw away current packet and make it an arp request
          (*pkt)[12] = 0x08; (*pkt)[13] = 0x06;
          (*pkt)[14] = 0x00; (*pkt)[15] = 0x01; // hw
          (*pkt)[16] = 0x08; (*pkt)[17] = 0x00; // prot
          (*pkt)[18] = 0x06; // hw_len
          (*pkt)[19] = 0x04; // prot_len
          (*pkt)[20] = 0x00; (*pkt)[21] = 0x01; // op

          id2mac (THISNODE->id, &(*pkt)[22]);
          *(u32 *)&(*pkt)[28] = ip_src;
          id2mac (0, &(*pkt)[32]);
          *(u32 *)&(*pkt)[38] = ip_dst;

          pkt->len = 42;

          dst = 0;
        }
      else
        dst = i->second;
    }
  else
    dst = 0; // broadcast non-ip

  id2mac (THISNODE->id, pkt->src);
  id2mac (dst, pkt->dst);

  return true;
}

bool 
ether_emu::tap_to_tun (tap_packet *pkt)
{
  if (pkt->is_arp ())
    {
      u32 ip_src = *(u32 *)&(*pkt)[28];

      // always update with all info we can get. in this case, the arp sender.
      set_ipv4 (ip_src, mac2id (&(*pkt)[22]));

      //TODO: remove cache dumper
      //for (ipv4map::iterator i = ipv4.begin (); i != ipv4.end (); ++i) printf ("%08lx => %d\n", i->first, i->second);

      if ((*pkt)[20] == 0x00 && (*pkt)[21] == 0x01) // arp request
        {
          // send a reply, if applicable
          u32 ip_dst = *(u32 *)&(*pkt)[38];
          ipv4map::iterator i = ipv4.find (ip_dst);
          
          // TODO: look up list of local networks and answer for them
          if (i != ipv4.end () && i->second == THISNODE->id)
            {
              // create an arp reply
              tap_packet *rep = new tap_packet;

              id2mac (THISNODE->id, rep->src);
              memcpy (rep->dst, pkt->src, sizeof (mac));

              (*rep)[12] = 0x08; (*rep)[13] = 0x06;
              (*rep)[14] = 0x00; (*rep)[15] = 0x01; // hw
              (*rep)[16] = 0x08; (*rep)[17] = 0x00; // prot
              (*rep)[18] = 0x06; // hw_len
              (*rep)[19] = 0x04; // prot_len
              (*rep)[20] = 0x00; (*rep)[21] = 0x02; // op

              id2mac (THISNODE->id, &(*rep)[22]);
              *(u32 *)&(*rep)[28] = ip_dst;
              memcpy (&(*rep)[32], &(*pkt)[22], sizeof (mac));
              *(u32 *)&(*rep)[38] = ip_src;

              rep->len = 42;

              network.inject_data_packet (rep, mac2id (rep->dst));

              delete rep;
            }
        }
      else if ((*pkt)[20] == 0x00 && (*pkt)[21] == 0x02) // arp reply
        set_ipv4 (*(u32 *)&(*pkt)[28], mac2id (&(*pkt)[22]));

      return false;
    }
  else if (pkt->is_ipv4 ())
    {
      // update arp cache
      set_ipv4 (pkt->ipv4_src (), mac2id (pkt->src));
      set_ipv4 (pkt->ipv4_dst (), mac2id (pkt->dst));
    }

  return true;
}

