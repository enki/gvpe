/*
    ROHC Project 2003 at Lulea University of Technology, Sweden.
    Authors: Andreas Vernersson <andver-8@student.luth.se>
             Daniel Pettersson <danpet-7@student.luth.se>
             Erik Soderstrom <soderstrom@yahoo.com>
             Fredrik Lindstrom <frelin-9@student.luth.se>
             Johan Stenmark <johste-8@student.luth.se>
             Martin Juhlin <juhlin@users.sourceforge.net>
             Mikael Larsson <larmik-9@student.luth.se>
             Robert Maxe <robmax-1@student.luth.se>
             
    Copyright (C) 2003 Andreas Vernersson, Daniel Pettersson, 
    Erik Soderström, Fredrik Lindström, Johan Stenmark, 
    Martin Juhlin, Mikael Larsson, Robert Maxe.  

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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/    
#ifndef _D_UDP_LITE_H
#define _D_UDP_LITE_H

#include "rohc.h"
#include "decomp.h"
#include "d_util.h"


struct s_udp_lite_change
{
	int rnd;
	int nbo;

	struct iphdr ip;
	struct udphdr udp;
};

struct s_udp_lite_profile_data
{
	struct s_udp_lite_change * last1;
	struct s_udp_lite_change * last2;
	struct s_udp_lite_change * active1;
	struct s_udp_lite_change * active2;

	struct sd_lsb_decode sn;
	struct sd_ip_id_decode ip_id1;
	struct sd_ip_id_decode ip_id2;

	int multiple_ip;

	// udp-lite checksum coverage field present or not
	int coverage_present;

	// if inferred then udp-lite == udp otherwise use
	// the value stored i udphdr length field which is
	// supposed to be the checksum coverage field in
	// udp-lite.
	// this matters only when coverage_present == 0
	int coverage_inferred;

	int ce_packet;
	int package_type;

	int counter;
	int last_packet_time; //the time of the last crc-approved packet
	int current_packet_time; //the time of the current packet without crc-test yet
	int inter_arrival_time; //a average inter-packet time of the last few packets,
};

struct s_profile * udp_lite_profile_create(void);

#endif
