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
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/    
#ifndef _D_IP_H
#define _D_IP_H

#include <linux/ip.h>
#include "rohc.h"
#include "decomp.h"
#include "d_util.h"

struct s_iponly_change
{
	int rnd;
	int nbo;

	struct iphdr ip;
};

struct s_iponly_profile_data
{
	struct s_iponly_change * last1;
	struct s_iponly_change * last2;
	struct s_iponly_change * active1;
	struct s_iponly_change * active2;

	struct sd_lsb_decode sn;
	struct sd_ip_id_decode ip_id1;
	struct sd_ip_id_decode ip_id2;

	// multiple ip-header if multiple_ip=1
	int multiple_ip;
//	struct type_timestamp	sn;
//	struct type_ipid	ipid;
	int package_type;

	int counter;
	int last_packet_time; //the time of the last crc-approved packet
	int current_packet_time; //the time of the current packet without crc-test yet
	int inter_arrival_time; //a average inter-packet time of the last few packets,
};

struct s_profile * iponly_profile_create(void);

#endif
