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
#ifndef _D_UTIL_H
#define _D_UTIL_H

#include "rohc.h"

#define OLD_REF_VALUE   0
#define LAST_REF_VALUE  1

// IP-id struct
struct sd_ip_id_decode
{
	int id_ref;
	int sn_ref;
};

// Least Significant Bits decoding
struct sd_lsb_decode
{
	int v_ref_d;
	int old_v_ref_d;
	int p;
};
// initiate the ip-id struct 
// in: the ip-id struct, the reference for ip-id, the sequenze number  
void d_ip_id_init(struct sd_ip_id_decode * s,int id_ref, int sn_ref);

// Decode the ip-id offset in packet m and return the ip_id
// Do not forget to update the id_ref and sn_ref after a crc-success
// in: the ip-id struct, the packet m containing the ip-id offset, the
//     length of the offset and the sequence number of packet m.
// out:ip_id
int d_ip_id_decode(struct sd_ip_id_decode * s, int m, int length, int sn);

// update the reference values for the ip-id and the sequence number
void d_ip_id_update(struct sd_ip_id_decode * s, int id_ref, int sn_ref);

// update the reference value
void d_lsb_update(struct sd_lsb_decode * s, int v_ref_d);

// copy the value in v_ref_d to old_v_ref_d
void d_lsb_sync_ref(struct sd_lsb_decode * s);

// get the old value of v_ref_d
int d_get_lsb_old_ref(struct sd_lsb_decode * s);

// Decode a LSB-value, do not forget to update the v_ref_d after a CRC-success
// in: the struct were the old received value is present
//     the LSB-value to decode and the length of it in bits
//
// out:the decoded value
int d_lsb_decode(struct sd_lsb_decode * s, int m,int length);

// Initiate the lsb struct
// in: the value of v_ref_d and type of p value
void d_lsb_init(struct sd_lsb_decode * s,int v_ref_d, int p);

// get the reference value
int d_get_lsb_ref(struct sd_lsb_decode * s);

// Decide if the field is a padding field
// Return: 1 = padding
//	   0 = else
int d_is_paddning(const unsigned char *);

// Decide if the field is a feedback field
// Return: 1 = feedback header
//	   0 = else
int d_is_feedback(const unsigned char *);

// Decide if the field is a segment field
// Return: 1 = segment
//	   0 = else
int d_is_segment(const unsigned char *);

// Return the size of the feedback
// In: Bytes of a feedback header
// Out: Size 
int d_feedback_size(const unsigned char *);

// Decide how many bytes the feedback header is
// In: Bytes of a feedback header
// Out: the size in bytes (1-2)
int d_feedback_headersize(const unsigned char *);

// Check if a byte is a add-cid value 
// It is also possible to use d_decode_add_cid instead.
// In: Bytes
// Out: 1 = Add-cid value
//	0 = else
int d_is_add_cid(const unsigned char *);

// Decode the add-cid value
// In: Bytes
// Out:	1-15, cid value
//	0, no cid value
int d_decode_add_cid(const unsigned char *);

// Decide if a byte is a ir-field
// In: Bytes
// Out: 1 = IR, 0 = else
int d_is_ir(const unsigned char *);

// Decide if a byte is a irdyn-field
// In: Bytes
// Out: 1 = IR-Dyn, 0 = else
int d_is_irdyn(const unsigned char *);

// Decide the size of the self-decsribing variable-length value
// In: Bytes
// Out: 1-4
int d_sdvalue_size(const unsigned char *);

// Decode a self-describing variable-length value
// In: Bytes
// Out: The self-describing variable-length value
int d_sdvalue_decode(const unsigned char *);

// Decode the static part of a ipv4 rohc packet and store it in a ip-structure
// Return the number of used bytes
int d_decode_static_ip4(const unsigned char *, struct iphdr * dest);

// Decode the static part in a udp rohc packet and store it in a udp-structure
// Return the number of used bytes
int d_decode_static_udp(const unsigned char *, struct udphdr * dest);

// Decode the dynamic part in a ipv4 rohc packet and store it in a ip-structure
// Return the number of used bytes
int d_decode_dynamic_ip4(const unsigned char *, struct iphdr * dest, int * rnd, int * nbo);

// Decode the dynamic part in a udp rohc packet and store it in a udp-structure
// Return the number of used bytes
int d_decode_dynamic_udp(const unsigned char *, struct udphdr * dest);

// Decode the dynamic part in a udp-lite rohc packet and store it in a udp-structure
// Return the number of used bytes
int d_decode_dynamic_udp_lite(const unsigned char *data, struct udphdr * dest);

#endif










