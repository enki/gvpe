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

#include "d_util.h"

static const unsigned char D_PADDING = 0xe0;
static const unsigned char D_ADD_CID = 0xe;
static const unsigned char D_FEEDBACK = 0xf0 >> 3;
static const unsigned char D_IR_DYN_PACKET = 0xf8;
static const unsigned char D_IR_PACKET = 0xfc >> 1;
static const unsigned char D_SEGMENT = 0xfe >> 1;

// Decide if the field is a segment field
// Return: 1 = segment
//	   0 = else
int d_is_segment(const unsigned char *data)
{
	if (GET_BIT_1_7(data) == D_SEGMENT)
		return 1;
	return 0;
}


// Decide if the field is a padding field
// Return: 1 = padding
//	   0 = else
int d_is_paddning(const unsigned char *data)
{
	if (GET_BIT_0_7(data) == D_PADDING)
		return 1;
	return 0;
}

// Decide if the field is a feedback field
// Return: 1 = feedback header
//	   0 = else
int d_is_feedback(const unsigned char *data)
{
	if (GET_BIT_3_7(data) == D_FEEDBACK)
		return 1;
	return 0;
}

// Return the size of the feedback
// In: Bytes of a feedback header
// Out: Size 
int d_feedback_size(const unsigned char *data)
{
	if(GET_BIT_0_2(data)!=(0x0 >> 1))
		return GET_BIT_0_2(data);
	else{
		data++; //change data to point on the next field
		return GET_BIT_0_7(data);
	}
}

// Decide how many bytes the feedback header is
// In: Bytes of a feedback header
// Out: the size in bytes (1-2)
int d_feedback_headersize(const unsigned char *data)
{
	if(GET_BIT_0_2(data)==(0x0 >> 1) )
		return 2;
	return 1;
}

// Check if a byte is a add-cid value 
// It is also possible to use d_decode_add_cid instead.
// In: Bytes
// Out: 1 = Add-cid value
//	0 = else
int d_is_add_cid(const unsigned char *data)
{
	if (GET_BIT_4_7(data) == D_ADD_CID)
		return 1;
	return 0;
}

// Decode the add-cid value
// In: Bytes
// Out:	1-15, cid value
//	0, no cid value
int d_decode_add_cid(const unsigned char *data)
{
	if (GET_BIT_4_7(data) == D_ADD_CID)
		return GET_BIT_0_3(data);
	return 0;
}

// Decide if a byte is a ir-field
// In: Bytes
// Out: 1 = IR, 0 = else
int d_is_ir(const unsigned char *data)
{
	if (GET_BIT_1_7(data) == D_IR_PACKET)
		return 1;
	return 0;
}

// Decide if a byte is a irdyn-field
// In: Bytes
// Out: 1 = IR-Dyn, 0 = else
int d_is_irdyn(const unsigned char *data)
{
	if (GET_BIT_0_7(data) == D_IR_DYN_PACKET)
		return 1;
	return 0;
}

// Decide the size of the self-decsribing variable-length value
// In: Bytes
// Out: 1-4
int d_sdvalue_size(const unsigned char *data)
{
	if(!GET_BIT_7( data ))                   //bit  == 0
		return 1;
	else if(GET_BIT_6_7(data) == (0x8 >> 2)) //bits == 10
		return 2;
	else if(GET_BIT_5_7(data) == (0xc >> 1)) //bits == 110
		return 3;
	else if(GET_BIT_5_7(data) == (0xe >> 1)) //bits == 111
		return 4;
	else
		return -1;  //should not happen
}

// Decode a self-describing variable-length value
// In: Bytes
// Out: The self-describing variable-length value
int d_sdvalue_decode(const unsigned char *data)
{
	if(!GET_BIT_7( data )){                   //bit  == 0
		
	        return GET_BIT_0_6(data);
	}
	else if(GET_BIT_6_7(data) == (0x8 >> 2)){ //bits == 10
	
	        return  (GET_BIT_0_5(data) << 8 |  GET_BIT_0_7((data+1)));
	}
	else if(GET_BIT_5_7(data) == (0xc >> 1)){ //bits == 110
	  
	        return (GET_BIT_0_4(data) << 16 |  GET_BIT_0_7((data+1)) << 8 
		       | GET_BIT_0_7((data+2))); 
	}
	else if(GET_BIT_5_7(data) == (0xe >> 1)){ //bits == 111
	  
	        return (GET_BIT_0_4(data) << 24 |  GET_BIT_0_7((data+1)) << 16 
                       | GET_BIT_0_7((data+2)) << 8 | GET_BIT_0_7((data+3)));  
	}
	else
		return -1;  //should not happen

}

//-----------------------------------------------------------------------------

// Decode the static part of a ipv4 rohc packet and store it in a ip-structure
// Return the number of used bytes
int d_decode_static_ip4(const unsigned char *data, struct iphdr * dest)
{
	dest->version = GET_BIT_4_7(data);
	if((dest->version)!=4)
	        return -1;
	data++;
	dest->protocol = GET_BIT_0_7(data);
	data++;
	dest->saddr = *((u32 *)data);
	data += 4;
	dest->daddr = *((u32 *)data);
	return 10;
}

// Decode the static part in a udp rohc packet and store it in a udp-structure
// Return the number of used bytes
int d_decode_static_udp(const unsigned char *data, struct udphdr * dest)
{
        dest-> source = *((u16 *)data);
	data += 2;
	dest-> dest = *((u16 *)data);
	return 4;
}

// Decode the dynamic part in a ipv4 rohc packet and store it in a ip-structure
// Return the number of used bytes
int d_decode_dynamic_ip4(const unsigned char *data, struct iphdr * dest, 
                         int * rnd, int * nbo)
{
  	dest->tos = GET_BIT_0_7(data);
	data++;
	dest->ttl = GET_BIT_0_7(data);
	data++;
	dest-> id = *((u16 *)data);
	data += 2;
	if(GET_BIT_7(data)){
		dest->frag_off = htons(0x4000);
	}else{
		dest->frag_off = htons(0x0000);
	}
	*nbo = GET_REAL(GET_BIT_5(data));
	*rnd = GET_REAL(GET_BIT_6(data));
	
	return 5;
}

// Decode the dynamic part in a udp rohc packet and store it in a udp-structure
// Return the number of used bytes
int d_decode_dynamic_udp(const unsigned char *data, struct udphdr * dest)
{
        dest-> check = *((u16 *)data);
	return 2;
}

// Decode the dynamic part in a udp-lite rohc packet and store it in a udp-structure
// Return the number of used bytes
int d_decode_dynamic_udp_lite(const unsigned char *data, struct udphdr * dest)
{
	dest-> len = *((u16 *)data);
	data += 2;
        dest-> check = *((u16 *)data);
	return 4;
}


// Initiate the lsb struct
// in: the value of v_ref_d and type of p value
void d_lsb_init(struct sd_lsb_decode * s,int v_ref_d, int p)
{
	s->p = p;
	s->v_ref_d = v_ref_d;
	s->old_v_ref_d = v_ref_d;
}

// Decode a LSB-value
// in: the struct were the old received value is present
//     m = the LSB-value to decode 
//     k = the length of m in bits
//     
// out:the decoded value
int d_lsb_decode(struct sd_lsb_decode * s, int m, int k)
{	
	int lower = (s->v_ref_d - s->p);
//	int higher = (ref - s->p) + 1 << k - 1;

	int bitmask = ~((1 << k) - 1);
 	int sn = (s->v_ref_d & bitmask) | m;
	if (sn < lower) sn += 1 << k;

	return sn & 0xFFFF;
}

// update the reference value, called after a crc-success to update the 
// last decoded value, eg the sn number
void d_lsb_update(struct sd_lsb_decode * s, int v_ref_d)
{
	s->v_ref_d = v_ref_d;
}

// copy the value in v_ref_d to old_v_ref_d
void d_lsb_sync_ref(struct sd_lsb_decode * s){
	s->old_v_ref_d = s->v_ref_d;
}

// get the old value of v_ref_d
int d_get_lsb_old_ref(struct sd_lsb_decode * s){
	return s->old_v_ref_d;
}

// get the reference value
int d_get_lsb_ref(struct sd_lsb_decode * s)
{
	return s->v_ref_d;
}


// initiate the ip-id struct 
// in: the ip-id struct, the reference for ip-id, the sequenze number  
void d_ip_id_init(struct sd_ip_id_decode * s,int id_ref, int sn_ref)
{
	s->id_ref = id_ref;
	s->sn_ref = sn_ref;
}

// Decode the ip-id offset in packet m and return the ip_id
// in: the ip-id struct, the packet m containing the ip-id offset,
//     m = the length of the offset
//     k = number of bits in m
//     sn = the sequence number of packet m.
// out:ip_id
int d_ip_id_decode(struct sd_ip_id_decode * s, int m, int k, int sn)
{
	int offset_ref = (s->id_ref - s->sn_ref)%(65536);
	int offset_m = -1;
	
	int bitmask = ~((1 << k) - 1);
	int ip_id = (offset_ref & bitmask) | m;
	
	if (ip_id < offset_ref) ip_id += 1 << k;
	
	offset_m = ip_id & 0xFFFF;
	return ((sn + offset_m)%(65536));
}


// update the reference values for the ip-id and the sequence number
void d_ip_id_update(struct sd_ip_id_decode * s, int id_ref, int sn_ref)
{
	s->id_ref = id_ref;
	s->sn_ref = sn_ref;
}



















