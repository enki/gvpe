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
/*
 * Implementation of the uncompressed profile (compressor)
 */
 
#include "rohc.h"
#include "comp.h"
#include "c_util.h"


/*
Structure that contain counters, flags and structures that need to saved between different
packages. Every context have one of these
*/
struct sc_uncompressed_context {
	int ir_count, normal_count;
	int go_back_ir_count;


};

static void uncompressed_decide_state(struct sc_context *context);

static void uncompressed_periodic_down_transition(struct sc_context *context);

static void uncompressed_change_mode(struct sc_context *c, C_MODE new_mode);

static void uncompressed_change_state(struct sc_context *c, C_STATE new_state);

static int uncompressed_code_packet(struct sc_context *context,
	const struct iphdr *ip,
	unsigned char *dest,
	int *payload_offset,
	int max_size);

static int uncompressed_code_IR_packet(struct sc_context *context,
	const struct iphdr *ip,
	unsigned char *dest,
	int *payload_offset,
	int max_size);

static int uncompressed_code_normal_packet(struct sc_context *context,
	const struct iphdr *ip,
	unsigned char *dest,
	int *payload_offset,
	int max_size);

/*
Function to allocate for a new context, it aslo initilize alot of variables.

This function is one of the functions that must exist for the framework to
work. Please notice that a pointer to this function has to exist in the
sc_profile struct thatwe have in the bottom of this file.
*/
int c_uncompressed_create(struct sc_context *context, const struct iphdr *ip)
{
	struct sc_uncompressed_context *uncompressed_profile;

	context->profile_context = kmalloc(sizeof(struct sc_uncompressed_context),GFP_ATOMIC);
	if (context->profile_context == 0) {
	  rohc_debugf(0,"c_ip_create(): no mem for profile context\n");
	  return 0;
	}
	uncompressed_profile = (struct sc_uncompressed_context *)context->profile_context;

	uncompressed_profile->ir_count = 0;
	uncompressed_profile->normal_count = 0;

	uncompressed_profile->go_back_ir_count = 0;
	return 1;

}


/*
Function to deallocate a context.

This function is one of the functions that must exist for the framework to
work. Please notice that a pointer to this function has to exist in the
sc_profile struct thatwe have in the bottom of this file.
*/
void c_uncompressed_destroy(struct sc_context *context){

	if (context->profile_context != 0)
	  kfree(context->profile_context);

}

/*
A package can always be sent uncompressed

This function is one of the functions that must exist for the framework to
work. Please notice that a pointer to this function has to exist in the
sc_profile struct that we have in the bottom of this file.
*/
int c_uncompressed_check_context(struct sc_context *context, const struct iphdr *ip){
	return 1;
}

/*
Encode packages to a pattern decided by two different factors.
1. Decide state
2. Code packet

This function is one of the functions that must exist for the framework to
work. Please notice that a pointer to this function has to exist in the
sc_profile struct that we have in the bottom of this file.
*/
int c_uncompressed_encode(struct sc_context *context,
	const struct iphdr *ip,
	int packet_size,
     	unsigned char *dest,
	int max_size,
	int *payload_offset)

{
	int size;

	// 1
	uncompressed_decide_state(context);

	//2
	size = uncompressed_code_packet(context,ip,dest,payload_offset,max_size);

	return size;
}

/*
Function that update the profile when feedback has arrived.

This function is one of the functions that must exist for the framework to
work. Please notice that a pointer to this function has to exist in the
sc_profile struct that we have in the bottom of this file.
*/
void c_uncompressed_feedback(struct sc_context *context, struct sc_feedback *feedback)
{
	//struct sc_uncompressed_context *uncompressed_context = (struct sc_uncompressed_context *)context->profile_context;
	unsigned char *p = feedback->data + feedback->specific_offset;

	if (feedback->type == 1) { // ack

	} else if (feedback->type == 2) { // FEEDBACK-2
		unsigned int crc = 0, crc_used=0;

		int sn_not_valid = 0;
		unsigned char mode = (p[0]>>4) & 3;
		unsigned int sn = ((p[0] & 15) << 8) + p[1];
		int remaining = feedback->specific_size-2;
		p+=2;


		while (remaining > 0) {
			int opt = p[0]>>4;
			int optlen = p[0] & 0x0f;

			switch (opt) {
			case 1: // CRC
				crc = p[1];
				crc_used = 1;
				p[1] = 0; // set to zero for crc computation..
			break;
			//case 2: // Reject
			//break;
			case 3: // SN-Not-Valid
				sn_not_valid=1;
			break;
			case 4: // SN  -- TODO: how is several SN options combined?
				sn = (sn<<8) + p[1];
			break;
			//case 7: // Loss
			//break;
			default:
				rohc_debugf(0,"c_ip_feedback(): Unknown feedback type: %d\n", opt);
			break;
			}

			remaining -= 1 + optlen;
			p += 1 + optlen;
		}

		if (crc_used) { // check crc..
			if (crc_calculate(CRC_TYPE_8, feedback->data, feedback->size ) != crc) {
				rohc_debugf(0,"c_ip_feedback(): crc check failed..(size=%d)\n", feedback->size);
				return;
			}
		}

		if (mode != 0) {
			if (crc_used) {
				uncompressed_change_mode(context, mode);
				rohc_debugf(1,"c_ip_feedback(): changing mode to %d\n", mode);
			} else {
				rohc_debugf(0,"c_ip_feedback(): mode change requested but no crc was given..\n");
			}
		}

		switch (feedback->acktype) {
		case ACK:

		break;

		case NACK:


		break;

		case STATIC_NACK:
			uncompressed_change_state(context, IR);
		break;

		case RESERVED:
			rohc_debugf(0, "c_ip_feedback(): reserved field used\n");
		break;
		}

	} else {
		rohc_debugf(0,"c_ip_feedback(): Feedback type not implemented (%d)\n", feedback->type);
	}

}

/* Decide the state we will work in. Observe that RFC3095 defines the states as ir and normal, but here
we call normal state FO instead*/
void uncompressed_decide_state(struct sc_context *context)
{
	struct sc_uncompressed_context *uncompressed_profile = (struct sc_uncompressed_context *)context->profile_context;

	if(context->c_state == IR &&  uncompressed_profile->ir_count >= MAX_IR_COUNT){
		uncompressed_change_state(context, FO);
	}
	if(context->c_mode == U){
		uncompressed_periodic_down_transition(context);
	}
}

/*Function that change state periodicly after a certain number of packets */
void uncompressed_periodic_down_transition(struct sc_context *context)
{
	struct sc_uncompressed_context *uncompressed_profile = (struct sc_uncompressed_context *)context->profile_context;
	if(uncompressed_profile->go_back_ir_count == CHANGE_TO_IR_COUNT){
		uncompressed_profile->go_back_ir_count = 0;
		uncompressed_change_state(context, IR);
	}
	if (context->c_state == FO)
		uncompressed_profile->go_back_ir_count++;

}

// Change the mode of this context
void uncompressed_change_mode(struct sc_context *c, C_MODE new_mode) {
	if(c->c_mode != new_mode){
		c->c_mode = new_mode;
		uncompressed_change_state(c, IR);
	}
}

// Change the state of this context
void uncompressed_change_state(struct sc_context *context, C_STATE new_state)
{

	struct sc_uncompressed_context *uncompressed_profile = (struct sc_uncompressed_context *)context->profile_context;
	// Reset counters only if different state
	if (context->c_state != new_state) {
		uncompressed_profile->ir_count = 0;
		uncompressed_profile->normal_count = 0;

	}

	context->c_state = new_state;
}

/*
Code the packet, it is eiter IR or normal
*/
int uncompressed_code_packet(struct sc_context *context,
	const struct iphdr *ip,
	unsigned char *dest,
	int *payload_offset,
	int max_size){

	struct sc_uncompressed_context *uncompressed_profile = (struct sc_uncompressed_context *)context->profile_context;
	switch(context->c_state){
		case IR:
			rohc_debugf(1,"uncompressed_code_packet(): IR packet uncomp..\n");
			uncompressed_profile->ir_count++;
			return uncompressed_code_IR_packet(context,ip,dest,payload_offset,max_size);
			break;
		case FO:
			rohc_debugf(1,"uncompressed_code_packet(): normal packet uncomp..\n");
			uncompressed_profile->normal_count++;
			return uncompressed_code_normal_packet(context,ip,dest,payload_offset,max_size);
			break;
		default:
			rohc_debugf(0,"uncompressed_code_packet(): Unknown packet..\n");
			return -1;
	}
}
/*

IR packet (5.10.1)

     0   1   2   3   4   5   6   7
    --- --- --- --- --- --- --- ---
 1 :         Add-CID octet         : if for small CIDs and (CID != 0)
   +---+---+---+---+---+---+---+---+
 2 | 1   1   1   1   1   1   0 |res|
   +---+---+---+---+---+---+---+---+
   :                               :
 3 /    0-2 octets of CID info     / 1-2 octets if for large CIDs
   :                               :
   +---+---+---+---+---+---+---+---+
 4 |          Profile = 0          | 1 octet
   +---+---+---+---+---+---+---+---+
 5 |              CRC              | 1 octet
   +---+---+---+---+---+---+---+---+
   :                               : (optional)
   /           IP packet           / variable length
   :                               :
    --- --- --- --- --- --- --- ---

*/
int uncompressed_code_IR_packet(struct sc_context *context,
	const struct iphdr *ip,
	unsigned char *dest,
	int *payload_offset,
	int max_size){

	int counter = 0;
	int first_position;

	rohc_debugf(2,"Coding IR packet (cid=%d)\n", context->cid);
	//Both 1 and 3, 2 will be placed in dest[first_position]
	counter = code_cid_values(context,dest,max_size,&first_position);

	// 2
	dest[first_position] = 0xfc;

	// 4
	dest[counter] = 0;
	counter++;

	// 5
	dest[counter]= crc_calculate(CRC_TYPE_8,dest,counter);
	counter++;
	*payload_offset = 0;
	return counter;
}
/*

Normal packet (5.10.2)

     0   1   2   3   4   5   6   7
    --- --- --- --- --- --- --- ---
 1 :         Add-CID octet         : if for small CIDs and (CID != 0)
   +---+---+---+---+---+---+---+---+
 2 |   first octet of IP packet    |
   +---+---+---+---+---+---+---+---+
   :                               :
 3 /    0-2 octets of CID info     / 1-2 octets if for large CIDs
   :                               :
   +---+---+---+---+---+---+---+---+
   |                               |
   /      rest of IP packet        / variable length
   |                               |
   +---+---+---+---+---+---+---+---+

*/
int uncompressed_code_normal_packet(struct sc_context *context,
	const struct iphdr *ip,
	unsigned char *dest,
	int *payload_offset,
	int max_size)
{

	int counter = 0;
	int first_position;


	rohc_debugf(2,"Coding normal packet (cid=%d)\n", context->cid);
	//Both 1 and 3, 2 will be placed in dest[first_position]
	counter = code_cid_values(context,dest,max_size,&first_position);

	// 2

	dest[first_position] = ((unsigned char *)ip)[0];

	*payload_offset = 1;
	return counter;
}

/*
A struct thate every function must have the first fieldtell what protocol this profile has.
The second row is the profile id-number, Then two strings that is for printing version and
description. And finaly pointers to functions that have to exist in every profile.
*/
struct sc_profile c_uncompressed_profile = {
	0, // IP-Protocol
	0, // Profile ID
	"1.0b", // Version
	"Uncompressed / Compressor", // Description
	c_uncompressed_create,
	c_uncompressed_destroy,
	c_uncompressed_check_context,
	c_uncompressed_encode,
	c_uncompressed_feedback
};
