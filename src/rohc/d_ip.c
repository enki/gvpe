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
// IP-Only profile in decompressor

/* The decode functions decode the packet, control CRC
 * and if crc-fails the try a new decompression with a
 * other SN number. The decode functions returns some
 * kind of ROHC_ERROR or if it is correct decoded the
 * length of the decoded packet is returned.
*/

#include "rohc.h"
#include "decomp.h"

#include "d_ip.h"
#include "d_util.h"
#include "comp.h"
#include "c_util.h"

//--------------------------------------------------------- Helpfunctions

/* Decode a UO-0 package */
static int decode_uo0(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * head,
	unsigned char * src,
	unsigned char * dest,
	int payload_size
	);

/* Decode a UO-1 package */
static int decode_uo1(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * head,
	unsigned char * src2,
	unsigned char * dest,
	int payload_size
	);

/* Decode a UO-2 package */
static int decode_uor2(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * head,
	unsigned char * src2,
	unsigned char * dest,
	int payload_size
	);

/* Decode a IR-Dyn package */
static int decode_irdyn(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * head,
	unsigned char * src2,
	unsigned char * dest,
	int payload_size
	);

/* Decode extention 0 */
static int decode_extention0(unsigned char * src, int * sn, int * ip_id);

/* Decode extention 1 */
static int decode_extention1(unsigned char * src, int * sn, int * ip_id);

/* Decode extention 2 */
static int decode_extention2(unsigned char * src, int * sn, int * ip_id, int * ip_id2);

/* Decode extention 3
 *    - Updates random fields in the s_iponly_change
 *    - May update the SN value with 8 lower bits. sn_size is then changed
 */
static int decode_extention3(unsigned char * src, struct sd_context * context, struct sd_rohc *state,
	int * sn, int * sn_size, int * ip_id_changed, int * id2_updated);

// Make a copy of the "active"-struct to the "last"-struct.
static void syncronize(struct s_iponly_profile_data *);

// Decode package type
static int package_type(const unsigned char * p);

/* Deceide the extention type */
static int extention_type(const unsigned char * p);

/* Write a uncompressed IP v4 header */
static void write_uncompressed_ip4(
	struct s_iponly_change * active1,
	int ip_id,
	unsigned char * dest,
	int payload_size
	);


/* Copy the last-struct to active-struct. */
static void sync_on_failure(struct s_iponly_profile_data * pro);

/* Decode inner IP flags and fields. Storage the values
 * in a IP-head struct.
 */
static int decode_inner_header_flags(
	unsigned char * flags,
	unsigned char * fields,
	struct iphdr * ip,
	int * rnd, int * nbo);

/* Decode outer IP flags and fields. Storage the values
 * in a IP-head struct.
 */
static int decode_outer_header_flags(
	unsigned char * flags,
	unsigned char * fields,
	struct iphdr * ip,
	int * rnd, int * nbo,
	int * ip_changed);

/* A functions that decode uo0 and uo1 packets
 *
 */
static int help_to_decode_uo0_and_uo1(
	struct sd_context * context,
	unsigned char * src,
	unsigned char * dest,
	int * payload_size,
	int sn_bits,
	int number_of_sn_bits,
	int * id,
	int number_of_id_bits,
	int * id2,
	int * sn,
	int * calc_crc
	);

/* A functions that decode uor2 packets
 *
 */
static int help_to_decode_uor2(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * src2,
	unsigned char * dest,
	int * payload_size,
	int * id,
	int * id2,
	int * sn,
	int * sn_size,
	int sn_bits,
	int ext,
	int * calc_crc
	);

/* The function that try to correct a packet after
 * a crc-failure.
 * It try with an other SN value.
 */
static int act_on_crc_failure(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * src,
	unsigned char * dest,
	int sn_size,
	int * sn_curr1,
	int sn_bits,
	int * payload_size,
	int * id,
	int id_size,
	int * id2,
	int * calc_crc,
	int * real_crc,
	int ext
	);

static void update_inter_packet(struct s_iponly_profile_data * pro);
//---------------------------------------------------------- Code

// To allocate profile data
void * iponly_allocate_decode_data(void)
{
	struct s_iponly_profile_data * data;
	struct s_iponly_change * ch;
	void * p = kmalloc(sizeof(struct s_iponly_profile_data) + 4 * sizeof(struct s_iponly_change),
		GFP_ATOMIC);

	if (p==NULL) {
		rohc_debugf(0, "iponly_allocate_decode_data(): no mem for ip profile data\n");
		return NULL;
	}

	data = (struct s_iponly_profile_data *)p;
	ch = (struct s_iponly_change *)(data + 1);

	memset(p, 0, sizeof(struct s_iponly_profile_data) +
		4 * sizeof(struct s_iponly_change) );

	data->last1 = ch; ch++;
	data->active1 = ch; ch++;
	data->last2 = ch; ch++;
	data->active2 = ch;

	return p;
}

// To deallocate profile data
void iponly_free_decode_data(void * p)
{
	kfree(p);
}

// Decode an IR-package and initalize context
int iponly_decode_ir(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * src,
	int copy_size,
	int dynamic_present,
	unsigned char * dest
	)
{
	struct s_iponly_profile_data * pro = context->data;
	struct s_iponly_change * active1 = pro->active1;
	struct s_iponly_change * active2 = pro->active2;

	unsigned char * s = src;
	unsigned char * d = dest;

	int size, sn;

	pro->current_packet_time = get_microseconds();

	// Ip4 static
	size = d_decode_static_ip4(s, &active1->ip);

	if (active1->ip.protocol == PROTOCOL_IP_IN_IP){
		pro->multiple_ip = 1;
		rohc_debugf(1, "Multiple IP header\n");
	}else{
	        pro->multiple_ip = 0;
	}

	if (size == -1) {
		return ROHC_ERROR;
	}
	s += size; copy_size -= size;

	// If multiple-ip-header
	if(pro->multiple_ip){
		size = d_decode_static_ip4(s, &active2->ip);
		s += size; copy_size -= size;
		if (size == -1) {
			return ROHC_ERROR;
		}
	}

	// Dynamic field
	if (dynamic_present) {
		size = d_decode_dynamic_ip4(s, &active1->ip, &active1->rnd, &active1->nbo);
		s += size; copy_size -= (size + 2);

		// If multiple-ip-header
		if(pro->multiple_ip){
			size = d_decode_dynamic_ip4(s, &active2->ip, &active2->rnd, &active2->nbo);
			s += size; copy_size -= size;
		}
		// Reset the correction-counter
		pro->counter = 0;

		// Get and set SN
		sn = ntohs(* ((u16 *)s));
		d_lsb_init(&pro->sn, sn, -1);
		d_ip_id_init(&pro->ip_id1, ntohs(active1->ip.id), sn);
		s += 2;
		context->state = ROHC_FULL_CONTEXT;

		// If multiple-ip-header
		if(pro->multiple_ip){
			d_ip_id_init(&pro->ip_id2, ntohs(active2->ip.id), sn);
		}


	} else if (context->state != ROHC_FULL_CONTEXT) {
		// in static/no context and not get dynamic part
		return ROHC_ERROR;
	}


	// Header write
	if (pro->multiple_ip){
		write_uncompressed_ip4(active1, ntohs(active1->ip.id), d, copy_size+sizeof(struct iphdr));
		d += sizeof(struct iphdr);
		write_uncompressed_ip4(active2, ntohs(active2->ip.id), d, copy_size);

	}else{
		write_uncompressed_ip4(active1, ntohs(active1->ip.id), d, copy_size);
	}
	d += sizeof(struct iphdr);

	// Syncronizerar strukterna
	syncronize(pro);

	// Update the inter-packet variable
	update_inter_packet(pro);

	// Copy payload
	if (copy_size == 0) return ROHC_OK_NO_DATA;

	memcpy(d, s, copy_size);

	// Statistics:
	context->header_compressed_size += s - src;
	c_add_wlsb(context->header_16_compressed, 0,0, s - src);
	context->header_uncompressed_size += (pro->multiple_ip+1)*sizeof(struct iphdr);
	c_add_wlsb(context->header_16_uncompressed, 0, 0, (pro->multiple_ip+1)*sizeof(struct iphdr));

	return copy_size + (pro->multiple_ip + 1) * sizeof(struct iphdr);
}

// Calculate the size of data in an IR-package.
// return : size or zero.
int iponly_detect_ir_size(unsigned char * first_byte, int second_byte_add)
{
	int ret = 10;
	int d = GET_BIT_0(first_byte);
	if (d) ret += 5 + 2;
	if (first_byte[second_byte_add + 2] != 0x40) return 0;
	if (first_byte[second_byte_add + 3] == PROTOCOL_IP_IN_IP){
		ret += 10;
		if (d) ret += 5;
		if (first_byte[second_byte_add + 12] != 0x40) return 0;
	}
	return ret;
}

// Calculate the size of data in an IR-package.
// return : size or zero.
int iponly_detect_ir_dyn_size(unsigned char * first_byte, struct sd_context *c)
{
        struct s_iponly_profile_data * pro = c->data;
	if (pro->active1->ip.protocol == PROTOCOL_IP_IN_IP) return 12;
	return 7;
}

// Decode all package except IR-package.
int iponly_decode(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * src,
	int size,
	int second_byte,
	unsigned char * dest
	)
{
	struct s_iponly_profile_data * pro = context->data;
	// ---- DEBUG ----
	int i; unsigned char * p;

	struct s_iponly_change * active1 = pro->active1;
	struct s_iponly_change * active2 = pro->active2;
	struct s_iponly_change * last1 = pro->last1;
	struct s_iponly_change * last2 = pro->last2;

	pro->current_packet_time = get_microseconds();

	rohc_debugf(2,"(iponly_decode) nbo = %d rnd = %d\n", last1->nbo, last1->rnd);
	if (pro->multiple_ip){
		rohc_debugf(2,"Multiple ip-header\n");
		rohc_debugf(2,"(iponly_decode) nbo2 = %d rnd2 = %d\n", last2->nbo, last2->rnd);
	}
	if (memcmp(active1, last1, sizeof(struct s_iponly_change)) != 0) {
		rohc_debugf(0,"(iponly_decode) last1 and active1 struct is not synchronized\n");
		p = (unsigned char *)last1;
		for (i = 0; i < sizeof(struct s_iponly_change); i++) {
			rohc_debugf(1, "%2x ", p[i]);
		}
		rohc_debugf(1, "\nvs\n");
		p = (unsigned char *)active1;
		for (i = 0; i < sizeof(struct s_iponly_change); i++) {
			rohc_debugf(1, "%2x ", p[i]);
		}
		rohc_debugf(1,"\n");
	}
	if (memcmp(active2, last2, sizeof(struct s_iponly_change)) != 0) {
		rohc_debugf(0,"(iponly_decode) last2 and active2 struct is not synchronized\n");
		p = (unsigned char *)last2;
		for (i = 0; i < sizeof(struct s_iponly_change); i++) {
			rohc_debugf(1,"%2x ", p[i]);
		}
		rohc_debugf(1,"\nvs\n");
		p = (unsigned char *)active2;
		for (i = 0; i < sizeof(struct s_iponly_change); i++) {
			rohc_debugf(1,"%2x ", p[i]);
		}
		rohc_debugf(1,"\n");
	}
	// ---- DEBUG ----

	if (context->state == ROHC_NO_CONTEXT) return ROHC_ERROR;

	switch(package_type(src)) {
	case PACKAGE_UO_0:
		pro->package_type = PACKAGE_UO_0;
		if (context->state  == ROHC_STATIC_CONTEXT) return ROHC_ERROR;
		return decode_uo0(state, context, src, src + second_byte,
			dest, size - second_byte);
	case PACKAGE_UO_1:
		pro->package_type = PACKAGE_UO_1;
		if (context->state  == ROHC_STATIC_CONTEXT) return ROHC_ERROR;
		return decode_uo1(state, context, src, src + second_byte,
			dest, size - second_byte);
	case PACKAGE_UOR_2:
		pro->package_type = PACKAGE_UOR_2;
		return decode_uor2(state, context, src, src + second_byte,
			dest, size - second_byte);
	case PACKAGE_IR_DYN:
		return decode_irdyn(state, context, src, src + second_byte,
			dest, size - second_byte);
	default:
		rohc_debugf(0,"(Ip-only) Unknown package.\n");
		return ROHC_ERROR;
	}
}

static int iponly_get_sn(struct sd_context * context)
{
	struct s_iponly_profile_data * pro = context->data;
	return d_get_lsb_ref(&pro->sn);
}

static struct s_profile d_ip_profile = {4, "1.0", "IP / Decompressor",
	iponly_decode,
	iponly_decode_ir,
	iponly_allocate_decode_data,
	iponly_free_decode_data,
	iponly_detect_ir_size,
	iponly_detect_ir_dyn_size,
	iponly_get_sn
	};

struct s_profile * iponly_profile_create()
{
	return &d_ip_profile;
}

// --------------------------------------------------------- Package type decoder

/* Decode a UO-0 package */
 static int decode_uo0(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * head,
	unsigned char * src,
	unsigned char * dest,
	int payload_size
	)
{
	unsigned char *saved_src = src;
	struct s_iponly_profile_data * pro = context->data;
	int multiple_ip = pro->multiple_ip;
	int id, id2=-1, sn, sn_bits = GET_BIT_3_6(head), sn_size = 4;
	int calc_crc, real_crc = GET_BIT_0_2(head);
	int extra_fields = 0, org_payload_size = payload_size;
	// Do the decoding / find ip-id
	extra_fields = help_to_decode_uo0_and_uo1(context, src, dest, &payload_size, sn_bits, sn_size , &id, 0 , &id2, &sn, &calc_crc);

	if (calc_crc != real_crc) {
		rohc_debugf(0,"UO-0: CRC failure (calc) %x vs %x (real)\n",
			calc_crc, real_crc);

		payload_size = org_payload_size;
		act_on_crc_failure(0,context, src, dest, sn_size, &sn, sn_bits, &payload_size, &id, 0, &id2, &calc_crc, &real_crc, 0);
		return ROHC_ERROR_CRC;
	}

	// if any crc-correction then three correct packet need to pass crc
	if(pro->counter){
		if(pro->counter==1){

			rohc_debugf(2,"Throw away packet, just 2 packages right so far\n");

			pro->counter++;

			// Update the inter-packet variable
			update_inter_packet(pro);
			syncronize(pro);

			d_lsb_sync_ref(&pro->sn);
			d_lsb_update(&pro->sn, sn);
			d_ip_id_update(&pro->ip_id1, id, sn);
			if (pro->multiple_ip)
				d_ip_id_update(&pro->ip_id2, id2, sn);

			return ROHC_ERROR_CRC;

		}else if(pro->counter==2){
			pro->counter = 0;
			rohc_debugf(2,"The rapair is deemed successful\n");
		}else{
			rohc_debugf(2,"XX Should not happen XX\n");
		}
	}

	src += extra_fields;

	// Update the inter-packet variable
	update_inter_packet(pro);
	syncronize(pro);

	// Update lsb and id structs on CRC-success
	d_lsb_sync_ref(&pro->sn);
	d_lsb_update(&pro->sn, sn);
	d_ip_id_update(&pro->ip_id1, id, sn);
	if (pro->multiple_ip){
		d_ip_id_update(&pro->ip_id2, id2, sn);
		dest += sizeof(struct iphdr);
	}

	// Payload
	dest += sizeof(struct iphdr);
	memcpy(dest, src, payload_size);

	// Statistics:
	context->header_compressed_size += src - saved_src;
	c_add_wlsb(context->header_16_compressed, 0,0, src - saved_src);
	context->header_uncompressed_size += (multiple_ip+1)*sizeof(struct iphdr);
	c_add_wlsb(context->header_16_uncompressed, 0, 0, (multiple_ip+1)*sizeof(struct iphdr));

	return payload_size + (multiple_ip + 1) * sizeof(struct iphdr);
}



/* Decode a UO-1 package */
static int decode_uo1(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * head,
	unsigned char * src,
	unsigned char * dest,
	int payload_size
	)
{
	unsigned char *saved_src = src;
	struct s_iponly_profile_data * pro = context->data;

	int id = GET_BIT_0_5(head), id2=-1;
	int sn, sn_bits = GET_BIT_3_7(src), sn_size = 5;
	int org_payload_size, extra_fields=0;
	int calc_crc, real_crc = GET_BIT_0_2(src);
	src++; payload_size--;
	org_payload_size = payload_size;

	// Decode the id and sn
	extra_fields = help_to_decode_uo0_and_uo1(context, src, dest, &payload_size, sn_bits, sn_size , &id, 6 , &id2, &sn, &calc_crc);

	if (calc_crc != real_crc) {
		rohc_debugf(0,"UO-1: CRC failure (calc) %x vs %x (real)\n",
			calc_crc, real_crc);
		payload_size = org_payload_size;
		act_on_crc_failure(0,context, src, dest, sn_size, &sn, sn_bits, &payload_size, &id, 6, &id2, &calc_crc, &real_crc, 0);
		return ROHC_ERROR_CRC;
	}

	if(pro->counter){
		if(pro->counter==1){

			rohc_debugf(2,"Throw away packet, just 2 packages right so far\n");

			pro->counter++;
			// Update the inter-packet variable

			update_inter_packet(pro);
			syncronize(pro);

			d_lsb_sync_ref(&pro->sn);
			d_lsb_update(&pro->sn, sn);
			d_ip_id_update(&pro->ip_id1, id, sn);
			if (pro->multiple_ip)
				d_ip_id_update(&pro->ip_id2, id2, sn);

			return ROHC_ERROR_CRC;

		}else if(pro->counter==2){
			pro->counter = 0;
			rohc_debugf(2,"The rapair is deemed successful\n");
		}else{
			rohc_debugf(2,"XX Should not happen XX\n");
		}
	}

	src += extra_fields;

	// Update the inter-packet variable
	update_inter_packet(pro);

	syncronize(pro);

	d_lsb_sync_ref(&pro->sn);
	d_lsb_update(&pro->sn, sn);
	d_ip_id_update(&pro->ip_id1, id, sn);
	if (pro->multiple_ip){
		d_ip_id_update(&pro->ip_id2, id2, sn);
		dest += sizeof(struct iphdr);
	}

	// Payload
	dest += sizeof(struct iphdr);
	memcpy(dest, src, payload_size);

	// Statistics:
	context->header_compressed_size += src - saved_src;
	c_add_wlsb(context->header_16_compressed, 0,0, src - saved_src);
	context->header_uncompressed_size += (pro->multiple_ip+1)*sizeof(struct iphdr);
	c_add_wlsb(context->header_16_uncompressed, 0, 0, (pro->multiple_ip+1)*sizeof(struct iphdr));

	return payload_size + (pro->multiple_ip + 1)  * sizeof(struct iphdr);
}


/* Decode a UO-2 package */
static int decode_uor2(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * head,
	unsigned char * src,
	unsigned char * dest,
	int payload_size
	)
{
	unsigned char *saved_src = src;
        struct s_iponly_profile_data * pro = context->data;

	int org_payload_size = payload_size, extra_fields = 0;
	int sn_size = 0;
	int id = 0, id2 = 0, multiple_id = pro->multiple_ip;
	int calc_crc = 0;
	int sn_bits = GET_BIT_0_4(head) , sn = 0;
	int real_crc = GET_BIT_0_6(src);
	int ext = GET_BIT_7(src);
	src++;

	// Decode
	extra_fields = help_to_decode_uor2(state, context, src, dest, &payload_size, &id, &id2, &sn, &sn_size, sn_bits, ext, &calc_crc);

	if (calc_crc != real_crc) {
		rohc_debugf(0,"UOR-2: CRC failure (calc) %x vs %x (real)\n",
		calc_crc, real_crc);
		payload_size = org_payload_size;
		id =0 ; id2 = 0; calc_crc = 0;
		act_on_crc_failure(state, context, src, dest, sn_size, &sn, sn_bits, &payload_size, &id, 0, &id2, &calc_crc, &real_crc, ext);
		return ROHC_ERROR_CRC;
	}

	if(pro->counter){
		if(pro->counter==1){

			rohc_debugf(2,"Throw away packet, just 2 packages right so far\n");

			pro->counter++;
			// Update the inter-packet variable

			update_inter_packet(pro);
			syncronize(pro);

			d_lsb_sync_ref(&pro->sn);
			d_lsb_update(&pro->sn, sn);
			d_ip_id_update(&pro->ip_id1, id, sn);
			if (pro->multiple_ip)
				d_ip_id_update(&pro->ip_id2, id2, sn);

			return ROHC_ERROR_CRC;

		}else if(pro->counter==2){
			pro->counter = 0;
			rohc_debugf(2,"The rapair is deemed successful\n");
		}else{
			rohc_debugf(2,"XX Should not happen XX\n");
		}
	}

	context->state  = ROHC_FULL_CONTEXT;

	src += extra_fields;

	// if crc success
	syncronize(pro);

	// Update the inter-packet variable
	update_inter_packet(pro);

	// Update
	d_lsb_sync_ref(&pro->sn);
	d_lsb_update(&pro->sn, sn);
	d_ip_id_update(&pro->ip_id1, id, sn);
	if (pro->multiple_ip){
		d_ip_id_update(&pro->ip_id2, id2, sn);
		dest += sizeof(struct iphdr);
		rohc_debugf(2,"Decomps reference ID2 = %d SN = %d\n",pro->ip_id2.id_ref,pro->ip_id2.sn_ref );
	}
	// Payload
	dest += sizeof(struct iphdr);
	memcpy(dest, src, payload_size);
	rohc_debugf(2,"Decomps reference ID1 = %d SN = %d\n",pro->ip_id1.id_ref,pro->ip_id1.sn_ref );
	rohc_debugf(2,"Decomps reference SN = %d\n",d_get_lsb_ref(&pro->sn));

	// Statistics:
	context->header_compressed_size += src - saved_src;
	c_add_wlsb(context->header_16_compressed, 0,0, src - saved_src);
	context->header_uncompressed_size += (multiple_id+1)*sizeof(struct iphdr);
	c_add_wlsb(context->header_16_uncompressed, 0, 0, (multiple_id+1)*sizeof(struct iphdr));

	return payload_size + (multiple_id +1) *sizeof(struct iphdr);

}


/* Decode a IR-Dyn package */
static int decode_irdyn(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * head,
	unsigned char * src2,
	unsigned char * dest,
	int payload_size
	)
{
	unsigned char *saved_src = src2;
	struct s_iponly_profile_data * pro = context->data;
	//struct s_iponly_change * last1 = pro->last1;
	struct s_iponly_change * active1 = pro->active1;
	struct s_iponly_change * active2 = pro->active2;
	int sn = 0, size = d_decode_dynamic_ip4(src2, &active1->ip, &active1->rnd, &active1->nbo);
	src2 += size; payload_size -= size + 2;

	if( pro->multiple_ip ){
		size = d_decode_dynamic_ip4(src2, &active2->ip, &active2->rnd, &active2->nbo);
		src2 += size; payload_size -= size;
	}
	sn = ntohs(* ((u16 *)src2));
	d_lsb_init(&pro->sn, sn, -1);
	d_ip_id_init(&pro->ip_id1,ntohs(active1->ip.id), sn);
	syncronize(pro);
	// reset the correction-counter
	pro->counter = 0;
	src2 += 2;

	if (pro->multiple_ip){
		d_ip_id_init(&pro->ip_id2,ntohs(active2->ip.id), sn);
		rohc_debugf(2,"Decomps reference ID2 = %d SN = %d\n",pro->ip_id2.id_ref,pro->ip_id2.sn_ref );
		write_uncompressed_ip4(active1, ntohs(active1->ip.id), dest, payload_size+sizeof(struct iphdr));
		dest += sizeof(struct iphdr);
		write_uncompressed_ip4(active2, ntohs(active2->ip.id), dest, payload_size);
	}else{
		write_uncompressed_ip4(active1, ntohs(active1->ip.id), dest, payload_size);
	}
	context->state = ROHC_FULL_CONTEXT;
	// Update the inter-packet variable
	update_inter_packet(pro);

	dest += sizeof(struct iphdr);
	memcpy(dest, src2, payload_size);
	rohc_debugf(2,"Decomps reference ID = %d SN = %d\n",pro->ip_id1.id_ref,pro->ip_id1.sn_ref );
	rohc_debugf(2,"Decomps reference SN = %d\n",d_get_lsb_ref(&pro->sn));

	// Statistics:
	context->header_compressed_size += src2 - saved_src;
	c_add_wlsb(context->header_16_compressed, 0,0, src2 - saved_src);
	context->header_uncompressed_size += (pro->multiple_ip+1)*sizeof(struct iphdr);
	c_add_wlsb(context->header_16_uncompressed, 0, 0, (pro->multiple_ip+1)*sizeof(struct iphdr));

	return payload_size + ((pro->multiple_ip)+1) * sizeof(struct iphdr);
}

/* a help function that does the decoding of uo0 and uo1 packets */
static int help_to_decode_uo0_and_uo1(
	struct sd_context * context,
	unsigned char * src,
	unsigned char * dest,
	int * payload_size,
	int sn_bits,
	int number_of_sn_bits,
	int * id,
	int number_of_id_bits,
	int * id2,
	int * sn,
	int * calc_crc
	)
{
	struct s_iponly_profile_data * pro = context->data;
	struct s_iponly_change * active1 = pro->active1;
	struct s_iponly_change * active2 = pro->active2;
	int field_counter = 0;

	*sn = d_lsb_decode(&pro->sn, sn_bits, number_of_sn_bits);

 	if (active1->rnd) {
		*id = ntohs(*((u16 *)src));
		src += 2; field_counter +=2; *payload_size -= 2;

	} else {
		if(number_of_id_bits)
			*id = d_ip_id_decode(&pro->ip_id1, *id, number_of_id_bits, *sn);
		else
			*id = d_ip_id_decode(&pro->ip_id1, 0, 0, *sn);
	}

	// If multiple ip header
	if (pro->multiple_ip){

		if (active2->rnd) {
			*id2 = ntohs(*((u16 *)src));

			src +=2; field_counter +=2; *payload_size -= 2;
		} else {
			*id2 = d_ip_id_decode(&pro->ip_id2, 0, 0, *sn);
		}
	}

	// Header write
	if (pro->multiple_ip){
		write_uncompressed_ip4(active1, *id, dest, *payload_size+sizeof(struct iphdr));
		write_uncompressed_ip4(active2, *id2, dest+sizeof(struct iphdr),*payload_size);

	}else{
		write_uncompressed_ip4(active1, *id, dest, *payload_size);
	}

	// Check CRC
	*calc_crc = crc_calculate(CRC_TYPE_3, dest, (pro->multiple_ip + 1) * sizeof(struct iphdr));

	return field_counter;
}

/* a function that does the decoding of uor2 packets */
static int help_to_decode_uor2(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * src2,
	unsigned char * dest,
	int * payload_size,
	int * id,
	int * id2,
	int * sn,
	int * sn_size,
	int sn_bits,
	int ext,
	int * calc_crc
	)
{
	struct s_iponly_profile_data * pro = context->data;
	struct s_iponly_change * active1 = pro->active1;
	struct s_iponly_change * active2 = pro->active2;
	int  id2_updated = 0, size = 0;
	int  no_ip_id_update = 0;
	int field_counter = 0;

	*sn = sn_bits;

	if (ext) {
		// decode extention
		switch(extention_type(src2)) {
		case PACKAGE_EXT_0:
			size = decode_extention0(src2, sn, id);
			// ip_id_bits == 3
			*sn_size = 8;
			*sn = d_lsb_decode(&pro->sn, *sn, *sn_size );
			*id = d_ip_id_decode(&pro->ip_id1, *id, 3, *sn);
			*id2 = d_ip_id_decode(&pro->ip_id2, 0, 0, *sn);
			break;

		case PACKAGE_EXT_1:
			size = decode_extention1(src2, sn, id);
			// ip_id bits == 11
			*sn_size = 8;
			*sn = d_lsb_decode(&pro->sn, *sn, *sn_size );
			*id = d_ip_id_decode(&pro->ip_id1, *id, 11, *sn);
			*id2 = d_ip_id_decode(&pro->ip_id2, 0, 0, *sn);
			break;

		case PACKAGE_EXT_2:
			size = decode_extention2(src2, sn, id, id2);
			// ip_id bits == 8
			*sn_size = 8;
			*sn = d_lsb_decode(&pro->sn, *sn, *sn_size );
			*id2 = d_ip_id_decode(&pro->ip_id1, *id, 8, *sn);//inner
			*id = d_ip_id_decode(&pro->ip_id2, *id2, 11, *sn);//outer
			break;

		case PACKAGE_EXT_3:
			*sn_size = 5;
			size = decode_extention3(src2, context, state, sn,
				sn_size, &no_ip_id_update, &id2_updated);

			rohc_debugf(2,"(iponly_decode) after ext 3 : nbo = %d rnd = %d\n", active1->nbo, active1->rnd);

			*sn = d_lsb_decode(&pro->sn, *sn, *sn_size );

			if (no_ip_id_update) {
				*id = ntohs(active1->ip.id);
			} else {
				*id = d_ip_id_decode(&pro->ip_id1, 0, 0, *sn);
			}
			if( pro->multiple_ip ){
				rohc_debugf(2,"(iponly_decode) after ext 3 : nbo2 = %d rnd2 = %d\n", active2->nbo, active2->rnd);

				if (id2_updated){
					*id2 = ntohs(active2->ip.id);
				}else
					*id2 = d_ip_id_decode(&pro->ip_id2, 0, 0, *sn);

			}
			break;
		}


		src2 += size;
		field_counter +=size;
		*payload_size -= size + 1;
	} else {
		// No extention
		*sn_size = 5;
		*sn = d_lsb_decode(&pro->sn, *sn , *sn_size);

		*id = d_ip_id_decode(&pro->ip_id1, 0, 0, *sn);
		if( pro->multiple_ip)
			*id2 = d_ip_id_decode(&pro->ip_id1, 0, 0, *sn);
		*payload_size -= 1;
	}


	// Random IP ID ?
	if (active1->rnd) {
		*id = ntohs(*((u16 *)src2));
		src2 +=2; field_counter +=2; *payload_size -= 2;
	}

	// Multiple ip-header

	if (( pro->multiple_ip )&&( active2->rnd )){
		*id2 = ntohs(*((u16 *)src2));
		src2 +=2; field_counter +=2; *payload_size -= 2;
	}


	// Header write
	if (pro->multiple_ip){
		write_uncompressed_ip4(active1, *id, dest, *payload_size+sizeof(struct iphdr));
		write_uncompressed_ip4(active2, *id2, dest+sizeof(struct iphdr),*payload_size);
	}else{
		write_uncompressed_ip4(active1, *id, dest, *payload_size);
	}

	// CRC-check
	*calc_crc = crc_calculate(CRC_TYPE_7, dest, (pro->multiple_ip + 1) * sizeof(struct iphdr));

	return field_counter;
}





// ---------------------------------------------------------

/* Decode extention 0.
 *    - SN value is expanded with 3 lower bits
 *    - IP-ID is replaced with 3 bits
 */
static int decode_extention0(unsigned char * src, int * sn, int * ip_id)
{
	*sn = *sn << 3 | GET_BIT_3_5(src);
	*ip_id = GET_BIT_0_2(src);
	return 1;
}

/* Decode extention 1
 *    - SN value is expanded with 3 lower bits
 *    - IP-ID is replaced with 11 bits
 */
static int decode_extention1(unsigned char * src, int * sn, int * ip_id)
{
	*sn = *sn << 3 | GET_BIT_3_5(src);
	*ip_id = GET_BIT_0_2(src);

	src++;
	*ip_id = *ip_id << 8 | *src;

	return 2;
}

/* Decode extention 2
 *    - SN value is expanded with 3 lower bits
 *    - IP-ID is replaced with 8 bits
 */
static int decode_extention2(unsigned char * src, int * sn, int * ip_id, int * ip_id2)
{

	*sn = *sn << 3 | GET_BIT_3_5(src);
	*ip_id2 = GET_BIT_0_2(src);
	src++;

	*ip_id2 = *ip_id2 << 8 | *src;
	src++;

	*ip_id = *src;
	return 3;
}

/* Decode extention 3
 *    - Updates random fields in the s_iponly_change
 *    - May update the SN value with 8 lower bits. sn_size is then changed
 */
static int decode_extention3(
	unsigned char * src,
	struct sd_context * context,
	struct sd_rohc * state,
	int * sn,
	int * sn_size,
	int * ip_id_changed,
	int * update_id2
	)
{
	struct s_iponly_profile_data * pro = context->data;
	struct s_iponly_change * active1 = pro->active1;
	struct s_iponly_change * active2 = pro->active2;
	unsigned char * org = src;
	unsigned char * fields  = src + 1;
	int S = GET_BIT_5(src);
	int mode = GET_BIT_3_4(src);
	int I = GET_BIT_2(src);
	int ip = GET_BIT_1(src);
	int ip2 = GET_BIT_0(src);
	int size;

	src++;

	if (ip) fields++;
	if (ip2) fields++;

	if (S) {
		*sn = (*sn << 8) + *fields;
		*sn_size += 8;
		fields++;
	}

	if (ip) {
		if(pro->multiple_ip){
			size = decode_inner_header_flags(src, fields, &active2->ip,
			&active2->rnd, &active2->nbo);
		}else
			size = decode_inner_header_flags(src, fields, &active1->ip,
			&active1->rnd, &active1->nbo);
		fields += size;
	}
	if (I) {
		if(pro->multiple_ip){
			active2->ip.id = *((u16 *)fields);
			fields += 2;
			*update_id2 = 1;
		}else{
			active1->ip.id = *((u16 *)fields);
			fields += 2;
			*ip_id_changed = 1;
		}
	}
	if (ip2) {
		size = decode_outer_header_flags(src, fields, &active1->ip,
			&active1->rnd, &active1->nbo, ip_id_changed);
		fields += size;
	}

	if(mode != context->mode){
		rohc_debugf(2,"mode is not equal on decomp and comp.\n");
		d_change_mode_feedback(state, context);
	}
	return fields - org;
}

// --------------------------------------------------------- Local utils functions

// Deceide what package type
static int package_type(const unsigned char * p)
{
	if (!GET_BIT_7(p)) {
		return PACKAGE_UO_0;
	} else if (!GET_BIT_6(p)) {
		return PACKAGE_UO_1;
	} else if (GET_BIT_5_7(p) == 6) {
		return PACKAGE_UOR_2;
	} else if (*p == 0xf8) {
		return PACKAGE_IR_DYN;
	} else if ( (*p & 0xfe) == 0xfc) {
		return PACKAGE_IR;
	} else {
		return PACKAGE_UNKNOWN;
	}
}

// Copy the active-structs to last-structs.
static void syncronize(struct s_iponly_profile_data * pro)
{
	memcpy(pro->last1, pro->active1, sizeof(struct s_iponly_change));
	memcpy(pro->last2, pro->active2, sizeof(struct s_iponly_change));
}

// Copy the last-structs to the active-structs.
static void sync_on_failure(struct s_iponly_profile_data * pro)
{
	memcpy(pro->active1, pro->last1, sizeof(struct s_iponly_change));
	memcpy(pro->active2, pro->last2, sizeof(struct s_iponly_change));
}

// Deceide the extention type
static int extention_type(const unsigned char * p)
{
	return GET_BIT_6_7(p);
}

/* Decode inner IP flags and fields. Storage the values
 * in a IP-head struct.
 */
static int decode_inner_header_flags(
	unsigned char * flags,
	unsigned char * fields,
	struct iphdr * ip,
	int * rnd, int * nbo)
{
	int size = 0;
	if (GET_BIT_7(flags)) {
		ip->tos = *fields;
		fields++; size++;
	}
	if (GET_BIT_6(flags)) {
		ip->ttl = *fields;
		fields++; size++;
	}
	if (GET_BIT_5(flags)) {
		ip->frag_off = htons(IP_DF);
	} else {
		ip->frag_off = 0;
	}
	if (GET_BIT_4(flags)) {
		ip->protocol = *fields;
		fields++; size++;
	}
	if (GET_BIT_3(flags)) {
		// TODO, list compression
		rohc_debugf(0,"Listcompression is not supported\n");
	}
	*nbo = GET_BIT_2(flags);
	*rnd = GET_BIT_1(flags);
	return size;
}

/* Decode outer IP flags and fields. Storage the values
 * in a IP-head struct.
 */
static int decode_outer_header_flags(
	unsigned char * flags,
	unsigned char * fields,
	struct iphdr * ip,
	int * rnd, int * nbo,
	int * updated_id)
{
	int size = 0;
	if (GET_BIT_7(flags)) {
		ip->tos = *fields;
		fields++; size++;
	}
	if (GET_BIT_6(flags)) {
		ip->ttl = *fields;
		fields++; size++;
	}
	if (GET_BIT_5(flags)) {
		ip->frag_off = htons(IP_DF);
	} else {
		ip->frag_off = 0;
	}
	if (GET_BIT_4(flags)) {
		ip->protocol = *fields;
		fields++; size++;
	}
	if (GET_BIT_3(flags)) {
		// TODO, list compression
		rohc_debugf(0,"Listcompression is not supported\n");
	}
	*nbo = GET_BIT_2(flags);
	*rnd = GET_BIT_1(flags);

	if (GET_BIT_0(flags)) {
		ip->id = *((u16 *)fields);
		fields += 2; size += 2;
		*updated_id = 1;
	}
	return size;
}

/* Write a uncompressed IP v4 header */
static void write_uncompressed_ip4(
	struct s_iponly_change * active,
	int ip_id,
	unsigned char * dest,
	int payload_size
	)
{
	struct iphdr * ip = (struct iphdr *)dest;

	// --- static & some changing
	memcpy(dest, &active->ip, sizeof(struct iphdr));

	// --- ip-id
	ip->id = htons(ip_id);
	if (!active->nbo) ip->id = __swab16(ip->id);

	//--- Static-known fields
	ip->ihl = 5;

	//--- Interfered fields
	ip->tot_len = htons(payload_size + (ip->ihl * 4));
	ip->check = 0;
	ip->check = ip_fast_csum(dest, ip->ihl);
}



/*  This function try to repair the SN in one of two different ways
 *
 */
static int act_on_crc_failure(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * src,
	unsigned char * dest,
	int sn_size,
	int * sn,
	int sn_bits,
	int * payload_size,
	int * id,
	int id_size,
	int * id2,
	int * calc_crc,
	int * real_crc,
	int ext
	)
{
	struct s_iponly_profile_data * pro = context->data;

	int sn_ref = 0, intervall = 0;
	int sn_curr2 = 0, sn_curr1 = 0;
	int sn_update = 0;

	sync_on_failure(pro);

	if(CRC_ACTION){
		rohc_debugf(0,"Try to repair the CRC\n");

		if(pro->last_packet_time) //if last packettime == 0 then IR was just sent and ...
			intervall = pro->current_packet_time - pro->last_packet_time;

		if(intervall > ((1 << sn_size)*(pro->inter_arrival_time))){
			rohc_debugf(0,"ROHC: repair with the assumption:  SN LSB wraparound\n");
			rohc_debugf(2,"inter_arrival_time = %d and current intervall is = %d\n", pro->inter_arrival_time, intervall);
			rohc_debugf(2,"add %d to SN\n", 1 << sn_size);

			// Try and update the SN
			sn_ref = d_get_lsb_ref(&pro->sn);
			sn_ref += (1 << sn_size);
			d_lsb_sync_ref(&pro->sn);
			d_lsb_update(&pro->sn, sn_ref);
			*sn = d_lsb_decode(&pro->sn, sn_bits, sn_size );

			pro->counter = 0;

		}else{
			// try with the old sn_ref value

			rohc_debugf(0,"ROHC: repair with the assumption: incorrect SN-updates\n");
			rohc_debugf(2,"inter_arrival_time = %d and current intervall is = %d\n", pro->inter_arrival_time, intervall);

			// save current referece value
			sn_curr1 = d_get_lsb_ref(&pro->sn);
			// test with old reference value
			d_lsb_update(&pro->sn, d_get_lsb_old_ref(&pro->sn));

			sn_curr2 = d_lsb_decode(&pro->sn, sn_bits, sn_size );

			if( sn_curr2 == *sn){
				rohc_debugf(2,"with old ref value we get the same sn\n");
				return ROHC_ERROR_CRC;
			}
			*sn = sn_curr2;
			d_lsb_update(&pro->sn, sn_curr2);
			sn_update = 1;
			pro->counter = 0;
		}
		rohc_debugf(2,"Try a new decompression with another sn \n");
		// Try a new decompression with another SN
		switch (pro->package_type){
		case PACKAGE_UO_0:
 		//fall through
		case PACKAGE_UO_1:
			help_to_decode_uo0_and_uo1(context, src, dest, payload_size, sn_bits, sn_size , id, id_size, id2, sn, calc_crc);
			break;
		case PACKAGE_UOR_2:
			*sn = sn_bits;
			help_to_decode_uor2(state, context, src, dest, payload_size, id, id2, sn, &sn_size, sn_bits, ext, calc_crc);
			break;
		default:
			rohc_debugf(0,"(Ip-only) A existing packet?\n");
			d_lsb_update(&pro->sn, sn_curr1);
			return ROHC_ERROR_CRC;
		}

		if (*calc_crc != *real_crc){
			rohc_debugf(0,"ROHC: CRC failure also on the second attempt (calc) %x vs %x (real)\n",*calc_crc, *real_crc);
			pro->counter = 0;
			if(sn_update)
				d_lsb_update(&pro->sn, sn_curr1); //reference curr1 should be used
			sync_on_failure(pro);
			return ROHC_ERROR_CRC;
		}
		//CRC-pass
		rohc_debugf(2,"Update and sync with the new SN then throw away the packet\n");
		pro->counter++;
		update_inter_packet(pro);

		syncronize(pro);

		if(!sn_update){
			d_lsb_sync_ref(&pro->sn);
			d_lsb_update(&pro->sn, *sn);
		}else
			d_lsb_update(&pro->sn, sn_curr2);

		d_ip_id_update(&pro->ip_id1, *id, *sn);
		if (pro->multiple_ip)
			d_ip_id_update(&pro->ip_id2, *id2, *sn);

		return ROHC_ERROR_CRC;

	}else{
		return ROHC_ERROR_CRC;
	}
}

/* Update the inter-packet time, a sort of averange over the last inter-packet times */
static void update_inter_packet(struct s_iponly_profile_data * pro)
{
	int last_time = pro->last_packet_time;
	int delta = 0;
	rohc_debugf(2,"current time = %d and last time = %d\n", pro->current_packet_time, last_time);

	if (last_time)
		delta = pro->current_packet_time - last_time;
	pro->last_packet_time = pro->current_packet_time;
	if (pro->inter_arrival_time){
		pro->inter_arrival_time = (pro->inter_arrival_time >> WEIGHT_OLD) + (delta >> WEIGHT_NEW);

	} else
		pro->inter_arrival_time = delta;

	rohc_debugf(2,"inter_arrival_time = %d and current arrival delta is = %d\n", pro->inter_arrival_time, delta);
}
