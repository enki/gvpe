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
/***************************************************************************
 * File:        comp.c                                                     *
 * Description: description                                                *
 ***************************************************************************/

#include "rohc.h"
#include "comp.h"
#include "c_util.h"

#include "decomp.h"
#include "d_util.h"

///////////////////////////////////////////////////////////////////////
// Profile definitions and variables

// Profile IDs
#define ROHC_PROFILE_UNCOMPRESSED     0
#define ROHC_PROFILE_UDP     2
#define ROHC_PROFILE_UDPLITE 8
#define ROHC_PROFILE_IP      4

// The profiles.. in c_ip.c, c_udp.c, c_udp_lite.c, c_uncompressed.c
extern struct sc_profile c_ip_profile;
extern struct sc_profile c_uncompressed_profile;
extern struct sc_profile c_udp_profile;
extern struct sc_profile c_udp_lite_profile;

/* C_NUM_PROFILES is defined in comp.h */

// Pointers to all profiles:
static struct sc_profile *c_profiles[C_NUM_PROFILES] = {
	&c_udp_profile,
	&c_udp_lite_profile,
	&c_ip_profile,
	&c_uncompressed_profile
};

////////////////////////////////////////////////////////////////////////
// Feedback variables
static void c_piggyback_destroy(struct sc_rohc *);
static int c_piggyback_get(struct sc_rohc *, unsigned char *buf);

////////////////////////////////////////////////////////////////////////
// Context definitions functions
static void c_destroy_contexts(struct sc_rohc *);
static int c_create_contexts(struct sc_rohc *);
static int c_alloc_contexts(struct sc_rohc *, int num);


////////////////////////////////////////////////////////////////////////
// Public functions

/* Allocate space for a compressor (transmit side) */
void *rohc_alloc_compressor(int max_cid)
{

	struct sc_rohc *comp;
	int i;
	rohc_debugf(1, "ROHC: Allocating compressor\n");

	comp = kmalloc(sizeof(struct sc_rohc), GFP_ATOMIC);
	if (comp == NULL) {
	  rohc_debugf(0, "rohc_alloc_compressor() no mem for compressor!\n");
	  return NULL;
	}

	comp->enabled = 1;
	comp->feedback_pointer = 0;
	comp->max_cid = max_cid;
	comp->large_cid = 0;
	comp->mrru = 0;

	for (i = 0; i < C_NUM_PROFILES; i++) {
		comp->profiles[i] = 0;
	}

	comp->num_packets = 0;
	comp->total_compressed_size = 0;
	comp->total_uncompressed_size = 0;

	for (i=0; i<FEEDBACK_BUFFER_SIZE; i++) {
	  comp->feedback_buffer[i] = (void*)0;
	  comp->feedback_size[i] = 0;
	}

	if (!c_create_contexts(comp)) {
		return NULL;
	}

	return comp;
}


/* Free space used by a compressor */
void rohc_free_compressor(struct sc_rohc *comp) {

	rohc_debugf(2,"ROHC: Free contexts\n");
	// free memory used by contexts..
	c_destroy_contexts(comp);

	rohc_debugf(2,"ROHC: Free piggybacks\n");
	// destroy unsent piggybacked feedback
	c_piggyback_destroy(comp);

	// free profile array
	rohc_debugf(2,"ROHC: Free profiles\n");

	// free compressor..
	kfree(comp);
}


/* Compress a packet */
int     rohc_compress(struct sc_rohc *comp, unsigned char *ibuf, int isize,
                   unsigned char *obuf, int osize)
{
	struct iphdr *ip = (struct iphdr *)(ibuf); // + PPP_HDRLEN);
	int proto = ip->protocol;
	struct sc_profile *p;
	struct sc_context *c;
	int feedback_size, payload_size, payload_offset;
	int size, esize;

	if (comp == 0) {
		rohc_debugf(0, "c_compress(): comp=null!\n");
		return 0;
	}

	if (ip->version != 4) {
		rohc_debugf(0, "Wrong IP version (%d)\n", ip->version);
		return 0;
	}

	if (ip->ihl*4 != 20) {
		rohc_debugf(0, "Wrong IP header size (%d)\n", ip->ihl);
		return 0;
	}

	// Get profile based on ip->protocol..
	rohc_debugf(2,"c_compress(): protocoll %d \n", proto);
	p = c_get_profile_from_protocol(comp, proto);

	if (p == 0) // use IP-profile if no profile was found based on the protocol
	{
		rohc_debugf(2,"c_compress(): Using IP profile\n");
	        p = c_get_profile_from_id(comp, ROHC_PROFILE_IP);

		if (p == 0) { // Use Uncompressed-profile if IP profile was not found..
			rohc_debugf(0,"c_compress(): Using UNCOMPRESSED profile\n");
			p = c_get_profile_from_id(comp, ROHC_PROFILE_UNCOMPRESSED);

			if (p == 0) {
				rohc_debugf(0,"c_compress(): No profile found, giving up\n");
				return 0;
			}
		}
	}


	// Get Context using help from the profiles..
	c = c_find_context(comp, p, ip);

	if (c==0) // skapa nytt context
		c = c_create_context(comp, p, ip);
	else if (c==(struct sc_context*)-1) { 
		// the profile dedected anomalities in ip-packet (such as fragments) that made 
		// it un-compressible - switch to Uncompressed profile!
		
		p = c_get_profile_from_id(comp, ROHC_PROFILE_UNCOMPRESSED);
		c = c_find_context(comp, p,  ip); // find the uncompressed
		if (c==0)
			c = c_create_context(comp, p, ip);
	}


	c->latest_used = get_milliseconds();

        // copy PPP header
	//memcpy(obuf, rptr, PPP_HDRLEN);
        // change protocol in ppp header to rohc-over-ppp identifier???
        size = 0; //PPP_HDRLEN;

        // add feedback
        feedback_size = c_piggyback_get(comp, obuf);
        obuf += feedback_size;
        size += feedback_size;

	// use profile to compress packet
	esize = p->encode(c, ip, isize, obuf, osize - size, &payload_offset);

	if (esize < 0) { // error while compressing.. use uncompressed..
		if (c->num_send_packets <= 1) { // free context
			c->profile->destroy(c);
			c->used = 0;
		}

		p = c_get_profile_from_id(comp, ROHC_PROFILE_UNCOMPRESSED);
		c = c_find_context(comp, p,  ip); // find the uncompressed
		if (c==0)
			c = c_create_context(comp, p, ip);

		if (c!=0)
			esize = p->encode(c, ip, isize, obuf, osize - size, &payload_offset);
		else {
			rohc_debugf(0, "c_compress(): Failed to create uncompressed context!\n");
			return 0;
		}
	}

	size += esize;
	obuf += esize;

	payload_size = ntohs(ip->tot_len) - payload_offset;

	rohc_debugf(2,"c_compress(): ROHC size=%d, Payload size=%d (totlen=%d, ihl=%d), outbut buffer size=%d\n", size, payload_size, ntohs(ip->tot_len), ip->ihl*4, osize);

	if (size + payload_size > osize) // packet to big!!!
	{
		// do uncompressed!!
		rohc_debugf(0,"ROHC packet to large (osize=%d, isize=%d)\n", size+payload_size, isize);
		return 0;
	}

	// copy payload to rohc packet..
	memcpy(obuf, ((unsigned char*)ip) + payload_offset, payload_size);

	obuf += payload_size;
	size += payload_size;

	// Update statistic..
	comp->num_packets ++;
	comp->total_uncompressed_size += isize;
	comp->total_compressed_size += size;

	c->total_uncompressed_size += isize;
	c->total_compressed_size += size;
	c->header_uncompressed_size += payload_offset;
	c->header_compressed_size += esize;
	c->num_send_packets ++;
	c_add_wlsb(c->total_16_uncompressed, 0, 0, isize);
	c_add_wlsb(c->total_16_compressed, 0,0, size);
	c_add_wlsb(c->header_16_uncompressed, 0, 0, payload_offset);
	c_add_wlsb(c->header_16_compressed, 0,0, esize);

	return size;
}

// Used in the handshake to active profiles that are can be used
void rohc_activate_profile(struct sc_rohc * comp, int profile)
{
	int i;
	for (i = 0; i < C_NUM_PROFILES; i++) {
		if (c_profiles[i]->id == profile) {
			comp->profiles[i] = 1;
			return;
		}
	}
	rohc_debugf(0, "Unknown ROHC profile with id = %d\n", profile);
}

int rohc_c_using_small_cid(struct sc_rohc * comp)
{
	return !comp->large_cid;
}

void rohc_c_set_header(struct sc_rohc *compressor, int header)
{
	compressor->max_header_size = header;
}

void rohc_c_set_mrru(struct sc_rohc *compressor, int value) {
	compressor->mrru = value;
}

void rohc_c_set_max_cid(struct sc_rohc *compressor, int value) {
	if (compressor->large_cid) {
		if (value > 0 && value < 65536)
			compressor->max_cid = value;
	} else {
		if (value > 0 && value < 16)
			compressor->max_cid = value;
	}
}

void rohc_c_set_large_cid(struct sc_rohc *compressor, int value) {
	if (value) {
		compressor->large_cid = 1;
	} else {
		compressor->large_cid = 0;
		if (compressor->max_cid > 15)
			compressor->max_cid = 15;
	}
}

void rohc_c_set_connection_type(struct sc_rohc *compressor, int value) {
	compressor->connection_type = value;
}

void rohc_c_set_enable(struct sc_rohc *compressor, int value) {
	compressor->enabled = value;
}

int rohc_c_is_enabled(struct sc_rohc *compressor) {
	return compressor->enabled;
}


/* Called by proc_rohc to get information about available profiles (used in usermode ppp for handshake)*/
int	rohc_c_info(char *buffer) {
	int i;

	sprintf(buffer, "%s\n", "---Information");

	//"Profiles: 1 2 3 4"
	sprintf(buffer, "%s%s", buffer, "Profiles:");
	for (i=0; i<C_NUM_PROFILES; i++) {
		sprintf(buffer, "%s%d ", buffer, c_profiles[i]->id);
	}
	sprintf(buffer, "%s\n", buffer);

	return strlen(buffer);
}

/* Called by proc_rohc to get information about the compressor  */
int    rohc_c_statistics(struct sc_rohc *comp, char *buffer)
{
	char *save;
	struct sc_profile *p;
	int i,v;

	save = buffer;

	// Instance part..
	buffer += strlen(buffer);
	sprintf(buffer, "\n---Instance\n");
	buffer += strlen(buffer);
	sprintf(buffer, "CREATOR:%s\n", "LULEA/SMD143/2003");
	buffer += strlen(buffer);
	sprintf(buffer, "VERSION NO:%s\n", "1.0");
	buffer += strlen(buffer);
	sprintf(buffer, "STATUS:%s\n", comp->enabled?"ENABLED":"DISABLED");
	buffer += strlen(buffer);
	sprintf(buffer, "NO COMPRESSED FLOWS:%d\n", comp->num_used);
	buffer += strlen(buffer);
	sprintf(buffer, "TOTAL NO PACKETS:%d\n", comp->num_packets);
	buffer += strlen(buffer);

	if (comp->total_uncompressed_size != 0)
		v = (100 * comp->total_compressed_size) / comp->total_uncompressed_size;
	else
		v = 0;
	sprintf(buffer, "TOTAL COMPRESSION RATIO:%d%%\n", v);
	buffer += strlen(buffer);
	sprintf(buffer, "MAX_CID:%d\n", comp->max_cid);
	buffer += strlen(buffer);
	sprintf(buffer, "MRRU:%d\n", 4); // comp->mrru
	buffer += strlen(buffer);
	sprintf(buffer, "LARGE_CID:%s\n", comp->large_cid?"YES" : "NO");
	buffer += strlen(buffer);
	sprintf(buffer, "CONNECTION_TYPE:%d\n", 3);
	buffer += strlen(buffer);
	sprintf(buffer, "FEEDBACK_FREQ:%d\n", 7); // comp-> ??
	buffer += strlen(buffer);

	// profiles part
	for (i=0; i<C_NUM_PROFILES; i++) {
		p = c_profiles[i];

		sprintf(buffer, "\n---Profile\n");
		buffer += strlen(buffer);
		sprintf(buffer, "PROFILE NO:%d\n", p->id);
		buffer += strlen(buffer);
		sprintf(buffer, "ACTIVE:%s\n", comp->profiles[i]?"YES":"NO");
		buffer += strlen(buffer);
		sprintf(buffer, "VERSION NO:%s\n", p->version);
		buffer += strlen(buffer);
		sprintf(buffer, "PROFILE TYPE:%s\n", p->description);
		buffer += strlen(buffer);
	}

	return strlen(save);
}

/* Called by proc_rohc to get information about a context (cid=index)
 * Returns -2 if index is larger than allocated cids
 * Returns -1 if cid is unused
 * Else returns length if buffer..
 */
int rohc_c_context(struct sc_rohc *comp, int index, char *buffer) {
	struct sc_context *c;
	char *save;
	char *modes[4]= {"error", "U-mode", "O-mode", "R-mode"};
	char *states[4] = {"error", "IR", "FO", "SO"};
	int v;

	// Compressor Contexts
	if (index >= comp->num_allocated)
		return -2;

	c = &comp->contexts[index];
	if (!c->used)
		return -1;

	save = buffer;
	buffer += strlen(buffer);
	sprintf(buffer, "\n%s\n", "---Context");
	buffer += strlen(buffer);
	sprintf(buffer, "CONTEXTTYPE:Compressor\n");
	buffer += strlen(buffer);
	sprintf(buffer, "CID:%d\n", c->cid);
	buffer += strlen(buffer);
	sprintf(buffer, "CID_STATE:%s\n", c->used?"USED":"UNUSED");
	buffer += strlen(buffer);
	sprintf(buffer, "STATE:%s\n", states[c->c_state]);
	buffer += strlen(buffer);
	sprintf(buffer, "MODE:%s\n", modes[c->c_mode]);
	buffer += strlen(buffer);
	sprintf(buffer, "PROFILE:%s\n", c->profile->description);
	buffer += strlen(buffer);

	if (c->total_uncompressed_size != 0)
		v = (100*c->total_compressed_size) / c->total_uncompressed_size;
	else
		v = 0;
	if (v < 0) {
		rohc_debugf(0, "comp: total_compressed_size=%d total_uncompressed_size=%d\n", c->total_compressed_size, c->total_uncompressed_size);
	}
	sprintf(buffer, "TOTALCOMPRATIOALLPACK:%d%%\n", v);
	buffer += strlen(buffer);

	if (c->header_uncompressed_size != 0)
		v = (100*c->header_compressed_size) / c->header_uncompressed_size;
	else
		v = 0;
	sprintf(buffer, "TOTALCOMPRATIOALLPACKHEAD:%d%%\n", v);
	buffer += strlen(buffer);

	if (c->num_send_packets != 0)
		v = c->total_compressed_size / c->num_send_packets;
	else
		v = 0;
	sprintf(buffer, "MEANCOMPPACKSIZEALLPACK:%d\n", v);
	buffer += strlen(buffer);

	if (c->num_send_packets != 0)
		v = c->header_compressed_size / c->num_send_packets;
	else
		v = 0;
	sprintf(buffer, "MEANHEADSIZEALLCOMPHEAD:%d\n", v);
	buffer += strlen(buffer);

	v = c_sum_wlsb(c->total_16_uncompressed);
	if (v != 0)
		v = (100*c_sum_wlsb(c->total_16_compressed)) / v;
	sprintf(buffer, "COMPRATIOLAST16PACK:%d%%\n", v);
	buffer += strlen(buffer);

	v = c_sum_wlsb(c->header_16_uncompressed);
	if (v != 0)
		v = (100*c_sum_wlsb(c->header_16_compressed)) / v;
	sprintf(buffer, "COMPRATIOLAST16PACKHEAD:%d%%\n", v);
	buffer += strlen(buffer);

	v = c_mean_wlsb(c->total_16_compressed);
	sprintf(buffer, "MEANCOMPPACKSIZELAST16PACK:%d\n", v);
	buffer += strlen(buffer);

	v = c_mean_wlsb(c->header_16_compressed);
	sprintf(buffer, "MEANHEADSIZELAST16COMPHEAD:%d\n", v);
	buffer += strlen(buffer);
	sprintf(buffer, "CONTEXTACTIVATIONTIME:%d\n", (get_milliseconds() - c->first_used)/1000);
	buffer += strlen(buffer);
	sprintf(buffer, "CONTEXTIDLETIME:%d\n", (get_milliseconds() - c->latest_used)/1000);
	buffer += strlen(buffer);
	sprintf(buffer, "NOSENTPACKETS:%d\n", c->num_send_packets);
	buffer += strlen(buffer);
	sprintf(buffer, "NOSENTIRPACKETS:%d\n", c->num_send_ir);
	buffer += strlen(buffer);
	sprintf(buffer, "NOSENTIRDYNPACKETS:%d\n", c->num_send_ir_dyn);
	buffer += strlen(buffer);
	sprintf(buffer, "NORECVFEEDBACKS:%d\n", c->num_recv_feedbacks);

	return strlen(save);
}


////////////////////////////////////////////////////////////////////////
// Generic profile functions

// Retrieve a profile given a profile_id
struct sc_profile *c_get_profile_from_id(struct sc_rohc *comp, int profile_id)
{
	int i;
        for (i=0; i<C_NUM_PROFILES; i++)
        {
                if (c_profiles[i]->id == profile_id && comp->profiles[i]==1)
			return c_profiles[i];
        }

        // log this failure maybe..
        return NULL;
}

// Retrieve a profile given a (ip) protocol id
struct sc_profile *c_get_profile_from_protocol(struct sc_rohc *comp, int protocol)
{
	int i;
        for (i=0; i<C_NUM_PROFILES; i++)
        {
                if (c_profiles[i]->protocol == protocol && comp->profiles[i]==1)
			return c_profiles[i];
        }

        return NULL;
}

////////////////////////////////////////////////////////////////////////
// Generic context functions


// Allocate the context array
static int c_alloc_contexts(struct sc_rohc *comp, int num) {
	if (num > comp->max_cid+1)
		num = comp->max_cid+1;

	if (comp->num_allocated < num) {
		struct sc_context *tmp;
		int i;

		tmp = kmalloc(sizeof(struct sc_context) * num, GFP_ATOMIC);
		if (tmp == 0) {
		      rohc_debugf(0,"rohc_alloc_compressor() no mem for contexts!\n");
		      return 0;
		}

		for (i=0; i<num; i++) {
			tmp[i].used = 0;
		}

		if (comp->num_allocated > 0 && comp->contexts) {
			memcpy(tmp,comp->contexts, comp->num_allocated * sizeof(struct sc_context));
                	kfree(comp->contexts);
		}

		for (i=comp->num_allocated; i<num; i++) {
			tmp[i].total_16_uncompressed = c_create_wlsb(32, 16, 0); // create a window with 16 entries..
			tmp[i].total_16_compressed = c_create_wlsb(32, 16, 0);
			tmp[i].header_16_uncompressed = c_create_wlsb(32, 16, 0);
			tmp[i].header_16_compressed = c_create_wlsb(32, 16, 0);
		}

                comp->contexts = tmp;
		comp->num_allocated = num;
	}

	return 1;
}

// Skapa en ny context
struct sc_context *c_create_context(struct sc_rohc *comp, struct sc_profile *profile, struct iphdr *ip) {
	struct sc_context *c;
	int index, i;

	index = 0;

	if (comp->num_used >= comp->max_cid+1) {
		// find oldest or one not in use:
		int minimum;

find_oldest:

		index = 0;
		minimum = 0x7fffffff;
		for (i=0; i<comp->num_allocated; i++) {
			if (comp->contexts[i].used == 0) {
				index = i;
				break;
			} else if (comp->contexts[i].latest_used < minimum) {
				minimum = comp->contexts[i].latest_used;
				index = i;
			}
		}

		if (comp->contexts[index].used) {
			// free memory..
			rohc_debugf(2,"Freeing memory for recycled context (cid=%d)\n", index);
			comp->contexts[index].profile->destroy(&comp->contexts[index]);
		}

	} else if (comp->num_used >= comp->num_allocated) {
		if (!c_alloc_contexts(comp, comp->num_used * 2))
			goto find_oldest;

		index = comp->num_used;
		comp->num_used ++;

	} else{
		index = -1;
		for (i=0; i<comp->num_used; i++) {
			if (comp->contexts[i].used==0) {
				index = i;
				break;
			}
		}

		if (index==-1) {
			index = comp->num_used;
			comp->num_used++;
		}
	}


	c = &comp->contexts[index];

	c->used = 1;
	c->first_used = get_milliseconds();
	c->latest_used = get_milliseconds();

	c->total_uncompressed_size = 0;
	c->total_compressed_size = 0;
	c->header_uncompressed_size = 0;
	c->header_compressed_size = 0;
	c->num_send_packets = 0;
	c->num_send_ir = 0;
	c->num_send_ir_dyn = 0;
	c->num_recv_feedbacks = 0;

       	c->cid = index;

	c->profile = profile;
	c->profile_id = profile->id;

	c->c_mode = U;
	c->c_state = IR;

	c->nbo = 1;
	c->rnd = 0;

	c->nbo2 = 1;
	c->rnd2 = 0;

	c->compressor = comp;
	c->latest_used = get_milliseconds();

	rohc_debugf(1, "Creating context CID=%d (numUsed=%d)\n", c->cid, comp->num_used);

	// Create profile specific context and initialize..
	if (profile->create(c, ip) == 0) {
		c->used = 0;
		return NULL;
	}

	return c;
}



// Find context given a profile and a ip packet..
struct sc_context *c_find_context(struct sc_rohc *comp, struct sc_profile *profile, struct iphdr *ip) {
	int i;
	int ret;
        struct sc_context *c;

	rohc_debugf(2,"c_find_context(): %d\n", comp->num_used);

	for (i=0; i<comp->num_used; i++) {
		c = &comp->contexts[i];

		if (c && !c->used) {
			rohc_debugf(1,"Using unused context CID=%d\n", c->cid);
			return c;
		}
		if (c && c->used && c->profile_id==profile->id) {
			ret = c->profile->check_context(c, ip);

			if (ret==-1)
				return (struct sc_context*)-1;
			if (ret) {
				rohc_debugf(1,"Using context CID=%d\n", c->cid);
				return c;
			}
		}
	}

	rohc_debugf(2,"c_find_context(): No context was found\n");
	return NULL; // no matching context was found..
}


// Get context, given the CID
struct sc_context *c_get_context(struct sc_rohc *comp, int cid) {
	if (cid > comp->num_allocated)
		return NULL;
	if (cid > comp->num_used)
		return NULL;
	if (comp->contexts[cid].used == 0)
		return NULL;

	return &comp->contexts[cid];
}


// Allocate context memory..
static int c_create_contexts(struct sc_rohc *comp) {
	comp->num_used = 0;
	comp->num_allocated = 0;
	comp->contexts = 0;

	return c_alloc_contexts(comp, 4); // start with 4 contexts from the beginning..
}


// Deallocate all contexts including their profile specific context
static void c_destroy_contexts(struct sc_rohc *comp) {
	if (comp->num_allocated > 0) {
		int i;
		for (i=0; i<comp->num_allocated; i++) {

			if (comp->contexts[i].used && comp->contexts[i].profile != 0)
				comp->contexts[i].profile->destroy(&comp->contexts[i]);

			c_destroy_wlsb(comp->contexts[i].total_16_uncompressed);
			c_destroy_wlsb(comp->contexts[i].total_16_compressed);
			c_destroy_wlsb(comp->contexts[i].header_16_uncompressed);
			c_destroy_wlsb(comp->contexts[i].header_16_compressed);

			comp->contexts[i].used = 0;

		}

		kfree(comp->contexts);
	}
}



////////////////////////////////////////////////////////////////////////
// Feedback functions for piggybacking

// Add this feedback to the next outgoing ROHC packet:
void c_piggyback_feedback(struct sc_rohc *comp, unsigned char *feedback, int size) {
	if (comp->feedback_pointer >= FEEDBACK_BUFFER_SIZE) // log this failure maybe?
		return;

	comp->feedback_buffer[comp->feedback_pointer] = kmalloc(size, GFP_ATOMIC);
	if (comp->feedback_buffer[comp->feedback_pointer] == 0) {
	  rohc_debugf(0,"c_piggyback_feedback() no mem for feedback!\n");
	  return;
	}
	memcpy(comp->feedback_buffer[comp->feedback_pointer], feedback, size);
	comp->feedback_size[comp->feedback_pointer] = size;

	comp->feedback_pointer++;
}

// Retrieve one feedback and store in buf. Return length of feedback
static int c_piggyback_get(struct sc_rohc *comp, unsigned char *buf) {
	if (comp->feedback_pointer > 0) {
		int size;
		int index=0;

		comp->feedback_pointer--;
		size = comp->feedback_size[comp->feedback_pointer];
		if (size < 8) {
			buf[index] = 0xf0 | size;
			index++;
		} else {
			buf[index] = 0xf0;
			index++;
			buf[index] = size;
			index++;
		}

		memcpy(buf+index, comp->feedback_buffer[comp->feedback_pointer], size);

		kfree(comp->feedback_buffer[comp->feedback_pointer]);
		comp->feedback_size[comp->feedback_pointer] = 0;

		return index + size;
	}

	// No feedback exists..
	return 0;
}

// Destory memory allocated by the feedback buffer
static void c_piggyback_destroy(struct sc_rohc *comp) {
	int i;

	for (i=0; i<FEEDBACK_BUFFER_SIZE; i++) {
		if (comp->feedback_size[i] > 0 && comp->feedback_buffer[i] != 0)
			kfree(comp->feedback_buffer[i]);
	}
}

////////////////////////////////////////////////////////////////////////
// Feedback functions delivery to right profile/context..


// When feedback is received by the decompressor, this function is called
// and delivers that to the right profile/context..
void c_deliver_feedback(struct sc_rohc *comp, unsigned char *packet, int size) {
        struct sc_context *c;
        struct sc_feedback feedback;
        unsigned char *p = packet;

	feedback.size = size;

	if (comp->large_cid) { // decode large cid.at p[0..3]
		feedback.cid =  d_sdvalue_decode(p);
		p += d_sdvalue_size(p);
	} else {
		if (d_is_add_cid(p)) {
			feedback.cid = d_decode_add_cid(p);
			p++;
		} else
			feedback.cid = 0;
	}

	feedback.specific_size = size - (p - packet);
	rohc_debugf(2,"feedback size = %d\n",feedback.specific_size);
	if (feedback.specific_size == 1)
		feedback.type = 1;  // FEEDBACK-1
	else {
		feedback.type = 2;  // FEEDBACK-2
		feedback.acktype = p[0]>>6;
	}

	feedback.specific_offset = (p - packet);
	feedback.data = kmalloc(feedback.size, GFP_ATOMIC);

	if (feedback.data == 0) {
	  rohc_debugf(0, "c_deliver_feedback(): no mem for feedback data\n");
	  return;
	}

	rohc_debugf(2, "spec size    %d\n",feedback.specific_size);

	memcpy(feedback.data,packet,feedback.size );

	// find cid.. get context
        c = c_get_context(comp,feedback.cid);
        if (c==0){
		// Error: Context was not found..
		rohc_debugf(0, "c_deliver_feedback(): Context not found (cid=%d)\n", feedback.cid);
		kfree(feedback.data);
		return;
	}

	c->num_recv_feedbacks++;

	// deliver feedback to profile with the context..
        c->profile->feedback(c, &feedback);

	kfree(feedback.data);

}



