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
 * File:        comp.h                                                     *
 * Description: Functions and structures for the compressor framework      *
 ***************************************************************************/

#ifndef _COMP_H
#define _COMP_H

#include "rohc.h"

/////////////////////////////////////////////////////////////////////
// Public functions

struct sc_rohc;
struct sc_context;
struct sc_feedback;

/* Allocate space for a compressor (transmit side) */
void    *rohc_alloc_compressor(int max_cid);

/* Free space used by a compressor */
void    rohc_free_compressor(struct sc_rohc *compressor);

/* Compress a packet */
int     rohc_compress(struct sc_rohc *compressor, unsigned char *ibuf, int isize,
                           unsigned char *obuf, int osize);

/* Store static info (about profiles etc) in the buffer (no compressor is needed) */
int	rohc_c_info(char *buffer);

/* Store compression statistics for a compressor in the buffer */
int	rohc_c_statistics(struct sc_rohc *compressor, char *buffer);

/* Store context statistics for a compressor in the buffer */
int	rohc_c_context(struct sc_rohc *compressor, int index, char *buffer);

/* Get compressor enabled/disable status */
int     rohc_c_is_enabled(struct sc_rohc *compressor);

/* Is the compressor using small cid? */
int     rohc_c_using_small_cid(struct sc_rohc * ch);


// Functions used by rohc's proc device

void rohc_c_set_header(struct sc_rohc *compressor, int value);
void rohc_c_set_mrru(struct sc_rohc *compressor, int value);
void rohc_c_set_max_cid(struct sc_rohc *compressor, int value);
void rohc_c_set_large_cid(struct sc_rohc *compressor, int value);
void rohc_c_set_connection_type(struct sc_rohc *compressor, int value);
void rohc_c_set_enable(struct sc_rohc *compressor, int value);

// These functions are used by the decompressor to send feedback..

// Add this feedback to the next outgoing ROHC packet:
void c_piggyback_feedback(struct sc_rohc *,unsigned char *, int size);

// Deliver received feedback in in decompressor to compressor..
void c_deliver_feedback(struct sc_rohc *,unsigned char *packet, int size);


/////////////////////////////////////////////////////////////////////
// Profiles

#define C_NUM_PROFILES 4

// The generic interface to compression profiles

// To implement a new profile you need to implement the following interface
// (see c_ip.c or c_udp.c for examples) and add it to the "c_profiles" array
// in comp.c

struct sc_profile {
        unsigned short protocol; // IP-Protocol
        unsigned short id;       // Profile ID
	char *version;           // Version string
	char *description;       // Description string

        // Called when a new context should be initialized, based on the given packet
        int (*create)(struct sc_context *context, const struct iphdr *packet);

        // Destroy profile specific data in context
        void (*destroy)(struct sc_context *context);

        // Check if the packet belongs to the given context (using STATIC-DEF fields etc) */
        int (*check_context)(struct sc_context *context, const struct iphdr *packet);

        // Compress the packet using the given context. Payload_offset indicates where the
	// payload starts. Returns the size of the compressed packet or <=0 in case of an
	// error..
        int (*encode)(struct sc_context *, const struct iphdr *packet, int packet_size,
			unsigned char *dest, int dest_size, int *payload_offset);

        // Called when feedback to the context arrives..
        void (*feedback)(struct sc_context *, struct sc_feedback *);
};

struct sc_profile *c_get_profile_from_protocol(struct sc_rohc *comp, int protocol);
struct sc_profile *c_get_profile_from_id(struct sc_rohc *comp, int profile_id);

////////////////////////////////////////////////////////////////////////

typedef enum {U=1,O=2,R=3}    C_MODE;
typedef enum {IR=1,FO=2,SO=3} C_STATE;

struct sc_context {
        int used; // 1==used, 0==unused
        int latest_used; // time when this context was created
	int first_used; // time when this context was latest used

        int cid;
        int profile_id;
        struct sc_profile *profile;

        struct sc_rohc *compressor;

        // Parameters and initial values common for all
        // profiles:

        C_MODE c_mode;
        C_STATE c_state;

        int nbo, rnd;
	int nbo2, rnd2; // for second ip header if available

	// Statistics information
	int total_uncompressed_size, total_compressed_size;
	int header_uncompressed_size, header_compressed_size;
	int num_send_packets, num_send_ir, num_send_ir_dyn, num_recv_feedbacks;
	struct sc_wlsb *total_16_uncompressed, *total_16_compressed;
	struct sc_wlsb *header_16_uncompressed, *header_16_compressed;


        // Profile specific context here:
        void *profile_context;
};


// Create a new context
struct sc_context *c_create_context(struct sc_rohc *, struct sc_profile *profile, struct iphdr *ip);

// Find a context that match the given profile and IP-packet
struct sc_context *c_find_context(struct sc_rohc *, struct sc_profile *profile, struct iphdr *ip);

// Find a context given the CID
struct sc_context *c_get_context(struct sc_rohc *, int cid);
/////////////////////////////////////////////////////////////////////

struct sc_feedback {
	unsigned char size;  // =field(size) om field(code)==0, annars =field(code)
	int cid;

	int type;   // 1=FEEDBACK-1, 2=FEEDBACK-2

	unsigned char *data; // whole feedback packet exluding first feedback-type octet
	int specific_offset;
	int specific_size;

	// feedback-2 only:
	enum {ACK,NACK,STATIC_NACK,RESERVED} acktype; // 0=ACK, 1=NACK, 2=STATIC-NACK, 3=RESERVED
};

/////////////////////////////////////////////////////////////////////

#define FEEDBACK_BUFFER_SIZE 10 // Number of outgoing feedbacks that can be queued..

struct sc_rohc {
  int enabled;

  int max_cid;   // smallCID = [0-15], largeCID = [0-65535]
  int large_cid;

  int num_used;
  int num_allocated;
  struct sc_context *contexts; // allokeras om vid behov.

  int mrru; // Maximum reconstructed reception unit (== 0)
  int max_header_size; // Maximum header size that will be compressed
  int connection_type;

  int profiles[C_NUM_PROFILES];

  unsigned char *feedback_buffer[FEEDBACK_BUFFER_SIZE];
  unsigned int  feedback_size  [FEEDBACK_BUFFER_SIZE];
  int feedback_pointer;

  int num_packets; // total number of sent packets
  int total_compressed_size, total_uncompressed_size;

  struct sc_rohc *feedback_for;

};

int c_get_feedback(struct sc_rohc *, unsigned char *); 
void c_add_feedback(struct sc_rohc *, unsigned char *, int size);

/////////////////////////////////////////////////////////////////////

#endif
