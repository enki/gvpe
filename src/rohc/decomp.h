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
//----------------------------------------------------------------------------------------------------------------------------------
#ifndef _DECOMP_H
#define _DECOMP_H
//----------------------------------------------------------------------------------------------------------------------------------
#include "rohc.h"
#include "d_util.h"
#include "comp.h"

#define D_NUM_PROFILES 4
//----------------------------------------------------------------------------------------------------------------------------------
struct sd_decode_data
{
	int cid;
	int addcidUsed;
	int largecidUsed;
	struct sd_context * active;
};
//----------------------------------------------------------------------------------------------------------------------------------
struct sd_statistics
{
	unsigned int packets_received;
	unsigned int packets_failed_crc;
	unsigned int packets_failed_no_context;
	unsigned int packets_failed_package;
	unsigned int packets_feedback;
};
//----------------------------------------------------------------------------------------------------------------------------------
struct sd_rohc
{
	struct sd_context ** context;
	int context_array_size;

	struct s_medium * medium;
	struct sc_rohc * compressor;

	unsigned int maxval;		// updated from GUI
	unsigned int errval;
	unsigned int okval;
	int curval;

	struct sd_statistics statistics;
};
//----------------------------------------------------------------------------------------------------------------------------------
// Medium specific data
//----------------------------------------------------------------------------------------------------------------------------------
struct s_medium
{
	int cid_type;			// large or small cid
	int max_cid;			// maximum cid value
};
//----------------------------------------------------------------------------------------------------------------------------------
// The context structure
//----------------------------------------------------------------------------------------------------------------------------------
struct sd_context
{
	//int last_failed;

	struct s_profile * profile;	// used profile

	void * data;	// profile data

	int mode;	// U_MODE, O_MODE, R_MODE
	int state;	// NO_CONTEXT, STATIC_CONTEXT, FULL_CONTEXT


	int latest_used, first_used; // timestamps..

	// statistics variables..
	int total_uncompressed_size, total_compressed_size;
	int header_uncompressed_size, header_compressed_size; 
	int num_recv_packets, num_recv_ir, num_recv_ir_dyn, num_sent_feedbacks;
	int num_decomp_failures, num_decomp_repairs;
	struct sc_wlsb *total_16_uncompressed, *total_16_compressed;
	struct sc_wlsb *header_16_uncompressed, *header_16_compressed;

	int curval;
};
//----------------------------------------------------------------------------------------------------------------------------------
// The profile structure
//----------------------------------------------------------------------------------------------------------------------------------
struct s_profile
{
	int id;		// 0x0000 fr uncompress, etc
	char *version;
	char *description;

	int (*decode) (
		struct sd_rohc * state,
		struct sd_context * context,
		unsigned char * src,
		int size,
		int second_byte,
		unsigned char * dest
		);

	int (*decode_ir) (
		struct sd_rohc * state,
		struct sd_context * context,
		unsigned char * src,
		int size,
		int last_bit,
		unsigned char * dest
	);

	void *(*allocate_decode_data)(void);
	void (*free_decode_data)(void *);

	int (*detect_ir_size)(unsigned char * first_byte, int second_byte_add);
	int (*detect_ir_dyn_size)(unsigned char * first_byte, struct sd_context * context);
	int (*get_sn)(struct sd_context * context);
};
//----------------------------------------------------------------------------------------------------------------------------------
void context_array_increase(struct sd_rohc * state, int highestcid);
void context_array_decrease(struct sd_rohc * state);

struct sd_context * find_context(struct sd_rohc * state, int cid);
struct sd_context * context_create(struct sd_rohc * state, int with_cid, struct s_profile * profile);
void context_free(struct sd_context * context);

struct sd_rohc * rohc_alloc_decompressor(struct sc_rohc *compressor);
void rohc_free_decompressor(struct sd_rohc * state);
int rohc_decompress(struct sd_rohc * state, unsigned char * ibuf, int isize, unsigned char * obuf, int osize );

int rohc_d_statistics(struct sd_rohc *, char *buffer); // store statistics about decompressor
int rohc_d_context(struct sd_rohc *, int index, char *buffer); // store statistics about a context

int rohc_decompress_both(struct sd_rohc * state, unsigned char * ibuf, int isize, unsigned char * obuf, int osize, int large);

int d_decode_header(struct sd_rohc * state, unsigned char * ibuf, int isize, unsigned char * obuf, int osize, struct sd_decode_data * ddata);
int d_decode_feedback(struct sd_rohc * state, unsigned char * ibuf);
int d_decode_feedback_first(struct sd_rohc * state, unsigned char ** walk, const int isize);

void d_operation_mode_feedback(struct sd_rohc * state, int rohc_status, int cid, int addcidUsed, int largecidUsed, int mode, struct sd_context * ctxt);
void d_change_mode_feedback(struct sd_rohc * state, struct sd_context * ctxt);

int rohc_ir_packet_crc_ok(unsigned char * walk, const int largecid, const int addcidUsed, const struct s_profile * profile);
int rohc_ir_dyn_packet_crc_ok(unsigned char * walk, const int largecid, const int addcidUsed, const struct s_profile * profile, struct sd_context * context);

void clear_statistics(struct sd_rohc * state);
void usergui_interactions(struct sd_rohc * state, int feedback_maxval);
//----------------------------------------------------------------------------------------------------------------------------------
#endif
//----------------------------------------------------------------------------------------------------------------------------------
