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
/***************************************************************************
 * File:        c_util.h                                                   *
 * Description: utility functions for the compressor                       *
 ***************************************************************************/

#ifndef _C_UTIL_H
#define _C_UTIL_H

#include "rohc.h"

 /////////////////////////////////////////////////////////////////////
// W-LSB: Window based Least Significant Bits encoding

struct sc_window {
	int sn;
	int time;
	int value;
	boolean used;
};

struct sc_wlsb {
 	int windowWidth;
 	struct sc_window *window; // windowWidth number of sc_window..

	int oldest;	// points to the oldest entry in the window
	int next;	// keeps track of the current position in the window

 	int bits;
 	int p;
};


// Create new window..
struct sc_wlsb *c_create_wlsb(int bits, int windowWidth, int p);

// Print window content
void print_wlsb_stats(struct sc_wlsb * s);

// Add value to window with the given sequence number and timestamp
void c_add_wlsb(struct sc_wlsb *, int sn, int time, int value);

// Get minimum number of bits necessary (k) of value needed for 
// decompressor to decode correctly
int c_get_k_wlsb(struct sc_wlsb *, int value);

// Acknowledge (remove older values) from window based on the sequence number
void c_ack_sn_wlsb(struct sc_wlsb *, int sn);

// Acknowledge (remove odler values) from window based on the timestamp
void c_ack_time_wlsb(struct sc_wlsb *, int time);

// Unallocate all memory used in the WLSB structure
void c_destroy_wlsb(struct sc_wlsb *);

// Calculate the sum of the values in window (used for a statistics window)
int c_sum_wlsb(struct sc_wlsb *);

// Calculate the mean-value in window (used for a statistics window)
int c_mean_wlsb(struct sc_wlsb *);

void c_print_wlsb(struct sc_wlsb *);

/////////////////////////////////////////////////////////////////////
// SDVL: Self Described Variable Length  encoding

// returns number of bytes needed to represent value
int c_bytesSdvl(int value);

// returns false if value is to big (value>2^29)
boolean c_encodeSdvl(unsigned char *dest, int value);

// returns add-cid value
unsigned char c_add_cid(int cid);

/* Function that sets the cid_values it will set the cids proper in the
pointer dest, the function takes a pointer called first_position where you get the position
to place your first byte, the second byte can be placed in the value that this function returns.
*/
int code_cid_values(struct sc_context *context,unsigned char *dest,int max_size,int *first_position);

/////////////////////////////////////////////////////////////////////
// CRC

#define CRC_TYPE_3 1
#define CRC_TYPE_7 2
#define CRC_TYPE_8 3

unsigned int crc_calculate(int type, unsigned char *, int length);
int crc_get_polynom(int type);
void crc_init_table(unsigned char *table, unsigned char polynum);

#endif
