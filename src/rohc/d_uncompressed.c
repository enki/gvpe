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

// The Uncompressed profile in decompressor

#include "rohc.h"
#include "decomp.h"

#include "d_uncompressed.h"

// Allocate profile-data, nothing to allocate
void * uncompressed_allocate_decode_data(void)
{
	return (void*)1;
}

// To deallocate profile data, no data to free
void uncompressed_free_decode_data(void * p)
{
}

// Decode an IR-package and initalize context
int uncompressed_decode_ir(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * src,
	int copy_size,
	int dynamic_present,
	unsigned char * dest
	)
{
 	unsigned char * s = src;
	unsigned char * d = dest;

	context->state = ROHC_FULL_CONTEXT;

	if (copy_size == 0) return ROHC_OK_NO_DATA;

	memcpy(d, s, copy_size);
	return copy_size;
}

// Calculate the size of data in an IR-package.
// return : size or zero.
int uncompressed_detect_ir_size(unsigned char * first_byte, int second_byte_add)
{
	int ret = 10;
	int d = GET_BIT_0(first_byte);
	if (d) ret += 5 + 2;
	if (first_byte[second_byte_add + 2] != 0x40) return 0;

	return ret;
}

// Calculate the size of data in an IR-package.
// return : size or zero.
int uncompressed_detect_ir_dyn_size(unsigned char * first_byte, struct sd_context *c)
{
	return 7;
}

// Decode all package except IR-package.
int uncompressed_decode(
	struct sd_rohc * state,
	struct sd_context * context,
	unsigned char * src,
	int size,
	int second_byte,
	unsigned char * dest
	)
{
	unsigned char * s = src;
	unsigned char * d = dest;

	if (context->state == ROHC_NO_CONTEXT) return ROHC_ERROR;

	*d = GET_BIT_0_7(src);
	d += 1;
	s += second_byte;

	memcpy(d, s, size - second_byte);
	return (size - second_byte + 1);
}

static int uncompressed_get_sn(struct sd_context * dummy)
{
	return 0;
}

static struct s_profile d_uncomp_profile = {0,"1.0", "Uncompressed / Decompressor",
	uncompressed_decode,
	uncompressed_decode_ir,
	uncompressed_allocate_decode_data,
	uncompressed_free_decode_data,
	uncompressed_detect_ir_size,
	uncompressed_detect_ir_dyn_size,
	uncompressed_get_sn
	};

struct s_profile * uncompressed_profile_create()
{
	return &d_uncomp_profile;
}



