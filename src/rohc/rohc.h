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
#ifndef _ROHC_H
#define _ROHC_H

// ROHC_DEBUG_LEVEL determines the level of output produced by ROHC module
// 0 == error messages only (useable in kernel module)
// 1 == a few informative messages also
// 2 == more informative messages (useable for user mode debugging)
// 3 == even more informative messages
#define ROHC_DEBUG_LEVEL 0

#define ROHC_OK 	1
#define ROHC_OK_NO_DATA 0
#define ROHC_ERROR	-5
#define ROHC_ERROR_NO_CONTEXT		-1
#define ROHC_ERROR_PACKAGE_FAILED	-2
#define ROHC_FEEDBACK_ONLY		-3
#define ROHC_ERROR_CRC			-4

#define ROHC_TRUE 	1
#define ROHC_FALSE	0

typedef unsigned char boolean;

#define ROHC_LARGE_CID	1
#define ROHC_SMALL_CID	2

#define ROHC_U_MODE	1
#define ROHC_O_MODE	2
#define ROHC_R_MODE	3

#define ROHC_NO_CONTEXT		1
#define ROHC_STATIC_CONTEXT	2
#define ROHC_FULL_CONTEXT	3

#define GET_BIT_0_2(x)		((*x) & 0x07)
#define GET_BIT_0_4(x)		((*x) & 0x1f)
#define GET_BIT_0_3(x)          ( ((*x) & 0x0f) )
#define GET_BIT_0_5(x)		((*x) & 0x3f)
#define GET_BIT_0_6(x)		((*x) & 0x7f)
#define GET_BIT_0_7(x)		((*x) & 0xff)

#define GET_BIT_1_7(x)		( ((*x) & 0xfe) >> 1 )
#define GET_BIT_3_4(x)		( ((*x) & 0x18) >> 3 )
#define GET_BIT_3_5(x)		( ((*x) & 0x38) >> 3 )
#define GET_BIT_3_6(x)		( ((*x) & 0x78) >> 3 )
#define GET_BIT_3_7(x)		( ((*x) & 0xf8) >> 3 )
#define GET_BIT_4_7(x)		( ((*x) & 0xf0) >> 4 )
#define GET_BIT_5_7(x)		( ((*x) & 0xe0) >> 5 )
#define GET_BIT_6_7(x)		( ((*x) & 0xc0) >> 6 )

#define GET_DUAL_0_4_AND_7(x, y) ( ((*x) & 0x1f) << 1 | ( (*y) & 0x01 ) )
#define GET_DUAL_0_2_AND_ALL(x, y) ( ((*x) & 0x03) << 1 | ( (*y) & 0xff ) )

#define GET_BIT_0(x)		((*x) & 0x01)
#define GET_BIT_1(x)		((*x) & 0x02)
#define GET_BIT_2(x)		((*x) & 0x04)
#define GET_BIT_3(x)		((*x) & 0x08)
#define GET_BIT_4(x)		((*x) & 0x10)
#define GET_BIT_5(x)		((*x) & 0x20)
#define GET_BIT_6(x)		((*x) & 0x40)
#define GET_BIT_7(x)		((*x) & 0x80)

// Convert GET_BIT_x values to 0 or 1..
// example: GET_REAL( GET_BIT_5(data_ptr) );
#define GET_REAL(x)	( (x) ? 1 : 0 )

#define C_WINDOW_WIDTH 16


// Defines for the compressor profiles

#define GET_DF(x) ((ntohs(x)>>14)&1)

#define MOD_TOS 0x01
#define MOD_TOT_LEN 0x02
#define MOD_ID 0x04
#define MOD_FRAG_OFF 0x08
#define MOD_TTL 0x10
#define MOD_PROTOCOL 0x20
#define MOD_CHECK 0x40
#define MOD_SADDR 0x80
#define MOD_DADDR 0x0100

#define c_IR 0
#define c_IRDYN 1
#define c_UO0 2
#define c_UO1 3
#define c_UO2 4

#define c_NOEXT 0
#define c_EXT0 1
#define c_EXT1 2
#define c_EXT2 3
#define c_EXT3 4

#define CHANGE_TO_FO_COUNT 700
#define CHANGE_TO_IR_COUNT 1700

#define MAX_IR_COUNT 3
#define MAX_FO_COUNT 3

#define IPID_MAX_DELTA 20

// Defines for profiles in decomp.

#define PACKAGE_UO_0		0
#define PACKAGE_UO_1		1
#define PACKAGE_UOR_2		2
#define PACKAGE_IR_DYN		3
#define PACKAGE_IR		4
#define PACKAGE_UNKNOWN		5
#define PACKAGE_CE		6
#define PACKAGE_CE_OFF		7

// DO NOT CHANGE THIS NUMBERS!
#define PACKAGE_EXT_0		0
#define PACKAGE_EXT_1		1
#define PACKAGE_EXT_2		2
#define PACKAGE_EXT_3		3

#define PROTOCOL_IP_IN_IP	4
#define PROTOCOL_IP6		41

#define IP_DF          0x4000          /* Flag: "Don't Fragment"       */

#define CRC_ACTION 		1

#define WEIGHT_OLD            	1
#define WEIGHT_NEW		1

#ifdef USER_SPACE
	#include <stdio.h>
	#include <stdlib.h>
	#include <time.h>
	#include <sys/time.h>

	#define KERN_DEBUG	stderr
	#define GFP_KERNEL	0
	#define GFP_ATOMIC	1
	#define printk		printf
	#define kfree		free

        static inline void * kmalloc(int size, int type) {
		if (type != GFP_ATOMIC) {
		  printf("wrong kmalloc type..\n");
		  exit(0);
		}
		return malloc(size);
	}

	#include <stdarg.h>
	#define rohc_debugf(level, format...) if (level<=ROHC_DEBUG_LEVEL) { printf(format); } else


/*
 *      This is a version of ip_compute_csum() optimized for IP headers,
 *      which always checksum on 4 octet boundaries.
 *
 *      By Jorge Cwik <jorge@laser.satlink.net>, adapted for linux by
 *      Arnt Gulbrandsen.
 */
static inline unsigned short ip_fast_csum(unsigned char * iph,
                                          unsigned int ihl) {
        unsigned int sum;

        __asm__ __volatile__(" \n\
            movl (%1), %0      \n\
            subl $4, %2		\n\
            jbe 2f		\n\
            addl 4(%1), %0	\n\
            adcl 8(%1), %0	\n\
            adcl 12(%1), %0	\n\
1:          adcl 16(%1), %0	\n\
            lea 4(%1), %1	\n\
            decl %2		\n\
            jne 1b		\n\
            adcl $0, %0		\n\
            movl %0, %2		\n\
            shrl $16, %0	\n\
            addw %w2, %w0	\n\
            adcl $0, %0		\n\
            notl %0		\n\
2:				\n\
            "
        /* Since the input registers which are loaded with iph and ipl
           are modified, we must also specify them as outputs, or gcc
           will assume they contain their original values. */
        : "=r" (sum), "=r" (iph), "=r" (ihl)
        : "1" (iph), "2" (ihl));
        return(sum);
}

	static inline int get_microseconds(void) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		return tv.tv_sec * 1000000 + tv.tv_usec;
	}


	static inline int get_milliseconds(void) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		return tv.tv_sec * 1000 + tv.tv_usec/1000;
	}

     

	#define simple_strtol strtol

// End of userspace defines..
#else 
// Start of kernel mode defines..

	#define rohc_debugf(level, format...) if (level<=ROHC_DEBUG_LEVEL) { printk(KERN_INFO format); } else

	static inline int get_microseconds(void) {
		struct timeval tv;
		do_gettimeofday(&tv);
		return tv.tv_sec * 1000000 + tv.tv_usec;
	}

	static inline int get_milliseconds(void) {
		struct timeval tv;
		do_gettimeofday(&tv);
		return tv.tv_sec * 1000 + tv.tv_usec/1000;
	}

#endif // End of kernelsapce defines


#endif
