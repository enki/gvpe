/*
    global.h -- global variables and constants
    Copyright (C) 2003-2004 Marc Lehmann <pcg@goof.com>
 
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
    Foundation, Inc. 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#ifndef GLOBAL_H__
#define GLOBAL_H__

#include "config.h"

#include <time.h>

/* Protocol version. Different major versions are incompatible,
 * different minor versions probably are compatible ;)
 */

#define PROTOCOL_MAJOR 0
#define PROTOCOL_MINOR 1

#define RSA_KEYBITS	1280		// must be >= 1280 and divisible by 8
#define RSA_KEYLEN	((RSA_KEYBITS) >> 3)
#define RSA_OVERHEAD	(41 + 1)	// well, no define for OAEP in openssl

#define RSA_HASH	EVP_ripemd160 ()// speed don't matter, boy, safety does.. I need sha256 :(
#define RSA_HASHLEN	(160 >> 3)
#define RSA_RESLEN	RSA_HASHLEN

#define RSA_IDLEN	16		// how many bytes are used to identify the challenge
#define RSA_TTL		120		// challenge bytes timeout after n seconds

#define CIPHER		ENABLE_CIPHER ()
#define CIPHER_KEYLEN	(EVP_CIPHER_key_length (CIPHER))
#define DIGEST		ENABLE_DIGEST ()
#define HMAC_KEYLEN	(256 >> 3)	// number of bits used for the HMAC key (also change CHG_HMAC_KEY)

#define MAX_SEQNO	0xfffffff0U

#define CHG_SEQNO	 0	// where the seqno starts within the rsa challenge
#define CHG_CIPHER_KEY	 4	// where the key starts within the rsa challenge
#define CHG_HMAC_KEY	86	// where the key starts within the rsa challenge (256 bits at the end!)

//                   hdr seq len              hmac        MAC MAC
#define VPE_OVERHEAD (4 + 4 + 4 + RAND_SIZE + HMACLENGTH - 6 - 6)
#define IP_OVERHEAD  20			// size of a (normal) ip header
#define GRE_OVERHEAD (IP_OVERHEAD +  4)
#define ICMP_OVERHEAD (IP_OVERHEAD + 4)
#define UDP_OVERHEAD (IP_OVERHEAD + 20)	// size of a (normal) ip + udp header (wrong, but don't care)
#define TCP_OVERHEAD (IP_OVERHEAD + 22)	// size of a (normal) ip + tcp header + packetlength
#define MAX_OVERHEAD UDP_OVERHEAD	// the max. overhead of any protocol (ok, tcp doesn't count)
#define ETH_OVERHEAD 14			// the size of an ethernet header
#define MAXSIZE (MAX_MTU + VPE_OVERHEAD)// slightly too large, but who cares

#define PKTCACHESIZE 5			// the size of the memory pool for packets

#define QUEUEDEPTH 16			// the number of packets that will be queued (should be low)

#define WINDOWSIZE 512			// sliding window size

extern char *confbase;		// directory in which all config files are
extern char *thisnode;		// config for current node (TODO: remove)

#endif

