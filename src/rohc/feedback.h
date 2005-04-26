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
//----------------------------------------------------------------------------------------------------------------------------------
#ifndef __FEEDBACK_H__
#define __FEEDBACK_H__
//----------------------------------------------------------------------------------------------------------------------------------
#define OPT_TYPE_CRC		1
#define OPT_TYPE_REJECT		2
#define OPT_TYPE_SN_NOT_VALID	3
#define OPT_TYPE_SN		4
#define OPT_TYPE_CLOCK		5	// not used
#define OPT_TYPE_JITTER		6	// not used
#define OPT_TYPE_LOSS		7
//----------------------------------------------------------------------------------------------------------------------------------
#define ACKTYPE_ACK		0
#define ACKTYPE_NACK		1
#define ACKTYPE_STATIC_NACK	2
//----------------------------------------------------------------------------------------------------------------------------------
#define NO_CRC			0
#define WITH_CRC		1
//----------------------------------------------------------------------------------------------------------------------------------
#define	false			0
#define	true			1
//----------------------------------------------------------------------------------------------------------------------------------
typedef int bool;
//----------------------------------------------------------------------------------------------------------------------------------
/*
#define CT_MODEM 56
#define CT_ISDN 2
#define CT_XDSL 3
#define CT_T1 10000
#define CT_T3 100000
*/
//----------------------------------------------------------------------------------------------------------------------------------
struct sd_feedback
{
	int feedback_type;
	char feedback[30];
	int size;
};
//----------------------------------------------------------------------------------------------------------------------------------
// PUBLIC:
//int f_feedback(int acktype, int mode, int sn, struct sd_feedback * f);
bool f_feedback1(int sn, struct sd_feedback * f);
void f_feedback2(int acktype, int mode, int sn, struct sd_feedback * f);
bool f_add_option(struct sd_feedback * feedback, int opt_type, char * data);
char * f_wrap_feedback(struct sd_feedback * f, int cid, int largecidUsed, int with_crc, int * final_size);
// PRIVATE:
bool f_append_cid(struct sd_feedback * f, int cid, int largecidUsed);
//----------------------------------------------------------------------------------------------------------------------------------
#endif
//----------------------------------------------------------------------------------------------------------------------------------
