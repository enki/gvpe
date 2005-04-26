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
#include "comp.h"
#include "c_util.h"
#include "feedback.h"
//----------------------------------------------------------------------------------------------------------------------------------
// Builds a feedback1-package
// Param sn: sequence-number
// Param f: pointer to feedback packet
// Return: true if build was ok
//----------------------------------------------------------------------------------------------------------------------------------
bool f_feedback1(int sn, struct sd_feedback * f)
{
//	int req_sn_bits = calc_feedback_sn_size();	//check if feddback1 is ok ..
//	if (req_sn_bits < 9) {
		f->feedback_type = 1;	//set type for add_option
		f->size = 1;
		f->feedback[0] = (sn & 0xFF);
		return true;
//	}
//	return false;
}
//----------------------------------------------------------------------------------------------------------------------------------
// Builds a feedback2-package
// Param achtype: ACK, NACK or S-NACK
// Param mode: mode in which ROHC operates; U-, O- or R-MODE
// Param sn: sequence-number
// Param f: pointer to feedback packet
//----------------------------------------------------------------------------------------------------------------------------------
void f_feedback2(int acktype, int mode, int sn, struct sd_feedback * f)
{
//	int req_sn_bits=-1;
	char tkn = (sn & 0xFF);
	f->size = 2;		// size of feedback-2 head

	f->feedback_type = 2;	//set type for add_option

	f->feedback[0] = (acktype & 0x3) << 6 | (mode & 0x3) << 4;

//	req_sn_bits = calc_feedback_sn_size();

	if(sn < 255){	//12 bits sn
//	if(req_sn_bits < 13){
		f->feedback[0] |= (sn & 0xF00) >> 8;
		f->feedback[1] = sn & 0xFF;
	} else {	//20 bits sn
		f->feedback[0] |= (sn & 0xF0000) >> 16;
		f->feedback[1] = sn & 0xFF00 >> 8;
		f_add_option(f, OPT_TYPE_SN, &tkn);	//return ! important ..
	}
}
//----------------------------------------------------------------------------------------------------------------------------------
// Adds an option data for feedback2
// Param f: pointer to feedback packet
// Param opt_type: type of option to be added
// Param data: the option data
// Return: 0 if failed, 1 if ok
//----------------------------------------------------------------------------------------------------------------------------------
bool f_add_option(struct sd_feedback * f, int opt_type, char * data)
{
	if (f->feedback_type == 2) {
		f->feedback[f->size] = opt_type & 0xF;
		f->feedback[f->size] <<= 4;
		f->feedback[f->size] = (data ? 1 : 0) | f->feedback[f->size];
		f->size++;

		if(opt_type == OPT_TYPE_CRC || data) {
			if(opt_type == OPT_TYPE_CRC)
				f->feedback[f->size] = 0;
			else
				f->feedback[f->size] = data[0];
			f->size++;
		}
		return true;
	}
	return false;
}
//----------------------------------------------------------------------------------------------------------------------------------
// Appends the cid on the feedback packet
// Param f: pointer to the feedback packet
// Param cid: the context-id
// Param largecidUsed: ==1 if largecid is used
// Return: true if cid was successfully appended, else false
//----------------------------------------------------------------------------------------------------------------------------------
bool f_append_cid(struct sd_feedback * f, int cid, int largecidUsed)
{
	char * acid;
	int largecidsize, i;

	if(largecidUsed) {	// largecid
		largecidsize = c_bytesSdvl(cid);
		if(f->size+largecidsize > 30) {
			rohc_debugf(0, "ERROR [feedback.c - f_append_cid()]: Array to small!\n");
			return(false);
		} else {
			for(i=f->size-1; i>=0; i--)
				f->feedback[i+largecidsize] = f->feedback[i];
		}
		acid = (char*)kmalloc(largecidsize, GFP_ATOMIC);
		if(!acid) {
			f->size = 0;
			return(false);
		}
		if(!c_encodeSdvl(acid, cid)) {
			rohc_debugf(0, "ERROR [feedback.c - f_append_cid()]: This should never happen!\n");
			return(false);
		}
		memcpy(f->feedback, acid, largecidsize);
		kfree(acid);
		f->size += largecidsize;
	} else {
		if(cid > 0 && cid < 16) {
			for(i = f->size-1; i>=0; i--)
				f->feedback[i+1] = f->feedback[i];
			f->feedback[0] = 0xE0;
			f->feedback[0] = (cid & 0xF) | f->feedback[0];
			f->size++;
		}
	}
	return(true);
}

//----------------------------------------------------------------------------------------------------------------------------------
// Wrap the feedback packet and add a CRC-option if specified
// Param f: the pointer to the feedback packet
// Param cid: the context-id
// Param largecidUsed: ==1 if largecid is used, else ==0
// Param with_crc: if ==1, the CRC option will be added to the feedback packet
// Param final_size: final size of the feedback packet will be written to this variable
// Return: NULL if failed, otherwise the pointer to the feedback packet
//----------------------------------------------------------------------------------------------------------------------------------
char * f_wrap_feedback(struct sd_feedback * f, int cid, int largecidUsed, int with_crc, int * final_size)
{
	unsigned int crc;
	char * feedback;

	if (!f_append_cid(f, cid, largecidUsed))
		return NULL;
	if(with_crc) {
		f_add_option(f, OPT_TYPE_CRC, (char*)1);
		feedback = (char*)kmalloc(f->size, GFP_ATOMIC);
		if (!feedback) {
			f->size = 0;
			return NULL;
		}
		memcpy(feedback, f->feedback, f->size);
		crc = crc_calculate(CRC_TYPE_8, feedback, f->size);
		feedback[f->size-1] = (char)(crc & 0xFF);
		*final_size = f->size;
		f->size = 0;
		return(feedback);
	}

	feedback = (char*)kmalloc(f->size, GFP_ATOMIC);
	if (!feedback) {
		f->size = 0;
		return NULL;
	}
	memcpy(feedback, f->feedback, f->size);
	*final_size = f->size;
	f->size = 0;
	return(feedback);
}
//----------------------------------------------------------------------------------------------------------------------------------
