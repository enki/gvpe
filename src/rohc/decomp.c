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
#include "decomp.h"
#include "d_ip.h"
#include "d_udp.h"
#include "d_uncompressed.h"
#include "d_udp_lite.h"
#include "feedback.h"
//----------------------------------------------------------------------------------------------------------------------------------
extern struct s_profile d_udplite_profile, d_udp_profile, d_ip_profile, d_uncomp_profile;
//----------------------------------------------------------------------------------------------------------------------------------
static struct s_profile *d_profiles[D_NUM_PROFILES] = {
	&d_udplite_profile,
	&d_udp_profile,
	&d_ip_profile,
	&d_uncomp_profile
};
//----------------------------------------------------------------------------------------------------------------------------------
static struct s_profile * find_profile(int id);
//----------------------------------------------------------------------------------------------------------------------------------
// Increases the context array size in sizes of 2^x (max 16384)
// Param state: pointer to decompressor
// Param highest cid: cid to adapt context array size with
//----------------------------------------------------------------------------------------------------------------------------------
void context_array_increase(struct sd_rohc * state, int highestcid)
{
	struct sd_context ** pnew;
	int calcsize, i;

	for(i=4; i<15; i++) {				// calculate new size of array
		calcsize = 1<<i;
		if(highestcid < calcsize)
			break;
	}
	pnew = (struct sd_context**)kmalloc(sizeof(struct sd_context*) * calcsize, GFP_ATOMIC);	// allocate new array
	if(!pnew) {
		rohc_debugf(0,"[ERROR] context_array_increase(): unable to allocate memory!\n");
		return;
	}
	for(i=0; i<calcsize; i++)			// reset all new pointers to NULL
		pnew[i] = NULL;
	for(i=0; i<state->context_array_size; i++)	// copy all pointers
		pnew[i] = state->context[i];
	state->context_array_size = calcsize;
	kfree(state->context);
	state->context = pnew;
}
//----------------------------------------------------------------------------------------------------------------------------------
// Decreases the context array size in sizes of 2^x (min 16)
// Param state: pointer to decompressor
//----------------------------------------------------------------------------------------------------------------------------------
void context_array_decrease(struct sd_rohc * state)
{
	struct sd_context ** pnew;
	int highestcid=0, calcsize, i;

	for(i=state->context_array_size-1; i>=0; i--)	// search for the highest cid (from the end and backwards)
		if(state->context[i]) {
			highestcid = i;
			break;
		}
	for(i=4; i<15; i++) {				// calculate new size of array
		calcsize = 1<<i;
		if(highestcid < calcsize)
			break;
	}
	pnew = (struct sd_context **)kmalloc(sizeof(struct sd_context*) * calcsize, GFP_ATOMIC);	// allocate new array
	if(!pnew) {
		rohc_debugf(0,"[ERROR] context_array_decrease(): unable to allocate memory!\n");
		return;
	}
	for(i=0; i<calcsize; i++)			// reset all new pointers to NULL
		pnew[i] = NULL;
	for(i=0; i<=highestcid; i++)			// copy all pointers
		pnew[i] = state->context[i];

	state->context_array_size = calcsize;
	kfree(state->context);
	state->context = pnew;
}
//----------------------------------------------------------------------------------------------------------------------------------
// Finds a specific context
// Param state: pointer to decompressor
// Param cid: context-id to find in array
// Return: pointer to context if found, else NULL
//----------------------------------------------------------------------------------------------------------------------------------
struct sd_context * find_context(struct sd_rohc * state, int cid)
{
	if(cid < state->context_array_size)		// cid must not be equal or larger than the context array size
		return(state->context[cid]);

	return(NULL);
}
//----------------------------------------------------------------------------------------------------------------------------------
// Create and allocate a new context with profile specific data
// Param state: pointer to decompressor
// Param with_cid: context-id (not used for now)
// Param profile: profile to be assigned with context
// Return: pointer to new context if allocatable, else NULL
//----------------------------------------------------------------------------------------------------------------------------------
struct sd_context * context_create(struct sd_rohc * state, int with_cid, struct s_profile * profile)
{
	struct sd_context * pnew = (struct sd_context*)kmalloc(sizeof(struct sd_context), GFP_ATOMIC);
	if(!pnew) {
		rohc_debugf(0,"[ERROR] context_create(): unable to allocate memory!\n");
		return(NULL);
	}
	pnew->profile = profile;
	pnew->mode = ROHC_U_MODE;
	pnew->state = ROHC_NO_CONTEXT;
	pnew->data = profile->allocate_decode_data();
	if(!pnew->data) {
		kfree(pnew);
		return(NULL);
	}
	pnew->curval = 0;

	pnew->num_recv_packets = 0;
	pnew->total_uncompressed_size = 0;
	pnew->total_compressed_size = 0;
	pnew->header_uncompressed_size = 0;
	pnew->header_compressed_size = 0;
	pnew->num_recv_ir = 0;
	pnew->num_recv_ir_dyn = 0;
	pnew->num_sent_feedbacks = 0;
	pnew->num_decomp_failures = 0;
	pnew->num_decomp_repairs = 0;

	pnew->first_used = get_milliseconds();
	pnew->latest_used = get_milliseconds();

	pnew->total_16_uncompressed = c_create_wlsb(32, 16, 0); // create a window with 16 entries..
	pnew->total_16_compressed = c_create_wlsb(32, 16, 0);
	pnew->header_16_uncompressed = c_create_wlsb(32, 16, 0);
	pnew->header_16_compressed = c_create_wlsb(32, 16, 0);

	return(pnew);
}
//----------------------------------------------------------------------------------------------------------------------------------
// Free a context and the profile specific data within
// Param context: context to free
//----------------------------------------------------------------------------------------------------------------------------------
void context_free(struct sd_context * context)
{
	if(!context)
		return;

	context->profile->free_decode_data(context->data);

	c_destroy_wlsb(context->total_16_uncompressed);
	c_destroy_wlsb(context->total_16_compressed);
	c_destroy_wlsb(context->header_16_uncompressed);
	c_destroy_wlsb(context->header_16_compressed);

	kfree(context);
}
//----------------------------------------------------------------------------------------------------------------------------------
// Create and allocate a ROHC-decompressor
// Param compressor: pointer to ROHC-compressor
// Return: pointer to the newly allocated decompressor
//----------------------------------------------------------------------------------------------------------------------------------
struct sd_rohc * rohc_alloc_decompressor(struct sc_rohc * compressor)
{
	struct s_medium medium = {ROHC_SMALL_CID, 15 }; //, 3};
	struct sd_rohc * pnew = (struct sd_rohc *)kmalloc(sizeof(struct sd_rohc), GFP_ATOMIC);
	if(!pnew) {
		rohc_debugf(0,"[ERROR] rohc_alloc_decompressor(): unable to allocate memory!\n");
		return(NULL);
	}
	pnew->medium = (struct s_medium*)kmalloc(sizeof(struct s_medium), GFP_ATOMIC);
	if (!pnew->medium) {
		rohc_debugf(0,"[ERROR] rohc_alloc_decompressor(): unable to allocate memory (2)!\n");
		kfree(pnew);
		return(NULL);
	}
	memcpy(pnew->medium, &medium, sizeof(struct s_medium));

	pnew->compressor = compressor;

	pnew->context_array_size = 0;		// must be zero
	pnew->context = NULL;			// must be NULL
	context_array_increase(pnew, 0);	// initialize array of size 16

	pnew->maxval = 300;
	pnew->errval = 100;
	pnew->okval = 12;
	pnew->curval = 0;

	clear_statistics(pnew);

	return(pnew);
}
//----------------------------------------------------------------------------------------------------------------------------------
// Free and deallocate a ROHC-decompressor
// Param state: pointer to the ROHC-decompressor to free
//----------------------------------------------------------------------------------------------------------------------------------
void rohc_free_decompressor(struct sd_rohc * state)
{
	int i;

	for(i=0; i<state->context_array_size; i++)
		if(state->context[i])
			context_free(state->context[i]);
	kfree(state->context);
	kfree(state->medium);
	kfree(state);
}
//----------------------------------------------------------------------------------------------------------------------------------
// Main function for decompressing a ROHC-packet
// Param state: pointer to decompressor
// Param ibuf: pointer to incoming packet
// Param isize: size of incoming packet
// Param obuf: pointer to output buffer
// Param osize: size of output buffer
// Return: size of decompressed packet
//TODO:	kolla upp sï¿½ingen annan anropar d_decode_header DIREKT, anropen mï¿½te ske till denna funktion, annars funkar inte statistik och feedback!!
//----------------------------------------------------------------------------------------------------------------------------------
int rohc_decompress(struct sd_rohc * state, unsigned char * ibuf, int isize, unsigned char * obuf, int osize)
{
	int ret;
	struct sd_decode_data ddata = { -1, 0, 0, NULL };	// { cid, addcidUsed, largecidUsed, sd_context * active }

	state->statistics.packets_received++;
	ret = d_decode_header(state, ibuf, isize, obuf, osize, &ddata);
	if(ddata.active == NULL && (ret == ROHC_ERROR_PACKAGE_FAILED || ret == ROHC_ERROR || ret == ROHC_ERROR_CRC))
		ret = ROHC_ERROR_NO_CONTEXT;

	if (ddata.active) {
		ddata.active->num_recv_packets ++;
		rohc_debugf(2,"State in decomp %d\n",ddata.active->state );
	}

	if (ret >= 0) {
		if (!ddata.active) {
			rohc_debugf(1, "decompress: ddata.active == null when ret >=0!\n");
		} else {
			struct sd_context *c = ddata.active;
			c->total_uncompressed_size += ret;
			c->total_compressed_size += isize;

			if (state->compressor) {
				state->compressor->num_packets ++;
				state->compressor->total_uncompressed_size += ret;
				state->compressor->total_compressed_size += isize;
			}

			c_add_wlsb(c->total_16_uncompressed, 0, 0, ret);
			c_add_wlsb(c->total_16_compressed, 0,0, isize);
		}
	} else if (ddata.active) {
		ddata.active->num_decomp_failures ++;
	}

	//return ret;

	switch(ret)
	{
		case ROHC_ERROR_PACKAGE_FAILED:
		case ROHC_ERROR:
			state->statistics.packets_failed_package++;
			ddata.active->curval += state->errval;
			if(ddata.active->curval >= state->maxval) {
				ddata.active->curval = 0;
				d_operation_mode_feedback(state, ROHC_ERROR_PACKAGE_FAILED, ddata.cid, ddata.addcidUsed, ddata.largecidUsed, ddata.active->mode, ddata.active);
			}
			break;

		case ROHC_ERROR_NO_CONTEXT:
			state->statistics.packets_failed_no_context++;
			state->curval += state->errval;
			if(state->curval >= state->maxval) {
				state->curval = 0;
				d_operation_mode_feedback(state, ROHC_ERROR_NO_CONTEXT, ddata.cid, ddata.addcidUsed, ddata.largecidUsed, ROHC_O_MODE, NULL);
			}
			break;

		case ROHC_FEEDBACK_ONLY:
			state->statistics.packets_feedback++;
			break;

		case ROHC_ERROR_CRC:
			state->statistics.packets_failed_crc++;
			ddata.active->curval += state->errval;
			rohc_debugf(2,"feedback curr %d\n", ddata.active->curval);
			rohc_debugf(2,"feedback max %d\n", state->maxval);
			if(ddata.active->curval >= state->maxval) {
				ddata.active->curval = 0;
				d_operation_mode_feedback(state, ROHC_ERROR_CRC, ddata.cid, ddata.addcidUsed, ddata.largecidUsed, ddata.active->mode, ddata.active);
			}
			break;

		default:	// ROHC_OK_NO_DATA, ROHC_OK
			state->curval -= state->okval;				// framework (S-NACK)
			ddata.active->curval -= state->okval;			// context (NACK)
			rohc_debugf(2,"feedback curr %d\n", ddata.active->curval);
			if(state->curval < 0)
				state->curval = 0;

			if(ddata.active->curval < 0)
				ddata.active->curval = 0;

			rohc_debugf(2,"feedback curr %d\n", ddata.active->curval);
			if(ddata.active->mode == ROHC_U_MODE) {
				ddata.active->mode = ROHC_O_MODE;	// switch active context to o-mode
				d_operation_mode_feedback(state, ROHC_OK, ddata.cid, ddata.addcidUsed, ddata.largecidUsed, ddata.active->mode, ddata.active);
			}
			break;
	}
	return(ret);
}
//----------------------------------------------------------------------------------------------------------------------------------
// To decompress both large and small cid package
//----------------------------------------------------------------------------------------------------------------------------------
int rohc_decompress_both(struct sd_rohc * state, unsigned char * ibuf, int isize, unsigned char * obuf, int osize, int large)
{
	state->medium->cid_type = large ? ROHC_LARGE_CID : ROHC_SMALL_CID;

	return rohc_decompress(state, ibuf, isize, obuf, osize);
}
//----------------------------------------------------------------------------------------------------------------------------------
// Decode feedback and context-id if it exist
// Param state: pointer to decompressor
// Param walk: pointer to incoming packet
// Param isize: size of incoming packet
// Return: context-id if found, else rohc_feedback_only
//----------------------------------------------------------------------------------------------------------------------------------
int d_decode_feedback_first(struct sd_rohc * state, unsigned char ** walk, const int isize)
{
	int cid = 0, i, fbloop = 1;
	unsigned char * startpos = *walk;

	for(i=0; i<isize; i++)				// remove all padded octets
		if(d_is_paddning(*walk))
			(*walk)++;
		else
			break;
	while(fbloop) {
		fbloop = 0;
		if(d_is_add_cid(*walk)) {		// if addcid - extract value
			cid = d_decode_add_cid(*walk);
			(*walk)++;
		}
		if(d_is_feedback(*walk)) {		// is it feedback?
			if(cid>0)
				return(ROHC_ERROR_NO_CONTEXT);
			else
				*walk += d_decode_feedback(state, *walk);
			fbloop = 1;			// feedback found, keep looping
		}
		if((*walk)-startpos >= isize)		// end of package
			return(ROHC_FEEDBACK_ONLY);
	}
	return(cid);
}
//----------------------------------------------------------------------------------------------------------------------------------
// Main function for decompressing a ROHC-packet.
// Param state: pointer to decompressor
// Param ibuf: pointer to incoming packet
// Param isize: size of incoming packet
// Param obuf: pointer to output buffer
// Param osize: size of output buffer
// Param ddata: struct that holds important information to pass between several functions
// Return: size of decompressed packet
//----------------------------------------------------------------------------------------------------------------------------------
int d_decode_header(struct sd_rohc * state, unsigned char * ibuf, int isize, unsigned char * obuf, int osize, struct sd_decode_data * ddata)
{
	int largecid=0, size, irdynvar=0, casenew=0;

	struct s_profile * profile;
	unsigned char * walk = ibuf;

	if(isize < 2)
		return(ROHC_ERROR_NO_CONTEXT);
	ddata->cid = d_decode_feedback_first(state, &walk, isize);
	if(ddata->cid == ROHC_FEEDBACK_ONLY || ddata->cid == ROHC_ERROR_NO_CONTEXT)
		return(ddata->cid);

	if(ddata->cid > 0 && state->medium->cid_type == ROHC_SMALL_CID)
		ddata->addcidUsed=1;

	if(!ddata->addcidUsed && state->medium->cid_type == ROHC_LARGE_CID) {		// check if large cids are used
		largecid = d_sdvalue_size(walk+1);
		if(largecid >0 && largecid < 3) {
			ddata->cid = d_sdvalue_decode(walk+1);
			ddata->largecidUsed=1;
		} else
			return(ROHC_ERROR_NO_CONTEXT);
	}

	if(d_is_ir(walk)) {
		profile = find_profile(walk[largecid+1]);

		if(!rohc_ir_packet_crc_ok(walk, largecid, ddata->addcidUsed, profile))
			return(ROHC_ERROR_CRC);

		if(ddata->cid >= state->context_array_size)
			context_array_increase(state, ddata->cid);

		if(state->context[ddata->cid] && state->context[ddata->cid]->profile == profile) {
			ddata->active = state->context[ddata->cid];
			state->context[ddata->cid] = NULL;
		} else {
			casenew=1;
			ddata->active = context_create(state, ddata->cid, profile);
			if(!ddata->active)
				return(ROHC_ERROR_NO_CONTEXT);
		}

		ddata->active->num_recv_ir ++;
		size = ddata->active->profile->decode_ir(state, ddata->active, walk+largecid+3, (isize-(walk-ibuf))-3-largecid, GET_BIT_0(walk), obuf);
		if(size>0) {
			context_free(state->context[ddata->cid]);
			state->context[ddata->cid] = ddata->active;
			return(size);
		}
		if(casenew)
			context_free(ddata->active);
		else
			state->context[ddata->cid] = ddata->active;

		return(size);
	} else {
		ddata->active = find_context(state, ddata->cid);	// find context
		if(ddata->active && ddata->active->profile) {		// context is valid
			ddata->active->latest_used = get_milliseconds();
			if(d_is_irdyn(walk)) {
				ddata->active->num_recv_ir_dyn ++;
				profile = find_profile(walk[largecid+1]);
				if(profile != ddata->active->profile) {		// if IR-DYN changes profile, make comp. transit to NO_CONTEXT-state
					state->curval = state->maxval;
					rohc_debugf(2,"IR-DYN changed profile, sending S-NACK.\n");
					return(ROHC_ERROR_NO_CONTEXT);
				}
				if(!rohc_ir_dyn_packet_crc_ok(walk, largecid, ddata->addcidUsed, profile, ddata->active))
					return(ROHC_ERROR_CRC);
				irdynvar += 2;
			}
			return(ddata->active->profile->decode(state, ddata->active, walk, (isize-(walk-ibuf)), (ddata->largecidUsed ? (1+largecid+irdynvar) : 1+irdynvar), obuf));
		} else
			return(ROHC_ERROR_NO_CONTEXT);
	}
	return(ROHC_ERROR_NO_CONTEXT);
}
//----------------------------------------------------------------------------------------------------------------------------------
// Decode the Feedback
// Param state: pointer to decompressor
// Param ibuf: pointer to incoming packet
// Return: feedback size including feedback head
//----------------------------------------------------------------------------------------------------------------------------------
int d_decode_feedback(struct sd_rohc * state, unsigned char * ibuf)
{
	int feedbacksize, head;
	feedbacksize = d_feedback_size(ibuf);		// extract the size of the feedback
	head = d_feedback_headersize(ibuf);		// point to feedback data
	ibuf += head;
	#ifdef USER_SPACE
		feedbackRedir(ibuf, feedbacksize);	// if user space application is running, send feedback to it..
	#else
		//passFeedback(ibuf, feedbacksize);	// ..else pass it on to the compressor
		if (state->compressor)
			c_deliver_feedback(state->compressor, ibuf, feedbacksize);
	#endif

	return(feedbacksize + head);
}
//----------------------------------------------------------------------------------------------------------------------------------
// Find profile with a certain id
// Param id: profile id to find
// Return: pointer to the matching profile
//----------------------------------------------------------------------------------------------------------------------------------
struct s_profile * find_profile(int id)
{
	if(id==0)
		return uncompressed_profile_create();
	else if(id==2)
		return udp_profile_create();
	else if(id==4)
		return iponly_profile_create();
	else if(id==8)
		return udp_lite_profile_create();
	else
		return uncompressed_profile_create();
}
//----------------------------------------------------------------------------------------------------------------------------------
// CRC check on IR-packets
// Param walk: pointer to incoming packet
// Param largecid: largecid value
// Param addcidUsed: value of addcidUsed, if 1 then addcid is used, else 0
// Param profile: pointer to profile of packet
// Return: 1 if CRC is OK, else 0
//----------------------------------------------------------------------------------------------------------------------------------
int rohc_ir_packet_crc_ok(unsigned char * walk, const int largecid, const int addcidUsed, const struct s_profile * profile)
{
	int realcrc, crc;

	realcrc = walk[largecid+2];
	walk[largecid+2] = 0;
	if(profile->id==0)
		crc = crc_calculate(CRC_TYPE_8, walk-addcidUsed, profile->detect_ir_size(walk, largecid+1)+2+largecid+addcidUsed);
	else
		crc = crc_calculate(CRC_TYPE_8, walk-addcidUsed, profile->detect_ir_size(walk, largecid+1)+3+largecid+addcidUsed);
	walk[largecid+2] = realcrc;
	if(crc != realcrc) {
		rohc_debugf(0,"ROHC Decompress IR: CRC FAILED! SKA: %i, ï¿½: %i\n", realcrc, crc);
		return(0);
	}
	rohc_debugf(2,"ROHC Decompress IR: CRC OK!\n");

	return(1);
}
//----------------------------------------------------------------------------------------------------------------------------------
// CRC check on IR-DYN packets
// Param walk: pointer to incoming packet
// Param largecid: largecid value'
// Param addcidUsed: value of addcidUsed'
// Param profile: pointer to profile of packet
// Return: 1 if CRC is OK, else 0
//----------------------------------------------------------------------------------------------------------------------------------
int rohc_ir_dyn_packet_crc_ok(unsigned char * walk, const int largecid, const int addcidUsed, const struct s_profile * profile, struct sd_context * context)
{
	int realcrc, crc;

	realcrc = walk[largecid+2];
	walk[largecid+2] = 0;
	crc = crc_calculate(CRC_TYPE_8, walk-addcidUsed, profile->detect_ir_dyn_size(walk, context)+3+largecid+addcidUsed);
	walk[largecid+2] = realcrc;
	if(crc != realcrc) {
		rohc_debugf(0,"ROHC Decompress IR_DYN: CRC FAILED! SKA: %i, ï¿½: %i\n", realcrc, crc);
		return(0);
	}
	rohc_debugf(2,"ROHC Decompress IR_DYN: CRC OK!\n");

	return(1);
}
//----------------------------------------------------------------------------------------------------------------------------------
// Send Feedback depending on Mode: Unidirectional, Optimistic or Reliable Mode
// Param state: pointer to decompressor
// Param rohc_status: type of feedback to send; 0 = OK (ack), -1 = ContextInvalid (S-nack), -2 = PackageFailed (Nack)
// Param cid: context-id value
// Param addcidUsed: ==1 if addcid is used
// Param largecidUsed: ==1 if largecid is used
// Param mode: mode that ROHC operates in; U-, O- or R-MODE
// Param ctxt: active/current context
//----------------------------------------------------------------------------------------------------------------------------------
void d_operation_mode_feedback(struct sd_rohc * state, int rohc_status, int cid, int addcidUsed, int largecidUsed, int mode, struct sd_context * ctxt)
{
	struct sd_feedback sfeedback;
	char * feedback;
	int feedbacksize;

	switch(mode)
	{
		case ROHC_U_MODE:
			// no feedback needed
			//break;
		case ROHC_O_MODE:
			switch(rohc_status)
			{
				case ROHC_OK:
					f_feedback2(ACKTYPE_ACK, ctxt->mode, ctxt->profile->get_sn(ctxt), &sfeedback);
					feedback = f_wrap_feedback(&sfeedback, cid, largecidUsed, WITH_CRC, &feedbacksize);
					if(!feedback) {
						rohc_debugf(0,"Feedback: ACK FAILED!\n");
						return;
					}
					ctxt->num_sent_feedbacks++;
					#ifdef USER_SPACE
						rohc_debugf(2,"Feedback send to testapp\n");
						feedbackRedir_piggy(feedback, feedbacksize);
					#else
						if(state->compressor)
							c_piggyback_feedback(state->compressor, feedback, feedbacksize);
					#endif
					kfree(feedback);
					break;
				case ROHC_ERROR_NO_CONTEXT:
					f_feedback2(ACKTYPE_STATIC_NACK, ROHC_O_MODE, 0, &sfeedback);
					f_add_option(&sfeedback, OPT_TYPE_SN_NOT_VALID, NULL);
					feedback = f_wrap_feedback(&sfeedback, cid, largecidUsed, NO_CRC, &feedbacksize);
					if(!feedback) {
						rohc_debugf(0,"Feedback: ACK FAILED!\n");
						return;
					}
					//ctxt->num_sent_feedbacks++;
					#ifdef USER_SPACE
						rohc_debugf(2,"Feedback send to testapp\n");
						feedbackRedir_piggy(feedback, feedbacksize);
					#else
						if(state->compressor)
							c_piggyback_feedback(state->compressor, feedback, feedbacksize);
					#endif
					kfree(feedback);
					break;
				case ROHC_ERROR_PACKAGE_FAILED:
				case ROHC_ERROR_CRC:
					ctxt->num_sent_feedbacks++;
					switch(ctxt->state)
					{
						case ROHC_NO_CONTEXT:
							rohc_debugf(2,"No context\n");
							f_feedback2(ACKTYPE_STATIC_NACK, ctxt->mode, ctxt->profile->get_sn(ctxt), &sfeedback);
							feedback = f_wrap_feedback(&sfeedback, cid, largecidUsed, WITH_CRC, &feedbacksize);
							if(!feedback) {
								rohc_debugf(0,"Feedback: S-NACK (PF/CRC) FAILED!\n");
								return;
							}
							#ifdef USER_SPACE
								rohc_debugf(2,"Feedback send to testapp\n");
								feedbackRedir_piggy(feedback, feedbacksize);
							#else
								if(state->compressor)
									c_piggyback_feedback(state->compressor, feedback, feedbacksize);
							#endif
							kfree(feedback);
							break;
						case ROHC_STATIC_CONTEXT:
						case ROHC_FULL_CONTEXT:

							f_feedback2(ACKTYPE_NACK, ctxt->mode, ctxt->profile->get_sn(ctxt), &sfeedback);
							feedback = f_wrap_feedback(&sfeedback, cid, largecidUsed, WITH_CRC, &feedbacksize);
							if(!feedback) {
								rohc_debugf(0,"Feedback: S-NACK (NC/SC) FAILED!\n");
								return;
							}
							#ifdef USER_SPACE
								rohc_debugf(2,"Feedback send to testapp\n");
								feedbackRedir_piggy(feedback, feedbacksize);
							#else
								if(state->compressor)
									c_piggyback_feedback(state->compressor, feedback, feedbacksize);
							#endif
							if(ctxt->state == ROHC_STATIC_CONTEXT)
								ctxt->state = ROHC_NO_CONTEXT;
							if(ctxt->state == ROHC_FULL_CONTEXT)
								ctxt->state = ROHC_STATIC_CONTEXT;
							kfree(feedback);
							break;
						default:
							break;
					}
					break;
			}
			break;
		case ROHC_R_MODE:
			// send feedback (not supported for now)
			break;
	}
}
//----------------------------------------------------------------------------------------------------------------------------------
// Clear all the statistics
// Param state: pointer to decompressor
//----------------------------------------------------------------------------------------------------------------------------------
void clear_statistics(struct sd_rohc * state)
{
	state->statistics.packets_received = 0;
	state->statistics.packets_failed_crc = 0;
	state->statistics.packets_failed_no_context = 0;
	state->statistics.packets_failed_package = 0;
	state->statistics.packets_feedback = 0;
}

//----------------------------------------------------------------------------------------------------------------------------------
// Store decompression statistics for a decompressor to the buffer
// Param decomp: pointer to the decompressor
// Param buffer:
//----------------------------------------------------------------------------------------------------------------------------------
/* Store decompression statistics for a decompressor to the buffer */
int rohc_d_statistics(struct sd_rohc *decomp, char *buffer)
{
	struct s_profile *p;
	int i;

	// Decompressor profiles
	for (i=0; i<D_NUM_PROFILES; i++) {
		p = d_profiles[i];

		sprintf(buffer, "%s\n%s\n", buffer, "---Profile");
		sprintf(buffer, "%sPROFILE NO:%d\n", buffer, p->id);
		sprintf(buffer, "%sACTIVE:%s\n", buffer, "YES");
		sprintf(buffer, "%sVERSION NO:%s\n", buffer, p->version);
		sprintf(buffer, "%sPROFILE TYPE:%s\n", buffer, p->description);

	}

	return strlen(buffer);
}

//----------------------------------------------------------------------------------------------------------------------------------
// Decompressor Contexts
// Param decomp: pointer to the decompressor
// Param index:
// Param buffer:
//----------------------------------------------------------------------------------------------------------------------------------
int rohc_d_context(struct sd_rohc *decomp, int index, char *buffer) {
	char *modes[4]= {"error", "U-mode", "O-mode", "R-mode"};
	char *states[4] = {"error", "NC", "SC", "FC"};
	char *save;
	struct sd_context *c;
	int v;

	if (index >= decomp->context_array_size)
		return -2;

	c = decomp->context[index];
	if (!c || !c->profile)
		return -1;

	save = buffer;

	buffer += strlen(buffer);
	sprintf(buffer, "\n---Context\n");
	buffer += strlen(buffer);
	sprintf(buffer, "CONTEXTTYPE:Decompressor\n");
	buffer += strlen(buffer);
	sprintf(buffer, "CID:%d\n", index);
	buffer += strlen(buffer);
	sprintf(buffer, "CID_STATE:%s\n", "USED");
	buffer += strlen(buffer);
	sprintf(buffer, "STATE:%s\n", states[c->state]);
	buffer += strlen(buffer);
	sprintf(buffer, "MODE:%s\n", modes[c->mode]);
	buffer += strlen(buffer);
	sprintf(buffer, "PROFILE:%s\n", c->profile->description);
	buffer += strlen(buffer);

	if (c->total_uncompressed_size != 0)
		v = (100*c->total_compressed_size) / c->total_uncompressed_size;
	else
		v = 0;
	if (v < 0) {
		rohc_debugf(0, "decomp: total_compressed_size=%d total_uncompressed_size=%d\n", c->total_compressed_size, c->total_uncompressed_size);
	}
	sprintf(buffer, "TOTALCOMPRATIOALLPACK:%d%%\n", v);
	buffer += strlen(buffer);

	if (c->header_uncompressed_size != 0)
		v = (100*c->header_compressed_size) / c->header_uncompressed_size;
	else
		v = 0;
	sprintf(buffer, "TOTALCOMPRATIOALLPACKHEAD:%d%%\n", v);
	buffer += strlen(buffer);

	v = c->total_compressed_size/c->num_recv_packets;
	sprintf(buffer, "MEANCOMPPACKSIZEALLPACK:%d\n", v);
	buffer += strlen(buffer);

	v = c->header_compressed_size/c->num_recv_packets;
	sprintf(buffer, "MEANHEADSIZEALLCOMPHEAD:%d\n", v);
	buffer += strlen(buffer);

	v = c_sum_wlsb(c->total_16_uncompressed);
	if (v != 0)
		v = (100 * c_sum_wlsb(c->total_16_compressed)) / v;
	sprintf(buffer, "COMPRATIOLAST16PACK:%d%%\n", v);
	buffer += strlen(buffer);

	v = c_sum_wlsb(c->header_16_uncompressed);
	if (v != 0)
		v = (100 * c_sum_wlsb(c->header_16_compressed)) / v;
	sprintf(buffer, "COMPRATIOLAST16PACKHEAD:%d%%\n", v);
	buffer += strlen(buffer);

	v = c_mean_wlsb(c->total_16_compressed);
	sprintf(buffer, "MEANCOMPPACKSIZELAST16PACK:%d\n", v);
	buffer += strlen(buffer);

	v = c_mean_wlsb(c->header_16_compressed);
	sprintf(buffer, "MEANHEADSIZELAST16COMPHEAD:%d\n", v);
	buffer += strlen(buffer);

	sprintf(buffer, "CONTEXTACTIVATIONTIME:%d\n", (get_milliseconds() - c->first_used) / 1000 );
	buffer += strlen(buffer);
	sprintf(buffer, "CONTEXTIDLETIME:%d\n", (get_milliseconds() - c->latest_used) / 1000);
	buffer += strlen(buffer);

	sprintf(buffer, "NORECVPACKETS:%d\n", c->num_recv_packets);
	buffer += strlen(buffer);
	sprintf(buffer, "NORECVIRPACKETS:%d\n", c->num_recv_ir);
	buffer += strlen(buffer);
	sprintf(buffer, "NORECVIRDYNPACKETS:%d\n", c->num_recv_ir_dyn);
	buffer += strlen(buffer);
	sprintf(buffer, "NOSENTFEEDBACKS:%d\n", c->num_sent_feedbacks);
	buffer += strlen(buffer);
	sprintf(buffer, "NODECOMPFAILURES:%d\n", c->num_decomp_failures);
	buffer += strlen(buffer);
	sprintf(buffer, "NODECOMPREPAIRS:%d\n", c->num_decomp_repairs);
	buffer += strlen(buffer);

	return strlen(save);
}

//----------------------------------------------------------------------------------------------------------------------------------
// Create an ACK-packet telling the compressor to change state
// Param state: pointer to decompressor
// Param ctxt: pointer to active context
//----------------------------------------------------------------------------------------------------------------------------------
void d_change_mode_feedback(struct sd_rohc * state, struct sd_context * ctxt)
{
	struct sd_feedback sfeedback;
	int cid, feedbacksize;
	char * feedback;

	for(cid=0; cid < state->context_array_size; cid++)
		if(ctxt == state->context[cid])
			break;
	if(cid >= state->context_array_size)
		return;

	f_feedback2(ACKTYPE_ACK, ctxt->mode, ctxt->profile->get_sn(ctxt), &sfeedback);
	feedback = f_wrap_feedback(&sfeedback, cid, (state->medium->cid_type == ROHC_LARGE_CID ? 1 : 0), WITH_CRC, &feedbacksize);

	if(!feedback) {
		rohc_debugf(0,"Feedback [d_change_mode_feedback()]: ACK FAILED!\n");
		return;
	}
	#ifdef USER_SPACE
		rohc_debugf(2,"Feedback [ACK] sent to testapp.\n");
		feedbackRedir_piggy(feedback, feedbacksize);
	#else
		if(state->compressor)
			c_piggyback_feedback(state->compressor, feedback, feedbacksize);
	#endif
	kfree(feedback);
}
//----------------------------------------------------------------------------------------------------------------------------------
// Update feedback interval with data from the gui
// Param state: pointer to the decompressor
// Param feedback_maxval: the value from the gui
//----------------------------------------------------------------------------------------------------------------------------------
void usergui_interactions(struct sd_rohc * state, int feedback_maxval)
{
	state->maxval = feedback_maxval*100;
}
//----------------------------------------------------------------------------------------------------------------------------------
