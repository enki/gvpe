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
 * File:        util.c                                                     *
 * Description: utility functions for the compressor                       *
 *                                                                         *
 ***************************************************************************/

#include "rohc.h"
#include "comp.h"
#include "c_util.h"

void c_ack_remove(struct sc_wlsb * s, int index, int time);

 /////////////////////////////////////////////////////////////////////
// W-LSB: Window base - Least Significant Bits  encoding

/* Removes (deallocates) a struct of window based LSB encoding
 * Param s : the struct
 */
void c_destroy_wlsb(struct sc_wlsb *s)
{
	if (s) {
		if (s->window)
	  		kfree(s->window);
		kfree(s);
	}
}


/* Create a new WLSB instance (and allocate memory for it)
 * Param bits : number of maximum bits for representing a value
 * Param windowWidth : number of entrys in the window
 * Param p : bit calculation algorithm modifying parameter, specific for the
 * profile.
 * Returns : the allocated struct, NULL if failure
 */

struct sc_wlsb *c_create_wlsb(int bits, int windowWidth, int p)
{
	int i;
	struct sc_wlsb * s = kmalloc(sizeof(struct sc_wlsb),GFP_ATOMIC);

	if(!s) {
	  rohc_debugf(0, "c_create_wlsb(): no mem for wlsb\n");
	  return NULL;
	}

	s->oldest = 0;
	s->next = 0;
	s->windowWidth = windowWidth;

	s->window = (struct sc_window *)kmalloc(sizeof(struct sc_window)*windowWidth, GFP_ATOMIC);
	if (!s->window) {
		kfree(s);
		rohc_debugf(0, "c_create_wlsb(): no mem for window\n");
		return NULL;
	}

	s->bits = bits;
	s->p = p;
	for(i = 0; i < windowWidth; i++){
		s->window[i].time = -1;
		s->window[i].used = ROHC_FALSE;
	}

	return s;
}

// debug function
void print_wlsb_stats(struct sc_wlsb * s)
{
	int i;
	if (!s)
	  return;

	for(i = 0; i < s->windowWidth; i++) {
		if (s->window[i].used) {
			rohc_debugf(2, "window[%d].sn = %d, .time = %d, .value = %d\n", i, s->window[i].sn, s->window[i].time, s->window[i].value);
		}
	}

	rohc_debugf(0, "oldest entry has number %d\n", s->oldest);
	rohc_debugf(0, " and is (sn) %d\n", s->window[s->oldest].sn);
	rohc_debugf(0, "Next entry has number %d, oldest entry has number %d\n", s->next, s->oldest);
}

/* Adds a value (inserts an entry) to a window
 * Param s : the window
 * Param sn : the sequence number for the package (entry)
 * Param time : the time stamp for the package
 * Param value : the value to base the LSB coding on (i.e. sn)
 */
void c_add_wlsb(struct sc_wlsb * s, int sn, int time, int value)
{
	if (!s)
		return;
	if(s->window[s->next].used) s->oldest++;		// if window is full and an entry is overwritten
	s->window[s->next].sn = sn;
	s->window[s->next].time = time;
	s->window[s->next].value = value;
	s->window[s->next].used = ROHC_TRUE;
	s->next++;
	if(s->next >= s->windowWidth) s->next = 0;
	if(s->oldest >= s->windowWidth) s->oldest = 0;
}


/* Finds the interval [vref-p, v_ref+(2^k-1)-p] for given k
 * Part of the LSB calculation algorithm
 */
static void f(int v_ref, int k, int p, int * min, int * max)
{
	*min = v_ref - p;
	*max = v_ref + ((1 << k) - 1) - p;	// (1 << k) = 2 to the power of k
}

/* Find minimum k so that v falls into the interval f(v_ref, k)
 * Part of the LSB calculation algorithm
 */
static int g(int v_ref, int v, int p, int bits)
{
	int k, min, max;
	for(k = 0; k < bits; k++){
		f(v_ref, k, p, &min, &max);
		if( (v <= max) && (v >= min) ) break;
	}
	return k;
}

/* This is the function that is called when calculation of the LSB is desired.
 * Calculates the minimum number bits of the value that is required to uniquely
 * be able to create it given the window.
 * Param s : the window
 * Param value : the value to encode
 * Returns : the number of bits required to recreate the value uniquely
 */
int c_get_k_wlsb(struct sc_wlsb * s, int value)
{
	int i, k, min, max, tmp, valid;
	if (!s)
	  return 0;
	min = 0x7fffffff;
	max = 0x80000000;
	valid = 0;
	for(i = 0; i < s->windowWidth; i++){
		if(!s->window[i].used) continue;
		valid = 1;
		tmp = s->window[i].value;
		if( tmp < min ) min = tmp;
		if( tmp > max ) max = tmp;
	}
	if(valid){
		k = g(min, value, s->p, s->bits);
		tmp = g(max, value, s->p, s->bits);
		if( tmp > k ) k = tmp;
	} else return -1; // return -1 if no k match
	return k;
}

/* Acknowledge based on the sequence number. Removes all entries older than the given sn.
 * Param s : the window
 * Param sn : the sequence number
 */
void c_ack_sn_wlsb(struct sc_wlsb * s, int sn)
{
	int i, found;
	found = 0;
	if (!s)
	  return;
/*	if(s->next == 0){
		i = s->windowWidth - 1;
	} else i = s->next - 1;*/
	for(i = s->oldest; i < s->windowWidth; i++){
		if((s->window[i].used == ROHC_TRUE) && (s->window[i].sn == sn)){
			found = 1;
			break;
		}
	}
	if(!found){
		for(i = 0; (i < s->oldest); i++){
			if((s->window[i].used == ROHC_TRUE) && (s->window[i].sn == sn)){
				found = 1;
				break;
			}
		}
	}
	if(s->oldest == i) return;
	if(!found) return;
	c_ack_remove(s, i, 0);
}

/* Acknowledge based on the time stamp. Removes all entries older than the given time stamp.
 * Param s : the window
 * Param time : the time stamp
 */
void c_ack_time_wlsb(struct sc_wlsb * s, int time)
{
	int i, found;
	if (!s)
	  return;
	found = 0;
/*	if(s->next == 0){
		i = s->windowWidth - 1;
	} else i = s->next - 1;*/
	for(i = s->oldest; i < s->windowWidth; i++){
		if((s->window[i].used == ROHC_TRUE) && (s->window[i].time <= time)){
			if(s->window[i].time < time) i++;
			if(i >= s->windowWidth) i = 0;
			found = 1;
			break;
		}
	}
	if(!found){
		for(i = 0; i < s->oldest; i++){
			if((s->window[i].used == ROHC_TRUE) && (s->window[i].time <= time)){
				found = 1;
				break;
			}
		}
	}
	if(!found) return;
	c_ack_remove(s, i, 1);
}

/* Removes elements from the window. Removes all entries prior to index.
 * Param s : the window
 * Param index : the position to set as oldest
 * Param time : flag to see if called by sn or time ack
 */
void c_ack_remove(struct sc_wlsb * s, int index, int time)
{

	int j;
	if (!s)
	  return;
	rohc_debugf(2, "c_ack_remove(): Index is %d\n", index);
	if(s->oldest == index){
		s->window[s->oldest].time = -1;
		s->window[s->oldest].used = ROHC_FALSE;
	}else	if(s->oldest < index){	// remove all entries from oldest to (not including) index
		for(j = s->oldest; j < index; j++){
			s->window[j].time = -1;
			s->window[j].used = ROHC_FALSE;
		}
	} else {	// remove all entries from oldest to wrap-around, and all from start to (excluding) index
		for(j = s->oldest; j < s->windowWidth; j++){
			s->window[j].time = -1;
			s->window[j].used = ROHC_FALSE;
		}
		for(j = 0; j < index; j++){
			s->window[j].time = -1;
			s->window[j].used = ROHC_FALSE;
		}
	}
	if(index >= (s->windowWidth - 1)){
		s->oldest = index;
		/*if(time)*/ s->oldest = 0;
	} else {
		s->oldest = index;
		if(s->oldest >= s->windowWidth) s->oldest = 0;
	}
	s->next = s->oldest;
	for(j = s->oldest; j < s->windowWidth; j++){
		if(s->window[j].used == ROHC_TRUE){
			s->next = ( s->next+1 ) % s->windowWidth;
		} else {
			break;
		}
	}
	for(j = 0; j < s->oldest; j++){
		if(s->window[j].used == ROHC_TRUE){
			s->next = ( s->next+1 ) % s->windowWidth;
		} else {
			break;
		}
	}
	if(s->oldest >= s->windowWidth) s->oldest = 0;
}

/* Calculates the sum of the value for all the entries in the window.
 * Used for statistics
 */
int c_sum_wlsb(struct sc_wlsb *s) {
	int i;
	int sum=0;

	for (i=0; i<s->windowWidth; i++) {
		if (s->window[i].used) {
			sum += s->window[i].value;
		}
	}

	return sum;
}

/* Calculates the mean of the value for all the entries in the window.
 * Used for statistics
 */
int c_mean_wlsb(struct sc_wlsb *s) {
	int i;
	int sum=0;
	int num=0;

	for (i=0; i<s->windowWidth; i++) {
		if (s->window[i].used) {
			sum += s->window[i].value;
			num++;
		}
	}

	if (num > 0)
		return sum/num;

	return sum;
}


/////////////////////////////////////////////////////////////////////
// SDVL: Self Described Variable Length  encoding

/* Calculates how many bytes that are needed to represent the value with sdvl :
 * self-described variable length.
 * Param value : the value
 * Returns : number of bytes needed to represent the given value with sdvl.
 */
int c_bytesSdvl(int value)
{
	if(value <= 127) return 1;
	if(value <= 16383) return 2;
	if(value <= 2097151) return 3;
	if(value <= 536870911) return 4;
	return 5;
}

/* Encode a value using sdvl (self-described variable length).
 * Param *dest : the destination to write the result to.
 * Param value : the value to encode.
 * Returns : true if success, false if failure (due to value
 * greater than 2^29).
 */
boolean c_encodeSdvl(unsigned char *dest, int value)
{
	int tmp;
	if (!dest)
	  return ROHC_FALSE;
	tmp = c_bytesSdvl(value);
	if( tmp > 4 ) return ROHC_FALSE;
	if( tmp == 4 ){
		*dest++ = ((7 << 5) ^ ((value >> 24) & 31)) & 255;	// 7 = bit pattern 111
		*dest++ = (value >> 16) & 255;
		*dest++ = (value >> 8) & 255;
		*dest = value & 255;
	} else if( tmp == 3 ){
		*dest++ = ((6 << 5) ^ ((value >> 16) & 31)) & 255;	// 6 = bit pattern 110
		*dest++ = (value >> 8) & 255;
		*dest = value & 255;
	} else if( tmp == 2 ){
		*dest++ = ((2 << 6) ^ ((value >> 8)& 63)) & 255;	// 2 = bit pattern 10
		*dest = value & 255;
	} else if( tmp == 1 ){
		*dest = value & 255;
	}
	return ROHC_TRUE;
}


/////////////////////////////////////////////////////////////////////
// CRC

/* Tables to enable fast CRC computations */
static unsigned char crc_table_8[256];
static unsigned char crc_table_7[256];
static unsigned char crc_table_3[256];

/* Get the polynom for the crc type
 * Param type : the CRC type
 * Returns : the polynom for the requested type
 */
int crc_get_polynom(int type)
{
	if(type == CRC_TYPE_3) return 0x6;
	if(type == CRC_TYPE_7) return 0x79;
	if(type == CRC_TYPE_8) return 0xe0;
	return 0;
}

/* Initialize a table given a 256 bytes table and the polynom to use */
void crc_init_table(unsigned char *table, unsigned char poly) {
  unsigned char crc;
  int i,j;

  for (i=0; i<256; i++) {
    crc = i;
    for (j=0; j<8; j++) {
      if (crc & 1)
	crc = (crc>>1) ^ poly;
      else
        crc = (crc>>1);
    }
    table[i] = crc;
  }
}

/* Optimized CRC-8 calculation using the table */
inline unsigned char crc_calc_8(unsigned char *buf, int size) {
  int i;
  unsigned char crc = 0xff;
  for (i=0; i<size; i++) {
    crc = crc_table_8[buf[i]^crc];
  }
  return crc;
}

/* Optimized CRC-7 calculation using the table */
inline unsigned char crc_calc_7(unsigned char *buf, int size) {
  int i;
  unsigned char crc = 0x7f;
  for (i=0; i<size; i++) {
    crc = crc_table_7[buf[i]^(crc&127)];
  }
  return crc;
}

/* Optimized CRC-3 calculation using the table */
inline unsigned char crc_calc_3(unsigned char *buf, int size) {
  int i;
  unsigned char crc = 0x7;
  for (i=0; i<size; i++) {
    crc = crc_table_3[buf[i]^(crc&7)];
  }
  return crc;
}

/* Calculates the checksym for the given data.
 * Param type : the CRC type (CRC_TYPE_3, CRC_TYPE_7 or CRC_TYPE_8)
 * Param data : the data to calculate the checksum on
 * Param length : the length of the data
 * Returns : the checksum
 */

unsigned int crc_calculate(int type, unsigned char *data, int length) {
  switch (type) {
  case CRC_TYPE_8: return crc_calc_8(data, length);
  case CRC_TYPE_7: return crc_calc_7(data, length);
  case CRC_TYPE_3: return crc_calc_3(data, length);
  }
  return 0;
}

/**********************************************************/

/*Function for setting a addcid value when using small cids*/
unsigned char c_add_cid(int cid){
	unsigned char ret_value = 0xe0;
	ret_value |= (cid & 0x0f);
	return ret_value;
}

/* Function that sets the cid_values it will set the cids proper in the
pointer dest, the function takes a pointer called first_position where you get the position
to place your first byte, the second byte can be placed in the value that this function returns.
*/
int code_cid_values(struct sc_context *context,unsigned char *dest,int max_size,int *first_position)
{
	int counter = 0;
	//small cid
	if(!(context->compressor->large_cid)){
		if(context->cid > 0){
			dest[counter] = c_add_cid(context->cid);
			*first_position = 1;
			counter = 2;

		}
		else{
			*first_position = 0;
			counter = 1;
		}

		return counter; //return 0 if cid ==0 and small_cid
	}
	//large cid
	else{
		*first_position = 0;
		counter++;
		c_encodeSdvl(&dest[counter],context->cid);
		counter += c_bytesSdvl(context->cid);
		return counter;
	}
}


/////////////////////////////////////////////////////////////////////

