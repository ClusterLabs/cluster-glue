/*
 * cl_tiebreaker.h: head file for tiebreaker module
 *
 * Copyright (C) 2005 Guochun Shi <gshi@ncsa.uiuc.edu>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _CL_TIEBREAKER_H_
#define _CL_TIEBREAKER_H_ 

#define HB_TIEBREAKER_TYPE	tiebreaker
#define HB_TIEBREAKER_TYPE_S	"tiebreaker"

/*
 *	List of functions provided by implementations of tiebreaker interface.
 */
struct hb_tiebreaker_fns {
	gboolean (*break_tie) (int, int);
};


#endif
