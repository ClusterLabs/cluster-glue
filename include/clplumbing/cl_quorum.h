/*
 * quorum.h: head file for quorum module
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

#ifndef _QUORUM_H_
#define _QUORUM_H_ 

#define HB_QUORUM_TYPE	quorum
#define HB_QUORUM_TYPE_S	"quorum"

#define QUORUM_YES		0
#define QUORUM_NO		1
#define QUORUM_TIE		2
typedef void(*callback_t)(void);
/*
 *	List of functions provided by implementations of the quorum interface.
 */
struct hb_quorum_fns {
	
	int (*getquorum) (const char* cluster
	,		int member_count, int member_quorum_votes
	,		int total_node_count, int total_quorum_votes);
	int (*init) (callback_t notify, const char* cluster, const char* quorum_server);
	void (*stop) (void);
};


#endif
