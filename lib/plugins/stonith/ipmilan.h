/*
 * Stonith module for ipmi lan Stonith device
 *
 * Copyright (c) 2003 Intel Corp. 
 *	Yixiong Zou <yixiong.zou@intel.com>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#define ST_IPMI_STATUS 4
#include <time.h>

struct ipmilanHostInfo {
	char * 		hostname;
	char * 		ipaddr;
	int 		portnumber;
	int 		authtype;
	int		privilege;
	char * 		username;
	char *		password;
	int		reset_method;

	struct ipmilanHostInfo *  prev;
	struct ipmilanHostInfo *  next;
};

int do_ipmi_cmd(struct ipmilanHostInfo * host, int request);
void ipmi_leave(void);
