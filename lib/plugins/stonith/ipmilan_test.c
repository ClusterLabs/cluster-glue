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

/*
 * A quick test program to verify that IPMI host is setup correctly.
 * 
 * You will need to modify the values in user, pass, ip, and port. 
 */

#include <stdio.h>
#include <string.h>
#include "ipmilan.h"
#include <OpenIPMI/ipmi_auth.h>

int main(int argc, char * argv[])
{
	struct ipmilanHostInfo host;
	int request = 2;
	int rv;

	char user[] = "joe";
	char pass[] = "blow";
	char ip[] = "192.168.1.7";

	host.hostname = NULL;
	host.portnumber = 999;
	host.authtype = IPMI_AUTHTYPE_NONE;
	host.privilege = IPMI_PRIVILEGE_ADMIN;

	host.ipaddr = ip;
	memcpy(host.username, user, sizeof(user));
	memcpy(host.password, pass, sizeof(pass));
	/*
	memset(host.username, 0, sizeof(host.username));
	memset(host.password, 0, sizeof(host.password));
	*/

	rv = do_ipmi_cmd(&host, request);
	if (rv)  
		printf("rv = %d, operation failed. \n", rv);
	else 
		printf("operation succeeded. \n");
	return rv;
}
