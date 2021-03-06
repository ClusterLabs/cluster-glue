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
 * License along with this library; if not, see <http://www.gnu.org/licenses/>
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
	host.username = strdup(user);
	host.password = strdup(pass);

	rv = do_ipmi_cmd(&host, request);
	if (rv)  
		printf("rv = %d, operation failed. \n", rv);
	else 
		printf("operation succeeded. \n");
	return rv;
}
