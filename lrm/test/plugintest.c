/* File: plugintest.c
 * Description: A small,simple tool to test RA execution plugin
 *
 * Author: Sun Jiang Dong <sunjd@cn.ibm.com>
 * Copyright (c) 2004 International Business Machines
 *
 * Todo: security verification
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <portability.h>

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pils/plugin.h>
#include <pils/generic.h>
#include <lrm/raexec.h>

int main(void)
{
	PILPluginUniv * PluginLoadingSystem = NULL;
	GHashTable * RAExecFuncs = NULL;
	struct RAExecOps * RAExec;
	int key;
	int result, ret;
	char * meta_data;
	GHashTable * cmd_params;

	PILGenericIfMgmtRqst RegisterRqsts[]= { 
		{"RAExec", &RAExecFuncs, NULL, NULL, NULL},
		{ NULL, NULL, NULL, NULL, NULL} };

	PluginLoadingSystem = NewPILPluginUniv ("/usr/lib/heartbeat/plugins");

	PILLoadPlugin(PluginLoadingSystem , "InterfaceMgr", "generic" , &RegisterRqsts);

	PILLoadPlugin(PluginLoadingSystem , "RAExec", "lsb", NULL);

	RAExec = g_hash_table_lookup(RAExecFuncs,"lsb");
//	RAExec->execra("/root/linux-ha-checkout/linux-ha/lrm/test.sh",
	cmd_params = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(cmd_params, g_strdup("1"), g_strdup("par1"));
	g_hash_table_insert(cmd_params, g_strdup("2"), g_strdup("par2"));
	RAExec->execra("/tmp/test.sh",
			"start",cmd_params,NULL, TRUE, &key);
	sleep(1);
	printf("meta_data is %lx\n", (long)meta_data);
	do {
		ret = RAExec->post_query_result(key, &result, &meta_data); 
	} while (ret == 0);

	if ( ret > 0 ) {
		printf("ret: %d\n", ret);
		printf("exit status: %d\n", result);
		printf("meta_data is %lx\n", (long)meta_data);
		printf("Metadata is as below\n%s\n", meta_data);
	}


	PILLoadPlugin(PluginLoadingSystem , "RAExec", "ocf", NULL);
	RAExec = g_hash_table_lookup(RAExecFuncs,"ocf");
	if (0>RAExec->execra("/root/linux-ha-checkout/linux-ha/lrm/test.sh",
//	RAExec->execra("/tmp/test.sh",
			"stop",NULL,NULL, TRUE, &key)) {
		printf("Execution error\n");
		return -1;
	}
	sleep(1);
	printf("meta_data is %lx\n", (long)meta_data);
	do {
		ret = RAExec->post_query_result(key, &result, &meta_data); 
	} while (ret == 0);

	if ( ret > 0 ) {
		printf("ret: %d\n", ret);
		printf("exit status: %d\n", result);
		printf("meta_data is %lx\n", (long)meta_data);
		printf("Metadata is as below\n%s\n", meta_data);
	}

	return 0;
}
