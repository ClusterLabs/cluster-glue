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
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pils/plugin.h>
#include <pils/generic.h>
#include <lrm/raexec.h>

static void
g_print_item(gpointer data, gpointer user_data)
{
	printf("%s\n", (char*)data);
}


int main(void)
{
	PILPluginUniv * PluginLoadingSystem = NULL;
	GHashTable * RAExecFuncs = NULL;
	GList * ratype_list;
	struct RAExecOps * RAExec;
	/*
	GHashTable * cmd_params;
	*/
	int ret;

	PILGenericIfMgmtRqst RegisterRqsts[]= { 
		{"RAExec", &RAExecFuncs, NULL, NULL, NULL},
		{ NULL, NULL, NULL, NULL, NULL} };

	PluginLoadingSystem = NewPILPluginUniv ("/usr/lib/heartbeat/plugins");

	PILLoadPlugin(PluginLoadingSystem , "InterfaceMgr", "generic" , &RegisterRqsts);

	PILLoadPlugin(PluginLoadingSystem , "RAExec", "ocf", NULL);
	RAExec = g_hash_table_lookup(RAExecFuncs,"ocf");
	ret = RAExec->get_resource_list(&ratype_list);
	printf("length=%d\n", g_list_length(ratype_list));
	if (ret >= 0) {
		g_list_foreach(ratype_list, g_print_item, NULL);
	}

	/*
	PILLoadPlugin(PluginLoadingSystem , "RAExec", "lsb", NULL);
	RAExec = g_hash_table_lookup(RAExecFuncs,"lsb");
	cmd_params = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(cmd_params, g_strdup("1"), g_strdup("par1"));
	g_hash_table_insert(cmd_params, g_strdup("2"), g_strdup("par2"));
	ret = RAExec->execra("/tmp/test.sh", "start", cmd_params,NULL);
	*/

	/* For test the dealing with directory appended to RA */
	/*
	PILLoadPlugin(PluginLoadingSystem , "RAExec", "ocf", NULL);
	RAExec = g_hash_table_lookup(RAExecFuncs,"ocf");
	if (0>RAExec->execra("/root/linux-ha-checkout/linux-ha/lrm/test.sh",
			"stop",NULL,NULL, TRUE, &key)) 
	*/
	printf("execra result: ret = %d\n", ret);
	return -1;
}
