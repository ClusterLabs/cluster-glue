
/*
 * cl_plugin.c: This file handle plugin loading and deleting
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
#include <lha_internal.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <unistd.h>
#include <assert.h>
#include <glib.h>
#include <ha_msg.h>
#include <clplumbing/netstring.h>
#include <pils/plugin.h>
#include <pils/generic.h>
/* #include <stonith/stonith.h> */
/* #include <stonith/stonith_plugin.h> */
#include <clplumbing/cl_plugin.h>

#define MAXTYPES 16
#define MAXTYPELEN 64
 
static GHashTable*	funcstable[MAXTYPES];

static PILPluginUniv*		plugin_univ = NULL;

static PILGenericIfMgmtRqst	reqs[] =
	{
		{"compress", &funcstable[0], NULL, NULL, NULL},
		{"HBcoms", &funcstable[1], NULL, NULL, NULL},
		{"HBauth", &funcstable[2], NULL, NULL, NULL},
		{"RAExec", &funcstable[3], NULL, NULL, NULL},
		{"quorum", &funcstable[4], NULL, NULL, NULL},
		{"tiebreaker", &funcstable[5], NULL, NULL, NULL},
		{"quorumd", &funcstable[6], NULL, NULL, NULL},
		{NULL, NULL, NULL, NULL, NULL}
	};

static int
init_pluginsys(void){
	
	if (plugin_univ) {
		return TRUE;
	}
	
	plugin_univ = NewPILPluginUniv(HA_PLUGIN_DIR);
	
	if (plugin_univ) {
		if (PILLoadPlugin(plugin_univ, PI_IFMANAGER, "generic", reqs)
		!=	PIL_OK){
			cl_log(LOG_ERR, "generic plugin load failed\n");
			DelPILPluginUniv(plugin_univ);
			plugin_univ = NULL;
		}
	}else{
		cl_log(LOG_ERR, "pi univ creation failed\n");
	}
	return plugin_univ != NULL;

}

int
cl_remove_plugin(const char* type, const char* pluginname)
{
	return HA_OK;
}

void*
cl_load_plugin(const char* type, const char* pluginname)
{
	void*	funcs = NULL;
	int	i = 0;
	GHashTable** table = NULL;
	
	while (reqs[i].iftype != NULL){
		if ( strcmp(reqs[i].iftype,type) != 0){
			i++;
			continue;
		}
		
		table = reqs[i].ifmap;
		break;
	}
	
	if (table == NULL){
		cl_log(LOG_ERR, "%s: function table not found",__FUNCTION__);
		return NULL;
	}
	
	if (!init_pluginsys()){
		cl_log(LOG_ERR, "%s: init plugin universe failed", __FUNCTION__);
		return NULL;
	}
	
	if ((funcs = g_hash_table_lookup(*table, pluginname))
	    == NULL){
		if (PILPluginExists(plugin_univ, type, pluginname) == PIL_OK){
			PIL_rc rc;
			rc = PILLoadPlugin(plugin_univ, type, pluginname, NULL);
			if (rc != PIL_OK){
				cl_log(LOG_ERR, 
				       "Cannot load plugin %s[%s]",
				       pluginname, 
				       PIL_strerror(rc));
				return NULL;
			}
			funcs = g_hash_table_lookup(*table, 
						    pluginname);
		}
		
	}
	if (funcs == NULL){
		cl_log(LOG_ERR, "%s: module(%s) not found", 
		       __FUNCTION__, pluginname);
		return NULL;
	}
	
	return funcs;
	
}

