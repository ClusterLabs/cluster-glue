/* 
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
 *
 * File: raexecocf.c
 * Author: Sun Jiang Dong <sunjd@cn.ibm.com>
 * Copyright (c) 2004 International Business Machines
 *
 * This code implements the Resource Agent Plugin Module for LSB style.
 * It's a part of Local Resource Manager. Currently it's used by lrmd only.
 */

#include <portability.h>
#include <stdio.h>		
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <pils/plugin.h>
#include <dirent.h>
#include <libgen.h>  /* Add it for compiling on OSX */
#include <config.h>

#include <lrm/raexec.h>
#include <fencing/stonithd_api.h>

# define PIL_PLUGINTYPE		RA_EXEC_TYPE
# define PIL_PLUGINTYPE_S	"RAExec"
# define PIL_PLUGINLICENSE	LICENSE_PUBDOM
# define PIL_PLUGINLICENSEURL	URL_PUBDOM

# define PIL_PLUGIN		stonith
# define PIL_PLUGIN_S		"stonith"

static PIL_rc close_stonithRA(PILInterface*, void* ud_interface);

/* static const char * RA_PATH = STONITH_RA_DIR; */
/* Temporarily use it */
static const char * RA_PATH = "/usr/lib/stonith/plugins/stonith/";

/* The begin of exported function list */
static int execra(const char * rsc_id,
		  const char * rsc_type,
		  const char * provider,
		  const char * op_type,
		  const int    timeout,
	 	  GHashTable * params);
static uniform_ret_execra_t map_ra_retvalue(int ret_execra, 
					    const char * op_type);
static int get_resource_list(GList ** rsc_info);
static char* get_resource_meta(const char* rsc_type,  const char* provider);
static int get_provider_list(const char* op_type, GList ** providers);

/* The end of exported function list */

/* The begin of internal used function & data list */
static int get_providers(const char* class_path, const char* op_type,
			 GList ** providers);
static void stonithRA_ops_callback(stonithRA_ops_t * op, void * private_data);
static int exit_value;
static gboolean signedon_to_stonithd = FALSE;
/* The end of internal function & data list */

/* Rource agent execution plugin operations */
static struct RAExecOps raops =
{	execra,
	map_ra_retvalue,
	get_resource_list,
	get_provider_list,
	get_resource_meta
};

static const char * meta_data1 = "\n"
"<?xml version=\"1.0\"?>\n"
"<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"
"<resource-agent name=\"";

static const char * meta_data2 = 
"\" version=\"0.1\">\n"
"  <version>1.0</version>\n"
"  <parameters>\n"
"    <parameter name=\"config_string\" unique=\"0\">\n"
"      <longdesc lang=\"en\">\n"
"        Config string for a stonith resource -- one type of stonith devices\n"
"      </longdesc>\n"
"      <shortdesc lang=\"en\">Config string</shortdesc>\n"
"      <content type=\"string\" default=\"\" />\n"
"    </parameter>\n"
"    <parameter name=\"config_file\" unique=\"0\">\n"
"      <longdesc lang=\"en\">\n"
"        Config file for a stonith resource -- one type of stonithd devices.\n"
"      </longdesc>\n"
"      <shortdesc lang=\"en\">Config file</shortdesc>\n"
"      <content type=\"string\" default=\"\" />\n"
"    </parameter>\n"
"  </parameters>\n"
"  <actions>\n"
"    <action name=\"start\"   timeout=\"15\" />\n"
"    <action name=\"stop\"    timeout=\"15\" />\n"
"    <action name=\"monitor\" timeout=\"15\" interval=\"15\" start-delay=\"15\" />\n"
"    <action name=\"meta-data\"  timeout=\"5\" />\n"
"  </actions>\n"
"  <special tag=\"heartbeat\">\n"
"    <version>2.0</version>\n"
"  </special>\n"
"</resource-agent>\n";

PIL_PLUGIN_BOILERPLATE2("1.0", Debug);

static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static void*			OurImports;
static void*			interfprivate;

/*
 * Our plugin initialization and registration function
 * It gets called when the plugin gets loaded.
 */
PIL_rc
PIL_PLUGIN_INIT(PILPlugin * us, const PILPluginImports* imports);

PIL_rc
PIL_PLUGIN_INIT(PILPlugin * us, const PILPluginImports* imports)
{
	/* Force the compiler to do a little type checking */
	(void)(PILPluginInitFun)PIL_PLUGIN_INIT;

	PluginImports = imports;
	OurPlugin = us;

	if (ST_OK == stonithd_signon("STONITH_RA")) {
		signedon_to_stonithd = TRUE;
	} else {
		/* Redundant, but more safe */
		signedon_to_stonithd = FALSE;
		cl_log(LOG_ERR, "Can not signon to the stonithd.");
	}

	/* Register ourself as a plugin */
	imports->register_plugin(us, &OurPIExports);

	/*  Register our interfaces */
 	return imports->register_interface(us, PIL_PLUGINTYPE_S,  PIL_PLUGIN_S,
		&raops, close_stonithRA, &OurInterface, &OurImports,
		interfprivate);
}

static PIL_rc
close_stonithRA(PILInterface* pif, void* ud_interface)
{
	if (signedon_to_stonithd == TRUE) {
		stonithd_signoff();
		signedon_to_stonithd = FALSE;
	}
	return PIL_OK;
}

/*
 * Most of the oprations will be sent to sotnithd directly, such as 'start',
 * 'stop', 'monitor'. And others like 'meta-data' will be handled by itself
 * locally.
 * Some of important parameters' name:
 * config_file
 * config_string
 */
static int
execra(const char * rsc_id, const char * rsc_type, const char * provider,
       const char * op_type,const int timeout, GHashTable * params)
{
	stonithRA_ops_t * op;
	int call_id = -1;
	gboolean signedon_locally = FALSE;

	if (signedon_to_stonithd == FALSE) {
		if (ST_OK != stonithd_signon("STONITH_RA_EXEC")) {
			cl_log(LOG_ERR, "Can not signon to the stonithd.");
			exit(EXECRA_UNKNOWN_ERROR);
		} else {
			/* 
			 * Since this function will be called in a child
			 * process, actually this assignment is useless
			 * and harmless. Remain it for an apparent logic.
			 */
			signedon_to_stonithd = TRUE;
			signedon_locally = TRUE;
		}
	}

	/*
	 * Now handle "meta-data" operation locally. 
	 * Should be changed in the future?
	 */
	if (strncmp(op_type, "meta-data", strlen("meta-data")) == 0) {
		char * tmp;
		tmp = get_resource_meta(rsc_type, provider);
		printf("%s", tmp);
		g_free(tmp);
		if (signedon_locally == TRUE) {
			stonithd_signoff();
			signedon_locally = FALSE;
		}
		exit(0);
	}

	stonithd_set_stonithRA_ops_callback(stonithRA_ops_callback, &call_id);

	/* Temporarily donnot use it, but how to deal with the global OCF 
	 * variables. This is a important thing to think about and do.
	 */
	/* send the RA operation to stonithd to simulate a RA's actions */
	cl_log(LOG_DEBUG, "Will send the stonith RA operation to stonithd: " \
		"%s %s", rsc_type, op_type);

	op = g_new(stonithRA_ops_t, 1);
	op->ra_name = g_strdup(rsc_type);
	op->op_type = g_strdup(op_type);
	op->params = params;
	op->rsc_id = g_strdup(rsc_id);
	if (ST_FAIL == stonithd_virtual_stonithRA_ops(op, &call_id)) {
		cl_log(LOG_DEBUG, "sending stonithRA op to stonithd failed.");
		/* Need to improve the granularity for error return code */
		if (signedon_locally == TRUE) {
			stonithd_signoff();
			signedon_locally = FALSE;
		}
		exit(EXECRA_EXEC_UNKNOWN_ERROR);
	}

	cl_log(LOG_DEBUG, "Waiting until the final result returned.");
	/* May be redundant */
	while (stonithd_op_result_ready() != TRUE) {
		;
	}
	cl_log(LOG_DEBUG, "Will call stonithd_receive_ops_result.");
	stonithd_receive_ops_result(TRUE);

	/* exit_value will be setted by the callback function */
	g_free(op->ra_name);
	g_free(op->op_type);
	g_free(op->rsc_id);
	g_free(op);
	if (signedon_locally == TRUE) {
		stonithd_signoff();
		signedon_locally = FALSE;
	}
	cl_log(LOG_DEBUG, "stonithRA orignal exit code=%d", exit_value);
	exit(map_ra_retvalue(exit_value, op_type));
}

static void
stonithRA_ops_callback(stonithRA_ops_t * op, void * private_data)
{
	cl_log(LOG_DEBUG, "setting exit code=%d", exit_value);
	exit_value = op->op_result;
}

static uniform_ret_execra_t
map_ra_retvalue(int ret_execra, const char * op_type)
{
	/* Because the UNIFORM_RET_EXECRA is compatible with OCF standard */
	return ret_execra;
}

static int
get_resource_list(GList ** rsc_info)
{
	cl_log(LOG_ERR, "get_resource_list: begin.");

	if ( rsc_info == NULL ) {
		cl_log(LOG_ERR, "Parameter error: get_resource_list");
		return -2;
	}

	if ( *rsc_info != NULL ) {
		cl_log(LOG_ERR, "Parameter error: get_resource_list."\
			"will cause memory leak.");
		*rsc_info = NULL;
	}

	if (signedon_to_stonithd == FALSE) {
		if (ST_OK != stonithd_signon("STONITH_RA")) {
			cl_log(LOG_ERR, "Can not signon to the stonithd.");
			return -1;
		} else {
			signedon_to_stonithd = TRUE;
		}
	}

	return stonithd_list_stonith_types(rsc_info);
}

static int
get_provider_list(const char* op_type, GList ** providers)
{
	int ret;
	ret = get_providers(RA_PATH, op_type, providers);
	if (0>ret) {
		cl_log(LOG_ERR, "scandir failed in stonith RA plugin");
	}
	return ret;
}

static char *
get_resource_meta(const char* rsc_type, const char* provider)
{
	char * buffer;
	buffer = g_new(char, strlen(meta_data1)+strlen(meta_data2)+40);

	sprintf(buffer, "%s%s%s", meta_data1, rsc_type, meta_data2);

	return buffer;
}

/* 
 * Currently should return *providers = NULL, but rmain the old code for
 * possible unsing in the future
 */
static int
get_providers(const char* class_path, const char* op_type, GList ** providers)
{
	if ( providers == NULL ) {
		cl_log(LOG_ERR, "Parameter error: get_providers");
		return -2;
	}

	if ( *providers != NULL ) {
		cl_log(LOG_ERR, "Parameter error: get_providers."\
			"will cause memory leak.");
		*providers = NULL;
	}

	return 0;
#if 0
	struct dirent **namelist;
	int file_num;
	file_num = scandir(class_path, &namelist, 0, alphasort);
	if (file_num < 0) {
		return -2;
	}else{
		char tmp_buffer[FILENAME_MAX+1];
		while (file_num--) {
			if ((DT_DIR != namelist[file_num]->d_type) ||
			    ('.' == namelist[file_num]->d_name[0])) {
				free(namelist[file_num]);
				continue;
			}

			snprintf(tmp_buffer,FILENAME_MAX,"%s/%s/%s",
				 class_path, namelist[file_num]->d_name, op_type);

			if ( filtered(tmp_buffer) == TRUE ) {
				*providers = g_list_append(*providers,
					g_strdup(namelist[file_num]->d_name));
			}
			free(namelist[file_num]);
		}
		free(namelist);
	}
	return g_list_length(*providers);
#endif
}
