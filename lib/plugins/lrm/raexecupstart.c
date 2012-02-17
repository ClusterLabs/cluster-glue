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
 * File: raexecupstart.c
 * Copyright (C) 2010 Senko Rasic <senko.rasic@dobarkod.hr>
 * Copyright (c) 2010 Ante Karamatic <ivoks@init.hr>
 *
 * Heavily based on raexeclsb.c and raexechb.c:
 * Author: Sun Jiang Dong <sunjd@cn.ibm.com>
 * Copyright (c) 2004 International Business Machines
 *
 * This code implements the Resource Agent Plugin Module for Upstart.
 * It's a part of Local Resource Manager. Currently it's used by lrmd only.
 */

#define PIL_PLUGINTYPE		RA_EXEC_TYPE
#define PIL_PLUGIN		upstart
#define PIL_PLUGINTYPE_S	"RAExec"
#define PIL_PLUGIN_S		"upstart"
#define PIL_PLUGINLICENSE	LICENSE_PUBDOM
#define PIL_PLUGINLICENSEURL	URL_PUBDOM

#include <lha_internal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>  /* Add it for compiling on OSX */
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <pils/plugin.h>
#include <lrm/raexec.h>
#include <libgen.h>

#include <glib-object.h>

#include <libxml/entities.h>

#include "upstart-dbus.h"

#define meta_data_template  \
"<?xml version=\"1.0\"?>\n"\
"<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"\
"<resource-agent name=\"%s\" version=\"0.1\">\n"\
"  <version>1.0</version>\n"\
"  <longdesc lang=\"en\">\n"\
"    %s"\
"  </longdesc>\n"\
"  <shortdesc lang=\"en\">%s</shortdesc>\n"\
"  <parameters>\n"\
"  </parameters>\n"\
"  <actions>\n"\
"    <action name=\"start\"   timeout=\"15\" />\n"\
"    <action name=\"stop\"    timeout=\"15\" />\n"\
"    <action name=\"status\"  timeout=\"15\" />\n"\
"    <action name=\"restart\"  timeout=\"15\" />\n"\
"    <action name=\"monitor\" timeout=\"15\" interval=\"15\" start-delay=\"15\" />\n"\
"    <action name=\"meta-data\"  timeout=\"5\" />\n"\
"  </actions>\n"\
"  <special tag=\"upstart\">\n"\
"  </special>\n"\
"</resource-agent>\n"

/* The begin of exported function list */
static int execra(const char * rsc_id,
		  const char * rsc_type,
		  const char * provider,
		  const char * op_type,
		  const int    timeout,
	 	  GHashTable * params);

static uniform_ret_execra_t map_ra_retvalue(int ret_execra
	, const char * op_type, const char * std_output);
static char* get_resource_meta(const char* rsc_type, const char* provider);
static int get_resource_list(GList ** rsc_info);
static int get_provider_list(const char* ra_type, GList ** providers);

/* The end of exported function list */

/* The begin of internal used function & data list */
#define MAX_PARAMETER_NUM 40

const int MAX_LENGTH_OF_RSCNAME = 40,
	  MAX_LENGTH_OF_OPNAME = 40;

typedef char * RA_ARGV[MAX_PARAMETER_NUM];

/* The end of internal function & data list */

/* Rource agent execution plugin operations */
static struct RAExecOps raops =
{	execra,
	map_ra_retvalue,
	get_resource_list,
	get_provider_list,
	get_resource_meta
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug)

static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static void*			OurImports;
static void*			interfprivate;

PIL_rc
PIL_PLUGIN_INIT(PILPlugin * us, const PILPluginImports* imports);

PIL_rc
PIL_PLUGIN_INIT(PILPlugin * us, const PILPluginImports* imports)
{
	PluginImports = imports;
	OurPlugin = us;

	imports->register_plugin(us, &OurPIExports);

	g_type_init ();

	return imports->register_interface(us, PIL_PLUGINTYPE_S,  PIL_PLUGIN_S,
		&raops, NULL, &OurInterface, &OurImports,
		interfprivate);
}

static int
execra( const char * rsc_id, const char * rsc_type, const char * provider,
	const char * op_type, const int timeout, GHashTable * params)
{
	UpstartJobCommand cmd;

	if (!g_strcmp0(op_type, "meta-data")) {
		printf("%s", get_resource_meta(rsc_type, provider));
		exit(EXECRA_OK);
	} else if (!g_strcmp0(op_type, "monitor") || !g_strcmp0(op_type, "status")) {
		gboolean running = upstart_job_is_running (rsc_type);
		printf("%s", running ? "running" : "stopped");
		
		if (running)
			exit(EXECRA_OK);
		else
			exit(EXECRA_NOT_RUNNING);
	} else if (!g_strcmp0(op_type, "start")) {
		cmd = UPSTART_JOB_START;
	} else if (!g_strcmp0(op_type, "stop")) {
		cmd = UPSTART_JOB_STOP;
	} else if (!g_strcmp0(op_type, "restart")) {
		cmd = UPSTART_JOB_RESTART;
	} else {
		exit(EXECRA_UNIMPLEMENT_FEATURE);
	}

	/* It'd be better if it returned GError, so we can distinguish
	 * between failure modes (can't contact upstart, no such job,
	 * or failure to do action. */
	if (upstart_job_do(rsc_type, cmd, timeout)) {
		exit(EXECRA_OK);
	} else {
		exit(EXECRA_NO_RA);
	}
}

static uniform_ret_execra_t
map_ra_retvalue(int ret_execra, const char * op_type, const char * std_output)
{
	/* no need to map anything, execra() returns correct exit code */
	return ret_execra;
}

static int
get_resource_list(GList ** rsc_info)
{
	gchar **jobs;
	gint i;
	*rsc_info = NULL;

	jobs = upstart_get_all_jobs();

	if (!jobs)
		return 0;

	for (i = 0; jobs[i] != NULL; i++) {
		*rsc_info = g_list_prepend(*rsc_info, jobs[i]);
	}

	/* free the array, but not the strings */
	g_free(jobs);

	*rsc_info = g_list_reverse(*rsc_info);
	return g_list_length(*rsc_info);
}

static char *
get_resource_meta (const gchar *rsc_type, const gchar *provider)
{
	return g_strdup_printf(meta_data_template, rsc_type,
		rsc_type, rsc_type);
}

static int
get_provider_list (const gchar *ra_type, GList **providers)
{
	*providers = g_list_prepend(*providers, g_strdup("upstart"));
	return g_list_length(*providers);
}

