/* $Id: stonith.c,v 1.16 2005/02/01 20:22:51 gshi Exp $ */
/*
 * Stonith API infrastructure.
 *
 * Copyright (c) 2000 Alan Robertson <alanr@unix.sh>
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
#include <portability.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <dlfcn.h>
#include <dirent.h>
#include <glib.h>
#define ENABLE_PIL_DEFS_PRIVATE
#include <pils/plugin.h>
#include <pils/generic.h>
#include <stonith/stonith.h>
#include <stonith/stonith_plugin.h>


#define	MALLOC(n)	malloc(n)
#define MALLOCT(t)	(t*)(malloc(sizeof(t)))
#define FREE(p)		{free(p); (p) = NULL;}

#define	LOG(args...) PILCallLog(StonithPIsys->imports->log, args)

PILPluginUniv*		StonithPIsys = NULL;
static GHashTable*	Splugins = NULL;
static int		init_pluginsys(void);
extern StonithImports	stonithimports;

static PILGenericIfMgmtRqst	Reqs[] =
{
	{STONITH_TYPE_S, &Splugins, &stonithimports, NULL, NULL},
	{NULL, NULL, NULL, NULL, NULL}
};

void PILpisysSetDebugLevel(int);
/* Initialize the plugin system... */
static int
init_pluginsys(void) {

	if (StonithPIsys) {
		return TRUE;
	}


	/* PILpisysSetDebugLevel(10); */
	StonithPIsys = NewPILPluginUniv(STONITH_MODULES);
	
	if (StonithPIsys) {
		if (PILLoadPlugin(StonithPIsys, PI_IFMANAGER, "generic", Reqs)
		!=	PIL_OK){
			fprintf(stderr, "generic plugin load failed\n");
			DelPILPluginUniv(StonithPIsys);
			StonithPIsys = NULL;
		}
		/*PILSetDebugLevel(StonithPIsys, PI_IFMANAGER, "generic", 10);*/
	}else{
		fprintf(stderr, "pi univ creation failed\n");
	}
	return StonithPIsys != NULL;
}

/*
 *	Create a new Stonith object of the requested type.
 */

Stonith *
stonith_new(const char * type)
{
	StonithPlugin *		sp = NULL;
	struct stonith_ops*	ops = NULL;
	char *			key;


	if (!init_pluginsys()) {
		return NULL;
	}


	/* Look and see if it's already loaded... */

	if (g_hash_table_lookup_extended(Splugins, type
	,	(gpointer)&key, (gpointer)&ops)) {
		/* Yes!  Increment reference count */
		PILIncrIFRefCount(StonithPIsys, STONITH_TYPE_S, type, 1);

	}else{		/* No.  Try and load it... */
		if (PILLoadPlugin(StonithPIsys, STONITH_TYPE_S, type, NULL)
		!=	PIL_OK) {
			return NULL;
		}

		/* Look up the plugin in the Splugins table */
		if (!g_hash_table_lookup_extended(Splugins, type
		,		(void*)&key, (void*)&ops)) {
			/* OOPS! didn't find it(!?!)... */
			PILIncrIFRefCount(StonithPIsys, STONITH_TYPE_S, type, -1);
			return NULL;
		}
	}

	if (ops != NULL) {
		sp = ops->new();
		sp->s.stype = strdup(type);
	}

	return sp ? (&sp->s) : NULL;
}

/*
 *	Return list of STONITH types valid in stonith_new()
 */

char **
stonith_types(void)
{
	static char **	lasttypelist = NULL;
	if (!init_pluginsys()) {
		return NULL;
	}

	if (lasttypelist) {
		PILFreePluginList(lasttypelist);
		lasttypelist=NULL;
	}

	lasttypelist = PILListPlugins(StonithPIsys, STONITH_TYPE_S, NULL);
	return lasttypelist;
}

/* Destroy the STONITH object... */

void
stonith_delete(Stonith *s)
{
	StonithPlugin*	sp = (StonithPlugin*)s;

	if (sp && sp->s_ops) {
		char *	st = sp->s.stype;
		sp->s_ops->destroy(sp);
		PILIncrIFRefCount(StonithPIsys, STONITH_TYPE_S, st, -1);
		/* destroy should not free it */
		free(st);
	}
}

const char **
stonith_get_confignames(Stonith* s)
{
	StonithPlugin*	sp = (StonithPlugin*)s;

	if (sp && sp->s_ops) {
		return sp->s_ops->get_confignames(sp);
	}
	return NULL;
}

const char*
stonith_get_info(Stonith* s, int infotype)
{
	StonithPlugin*	sp = (StonithPlugin*)s;

	if (sp && sp->s_ops) {
		return sp->s_ops->get_info(sp, infotype);
	}
	return NULL;

}

void
stonith_set_debug	(Stonith* s, int debuglevel)
{
	StonithPlugin*	sp = (StonithPlugin*)s;
	if (StonithPIsys == NULL) {
		return;
	}
	PILSetDebugLevel(StonithPIsys, STONITH_TYPE_S, sp->s.stype, debuglevel);
}

int
stonith_set_config(Stonith* s, StonithNVpair* list)
{
	StonithPlugin*	sp = (StonithPlugin*)s;

	if (sp && sp->s_ops) {
		int	rc = sp->s_ops->set_config(sp, list);
		if (rc == S_OK) {
			sp->isconfigured = TRUE;
		}
		return rc;
	}
	return S_INVAL;
}

/*
 * FIXME: We really ought to support files with name=value type syntax
 * on each line...
 *
 */
int
stonith_set_config_file(Stonith* s, const char * configname)
{
	FILE *		cfgfile;

	char		line[1024];

	if ((cfgfile = fopen(configname, "r")) == NULL)  {
		LOG(PIL_CRIT, "Cannot open %s", configname);
		return(S_BADCONFIG);
	}
	while (fgets(line, sizeof(line), cfgfile) != NULL){
		int	len;
		
		if (*line == '#' || *line == '\n' || *line == EOS) {
			continue;
		}
		
		/*remove the new line in the end*/
		len = strnlen(line, 1024);		
		if (line[len-1] == '\n'){
			line[len-1] = '\0';
		}else {
		}

		return stonith_set_config_info(s, line);
	}
	return S_BADCONFIG;
}

int
stonith_set_config_info(Stonith* s, const char * info)
{
	StonithNVpair*	cinfo;
	int		rc;
	cinfo = stonith1_compat_string_to_NVpair(s, info);
	if (cinfo == NULL) {
		return S_BADCONFIG;
	}
	rc = stonith_set_config(s, cinfo);
	free_NVpair(cinfo); cinfo = NULL;
	return rc;
}

char**
stonith_get_hostlist(Stonith* s)
{
	StonithPlugin*	sp = (StonithPlugin*)s;
	if (sp && sp->s_ops && sp->isconfigured) {
		return sp->s_ops->get_hostlist(sp);
	}
	return NULL;
}

void
stonith_free_hostlist(char** hostlist)
{
	char ** here;

	for (here=hostlist; *here; ++here) {
		FREE(*here);
	}
	FREE(hostlist);
}

int
stonith_get_status(Stonith* s)
{
	StonithPlugin*	sp = (StonithPlugin*)s;
	if (sp && sp->s_ops && sp->isconfigured) {
		return sp->s_ops->get_status(sp);
	}
	return S_INVAL;
}

int
stonith_req_reset(Stonith* s, int operation, const char* node)
{
	StonithPlugin*	sp = (StonithPlugin*)s;
	if (sp && sp->s_ops && sp->isconfigured) {
		char*		nodecopy = strdup(node);
		int		rc;
		if (nodecopy == NULL) {
			return S_OOPS;
		}
		g_strdown(nodecopy);

		rc = sp->s_ops->req_reset(sp, operation, node);
		free(nodecopy);
		return rc;
	}
	return S_INVAL;
}
/* Stonith 1 compatibility:  Convert a string to an NVpair set */
StonithNVpair*
stonith1_compat_string_to_NVpair(Stonith* s, const char * str)
{
	/* We make some assumptions that the order of parameters in the
	 * result from stonith_get_confignames() matches that which
	 * was required from a Stonith1 module.
	 * Everything after the last delimiter is passed along as part of
	 * the final argument - white space and all...
	 */
	const char **	config_names;
	int		n_names;
	int		j;
	const char *	delims = " \t\n\r\f";
	StonithNVpair*	ret;

	if ((config_names = stonith_get_confignames(s)) == NULL) {
		return NULL;
	}
	for (n_names=0; config_names[n_names] != NULL; ++n_names) {
		/* Just count */;
	}
	ret = (StonithNVpair*) (malloc((n_names+1)*sizeof(StonithNVpair)));
	if (ret == NULL) {
		return NULL;
	}
	for (j=0; j < n_names; ++j) {
		size_t	len;
		if ((ret[j].s_name = strdup(config_names[j])) == NULL) {
			goto freeandexit;
		}
		ret[j].s_value = NULL;
		str += strspn(str, delims);
		if (*str == EOS) {
			goto freeandexit;
		}
		if (j == (n_names -1)) {
			len = strlen(str);
		}else{
			len = strcspn(str, delims);
		}
		if ((ret[j].s_value = malloc((len+1)*sizeof(char))) == NULL) {
			goto freeandexit;
		}
		memcpy(ret[j].s_value, str, len);
		ret[j].s_value[len] = EOS;
		str += len;
	}
	ret[j].s_name = NULL;
	return ret;
freeandexit:
	free_NVpair(ret); ret = NULL;
	return NULL;
}

static int NVcur = -1;
static int NVmax = -1;
static gboolean NVerr = FALSE;

static void
stonith_walk_ghash(gpointer key, gpointer value, gpointer user_data)
{
	StonithNVpair*	u = user_data;
	
	if (NVcur <= NVmax && !NVerr) {
		u[NVcur].s_name = strdup(key);
		u[NVcur].s_value = strdup(value);
		++NVcur;
		if (u[NVcur].s_name == NULL || u[NVcur].s_value == NULL) {
			NVerr = TRUE;
			return;
		}
	}else{
		NVerr = TRUE;
	}
}


StonithNVpair*
stonith_ghash_to_NVpair(GHashTable* stringtable)
{
	int		hsize = g_hash_table_size(stringtable);
	StonithNVpair*	ret;

	if ((ret = (StonithNVpair*)malloc(sizeof(StonithNVpair)*(hsize+1))) == NULL) {
		return NULL;
	}
	NVmax = hsize;
	NVcur = 0;
	g_hash_table_foreach(stringtable, stonith_walk_ghash, ret);
	NVmax = NVcur = -1;
	if (NVerr) {
		free_NVpair(ret);
		ret = NULL;
	}
	return ret;
}

void
free_NVpair(StonithNVpair* nv)
{
	StonithNVpair* this;

	if (nv == NULL) {
		return;
	}
	for (this=nv; this->s_name; ++this) {
		free(this->s_name);
		if (this->s_value) {
			free(this->s_value);
		}
	}
	free(nv);
}
