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
#include <linux-ha/portability.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifdef HAVE_LIBINTL_H
#    include <libintl.h>
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
#include <pils/plugin.h>
#include <pils/generic.h>
#include <stonith/stonith.h>

#include <ltdl.h>

#define MAX_FUNC_NAME 20

#define	MALLOC(n)	malloc(n)
#define MALLOCT(t)	(t*)(malloc(sizeof(t)))
#define FREE(p)		{free(p); (p) = NULL;}

PILPluginUniv*		PIsys = NULL;
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

	if (PIsys) {
		return TRUE;
	}


	//PILpisysSetDebugLevel(10);
	PIsys = NewPILPluginUniv(STONITH_MODULES);
	
	if (PIsys) {
		if (PILLoadPlugin(PIsys, PI_IFMANAGER, "generic", Reqs)
		!=	PIL_OK){
			fprintf(stderr, "generic plugin load failed\n");
			DelPILPluginUniv(PIsys);
			PIsys = NULL;
		}
		//PILSetDebugLevel(PIsys, PI_IFMANAGER, "generic", 10);
	}else{
		fprintf(stderr, "pi univ creation failed\n");
	}
	return PIsys != NULL;
}

/*
 *	Create a new Stonith object of the requested type.
 */

Stonith *
stonith_new(const char * type)
{
	Stonith *		s;
	struct stonith_ops*	ops;
	char *			key;

	bindtextdomain(ST_TEXTDOMAIN, LOCALEDIR);

	if (!init_pluginsys()) {
		return NULL;
	}

	s = MALLOCT(Stonith);

	if (s == NULL) {
		return(NULL);
	}

	/* Look and see if we already have it loaded... */

	if (g_hash_table_lookup_extended(Splugins, type
	,	(gpointer*)&key, (gpointer*)&ops)) {
		PILIncrIFRefCount(PIsys, STONITH_TYPE_S, type, 1);

	}else{		/* Try and load it... */
		if (PILLoadPlugin(PIsys, STONITH_TYPE_S, type, NULL)
		!=	PIL_OK) {
			FREE(s);
			return NULL;
		}

		/* Look the plugin up in the Splugins table */
		if (!g_hash_table_lookup_extended(Splugins, type
		,		(void**)&key, (void**)&ops)) {
			/* OOPS! didn't find it(!?!)... */
			PILIncrIFRefCount(PIsys, STONITH_TYPE_S, type, -1);
			FREE(s);
			return NULL;
		}
	}

	s->s_ops = ops;
	s->stype = key;
	s->pinfo = s->s_ops->new();

	return s;
}

/*
 *	Return the list of Stonith types which can be given to stonith_new()
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

	lasttypelist = PILListPlugins(PIsys, STONITH_TYPE_S, NULL);
	return lasttypelist;
}

/* Destroy the STONITH object... */

void
stonith_delete(Stonith *s)
{
	if (!s) {
		return;
	}
	if (s->s_ops) {
		s->s_ops->destroy(s);
	}
	/*
	 * FIXME:  This triggers a bug!
	PILIncrIFRefCount(PIsys, STONITH_TYPE_S, s->stype, -1);
	 * Naughty Bug!
	 */
	s->pinfo = NULL;
	s->s_ops = NULL;
	s->stype = NULL;	/* It is part of plugin system */
				/* we cannot free it */

	FREE(s);
}
