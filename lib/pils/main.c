/*
 * Copyright (C) 2001 Alan Robertson <alanr@unix.sh>
 * This software licensed under the GNU LGPL.
 *
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
#include <lha_internal.h>
#include <stdio.h>
#include <pils/generic.h>

#define MOD	"/home/alanr/modules"

GHashTable*	test1functions = NULL;

long	one = 1;
long	two = 2;
long	three = 3;
long	four = 4;

static int TestCallBack
(	GenericPILCallbackType t
,	PILPluginUniv*	univ
,	const char *	iftype
,	const char *	ifname
,	void*		userptr
);

static PILGenericIfMgmtRqst RegRqsts [] =
  {	{"test",	&test1functions, &one, TestCallBack, &two},
	{NULL,		NULL,		NULL,	NULL,	NULL}
};

int
main(int argc, char ** argv)
{
	PILPluginUniv *	u;
	PIL_rc		rc;
	int		j;


	u = NewPILPluginUniv(MOD);
	/* PILSetDebugLevel(u, NULL, NULL, 0); */
	PILLogMemStats();

	 
        if ((rc = PILLoadPlugin(u, "InterfaceMgr", "generic", &RegRqsts))
	!=	PIL_OK) {    
		fprintf(stderr, "generic plugin load Error = [%s]\n"
		,	lt_dlerror());
		/*exit(1);*/
	}
	/* PILSetDebugLevel(u, NULL, NULL, 0); */

	for (j=0; j < 10; ++j) {
		PILLogMemStats();
		fprintf(stderr, "****Loading plugin test/test\n");
        	if ((rc = PILLoadPlugin(u, "test", "test", NULL)) != PIL_OK) {
			printf("ERROR: test plugin load error = [%d/%s]\n"
			,	rc, lt_dlerror());
		}
		PILLogMemStats();
		fprintf(stderr, "****UN-loading plugin test/test\n");
		if ((rc = PILIncrIFRefCount(u, "test", "test", -1))!= PIL_OK){
			printf("ERROR: test plugin UNload error = [%d/%s]\n"
			,	rc, lt_dlerror());
		}
	}
	PILLogMemStats();
	DelPILPluginUniv(u); u = NULL;
	PILLogMemStats();

	return 0;
}


static int
TestCallBack
(	GenericPILCallbackType t
,	PILPluginUniv*	univ
,	const char *	iftype
,	const char *	ifname
,	void*	userptr)
{
	char cbbuf[32];

	switch(t) {
		case PIL_REGISTER:
			snprintf(cbbuf, sizeof(cbbuf), "PIL_REGISTER");
			break;

		case PIL_UNREGISTER:
			snprintf(cbbuf, sizeof(cbbuf), "PIL_UNREGISTER");
			break;

		default:
			snprintf(cbbuf, sizeof(cbbuf), "type [%d?]", t);
			break;
	}

	fprintf(stderr, "Callback: (%s, univ: 0x%lx, module: %s/%s, user ptr: 0x%lx (%ld))\n"
	,	cbbuf
	,	(unsigned long) univ
	,	iftype, ifname
	,	(unsigned long)userptr
	,	(*((long *)userptr)));
	return PIL_OK;
}

