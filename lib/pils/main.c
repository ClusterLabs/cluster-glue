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
{	{"test",	&test1functions, &one, TestCallBack, &two}
};

int
main(int argc, char ** argv)
{
	PILPluginUniv *	u;
	PIL_rc		rc;
	int		j;


	u = NewPILPluginUniv(MOD);
	PILSetDebugLevel(u, NULL, NULL, 100);
	PILLogMemStats();

	 
        if ((rc = PILLoadPlugin(u, "InterfaceMgr", "generic", &RegRqsts))
	!=	PIL_OK) {    
		fprintf(stderr, "generic plugin load Error = [%s]\n"
		,	lt_dlerror());
		/*exit(1);*/
	}
	PILSetDebugLevel(u, NULL, NULL, 100);

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

