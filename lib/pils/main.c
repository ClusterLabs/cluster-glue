#include <stdio.h>
#include <upmls/MLPlugin.h>

#define MOD	"/home/alanr/modules"

int
main(int argc, char ** argv)
{
	PILPluginUniv *	u;


	u = NewPILPluginUniv(MOD);
	PILLogMemStats();
	PILSetDebugLevel(100);

	printf("Load of foo: %d\n"
	,	PILLoadPlugin(u, PI_IFMANAGER, "test", NULL));
	printf("Error = [%s]\n", lt_dlerror());
	PILLogMemStats();
	DelPILPluginUniv(u); u = NULL;
	PILLogMemStats();

	return 0;
}
