#include <stdio.h>
#include <pils/plugin.h>

#define MOD	"/home/alanr/modules"

int
main(int argc, char ** argv)
{
	PILPluginUniv *	u;


	u = NewPILPluginUniv(MOD);
	PILSetDebugLevel(u, NULL, NULL, 100);
	PILLogMemStats();

	printf("Load of foo: %d\n"
	,	PILLoadPlugin(u, PI_IFMANAGER, "test", NULL));
	printf("Error = [%s]\n", lt_dlerror());
	PILLogMemStats();
	DelPILPluginUniv(u); u = NULL;
	PILLogMemStats();

	return 0;
}
