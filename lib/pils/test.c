/*
 *	Sample Interface manager.
 */
#define	PIL_PLUGINTYPE		test
#define	PIL_PLUGINTYPENAME	"test"
#define	PIL_PLUGIN		test
#define	PIL_PLUGINNAME		"test"

/* We are a interface manager... */
#define ENABLE_PLUGIN_MANAGER_PRIVATE

#include <pils/interface.h>
 
PIL_PLUGIN_BOILERPLATE("1.0", DebugFlag, Ourclose)

static void
Ourclose	(PILPlugin* us)
{
}

/*
 *	Places to store information gotten during registration.
 */
static const PILPluginImports*	OurPIImports;	/* Imported plugin funs */
static PILPlugin*		OurPlugin;	/* Our plugin info */
static PILInterfaceImports*	OurIfImports;	/* Interface imported funs */
static PILInterface*		OurIf;		/* Pointer to interface info */

/*
 *	Our Interface Manager interfaces - exported to the universe!
 *
 *	(or at least the interface management universe ;-).
 *
 */
static PILInterfaceOps		OurIfOps = {
	/* FIXME -- put some in here !! */
};

PIL_rc PIL_PLUGIN_INIT(PILPlugin*us, PILPluginImports* imports, void*);

static PIL_rc
IfClose(PILInterface*intf, void* ud_interface)
{
	OurPIImports->log(PIL_DEBUG, "In Ifclose (test plugin)");
	return PIL_OK;
}

PIL_rc
PIL_PLUGIN_INIT(PILPlugin*us, PILPluginImports* imports, void *user_ptr)
{
	PIL_rc		ret;
	/*
	 * Force compiler to check our parameters...
	 */
	PILPluginInitFun	fun = &PIL_PLUGIN_INIT; (void)fun;


	OurPIImports = imports;
	OurPlugin = us;

	imports->log(PIL_DEBUG, "Plugin %s: user_ptr = %lx"
	,	PIL_PLUGINNAME, (unsigned long)user_ptr);

	imports->log(PIL_DEBUG, "Registering ourselves as a plugin");

	/* Register as a plugin */
	imports->register_plugin(us, &OurPIExports);
 
	imports->log(PIL_DEBUG, "Registering our interfaces");

	/*  Register our interfaces */
	ret = imports->register_interface
	(	us
	,	PIL_PLUGINTYPENAME
	,	PIL_PLUGINNAME
	,	&OurIfOps	/* Exported interface operations */
	,	IfClose		/* Interface Close function */
	,	&OurIf
	,	(void**)&OurIfImports
	,	NULL);
	imports->log(PIL_DEBUG, "Returning %d", ret);

	return ret;
}
