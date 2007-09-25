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
/*
 *	Sample Interface manager.
 */
#define	PIL_PLUGINTYPE		test
#define	PIL_PLUGINTYPENAME	"test"
#define	PIL_PLUGIN		test
#define	PIL_PLUGINNAME		"test"
#define	PIL_PLUGINLICENSE	LICENSE_LGPL
#define	PIL_PLUGINLICENSEURL	URL_LGPL

/* We are a interface manager... */
#define ENABLE_PLUGIN_MANAGER_PRIVATE

#include <pils/interface.h>

PIL_PLUGIN_BOILERPLATE("1.0", DebugFlag, Ourclose)

/*
 *	Places to store information gotten during registration.
 */
static const PILPluginImports*	OurPIImports;	/* Imported plugin funs */
static PILPlugin*		OurPlugin;	/* Our plugin info */
static PILInterfaceImports*	OurIfImports;	/* Interface imported funs */
static PILInterface*		OurIf;		/* Pointer to interface info */

static void
Ourclose	(PILPlugin* us)
{
}

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
	OurPIImports->log(PIL_INFO, "In Ifclose (test plugin)");
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

	imports->log(PIL_INFO, "Plugin %s: user_ptr = %lx"
	,	PIL_PLUGINNAME, (unsigned long)user_ptr);

	imports->log(PIL_INFO, "Registering ourselves as a plugin");

	/* Register as a plugin */
	imports->register_plugin(us, &OurPIExports);
 
	imports->log(PIL_INFO, "Registering our interfaces");

	/*  Register our interfaces */
	ret = imports->register_interface
	(	us
	,	PIL_PLUGINTYPENAME
	,	PIL_PLUGINNAME
	,	&OurIfOps	/* Exported interface operations */
	,	IfClose		/* Interface Close function */
	,	&OurIf
	,	(void*)&OurIfImports
	,	NULL);
	imports->log(PIL_INFO, "test init function: returning %d"
		,	ret);

	return ret;
}
