/*
 *	Heartbeat authentication interface manager
 *
 *	Copyright 2001 Alan Robertson <alanr@unix.sh>
 *	Licensed under the GNU Lesser General Public License
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
 */
#define	PIL_PLUGINTYPE	InterfaceMgr
#define	PIL_PLUGIN	HBauth

#define PIN(f) #f
#define PIN2(f) PIN(f)
#define PIN3	PIN2(PIL_PLUGIN)
#define PIT	PIN2(PIL_PLUGINTYPE)

/* We are a interface manager... */
#define ENABLE_PLUGIN_MANAGER_PRIVATE

#include <lha_internal.h>
#include <pils/interface.h>
#include <stdio.h>

PIL_PLUGIN_BOILERPLATE2("1.0", AuthDebugFlag)


/*
 *	Places to store information gotten during registration.
 */
static const PILPluginImports*	AuthPIImports;	/* Imported plugin fcns */
static PILPlugin*		AuthPlugin;	/* Our plugin info */
static PILInterfaceImports*	AuthIfImports;	/* Interface imported fcns */
static PILInterface*		AuthIf;		/* Our Auth Interface info */

/* Our exported auth interface management functions */
static PIL_rc RegisterAuthIF(PILInterface* ifenv, void**	imports);

static PIL_rc UnregisterAuthIF(PILInterface*iifinfo);

/*
 *	Our Interface Manager interfaces - exported to the universe!
 *
 *	(or at least to the interface management universe ;-).
 *
 *	These are the interfaces which are used to manage our
 *	client authentication interfaces
 *
 */
static PILInterfaceOps		AuthIfOps =
{	RegisterAuthIF
,	UnregisterAuthIF
};


PIL_rc PIL_PLUGIN_INIT(PILPlugin*us, PILPluginImports* imports, void*);

/*
 *	Our user_ptr is presumed to point at a GHashTable for us
 *	to put plugin into when they show up, and drop from when
 *	they disappear.
 *
 *	We need to think more carefully about the way for us to get
 *	the user_ptr from the global environment.
 *
 *	We need to think more carefully about how interface registration
 *	etc. interact with plugin loading, reference counts, etc. and how
 *	the application that uses us (i.e., heartbeat) interacts with us.
 *
 * 	Issues include:
 * 	- freeing all memory,
 * 	- making sure things are all cleaned up correctly
 * 	- Thread-safety?
 *
 * 	I think the global system should handle thread-safety.
 */

PIL_rc
PIL_PLUGIN_INIT(PILPlugin*us, PILPluginImports* imports, void *user_ptr)
{
	PIL_rc		ret;
	/*
	 * Force compiler to check our parameters...
	 */
	PILPluginInitFun	fun = &PIL_PLUGIN_INIT; (void)fun;


	if (user_ptr == NULL) {
		imports->log(PIL_CRIT
		,	"Interface Manager %s requires non-NULL "
		" user pointer (to GHashTable) at initialization"
		,	PIN3);
		return PIL_INVAL;
	}

	AuthPIImports = imports;
	AuthPlugin = us;

	/* Register as a plugin */
	imports->register_plugin(us, &OurPIExports);
 

	/*  Register our interfaces */
	ret = imports->register_interface(us
	,	PIT
	,	PIN3
	,	&AuthIfOps
	,	NULL
	,	&AuthIf			/* Our interface object pointer */
	,	(void**)&AuthIfImports	/* Interface-imported functions */
	,	user_ptr);
	return ret;
}

/*
 *	We get called for every authentication interface that gets registered.
 *
 *	It's our job to make the authentication interface that's
 *	registering with us available to the system.
 *
 *	We do that by adding it to a g_hash_table of authentication
 *	plugin.  The rest of the system takes it from there...
 *	The key is the authentication method, and the data
 *	is a pointer to the functions the method exports.
 *	It's a piece of cake ;-)
 */
static PIL_rc
RegisterAuthIF(PILInterface* intf,  void** imports)
{
	GHashTable*	authtbl = intf->ifmanager->ud_interface;

	g_assert(authtbl != NULL);

	/* Reference count should now be one */
	g_assert(intf->refcnt == 1);
	g_hash_table_insert(authtbl, intf->interfacename, intf->exports);

	return PIL_OK;
}

/* Unregister a client authentication interface -
 * 	We get called from the interface mgmt sys when someone requests that
 * 	a interface be unregistered.
 */
static PIL_rc
UnregisterAuthIF(PILInterface*intf)
{
	GHashTable*	authtbl = intf->ifmanager->ud_interface;
	g_assert(authtbl != NULL);

	intf->refcnt--;
	g_assert(intf->refcnt >= 0);
	if (intf->refcnt <= 0) {
		g_hash_table_remove(authtbl, intf->interfacetype);
	}
	return PIL_OK;
}

