/*
 * Copyright (C) 2000 Alan Robertson <alanr@unix.sh>
 * This software licensed under the GNU LGPL.
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

#ifndef PILS_PLUGIN_H
#  define PILS_PLUGIN_H
#  include <ltdl.h>
#  include <glue_config.h>

/* Glib headers generate warnings - so we make them go away */

#define		time	FOOtime
#define		index	FOOindex
#include	<glib.h>
#undef		index
#undef		time

/*****************************************************************************
 *	PILS - Universal Plugin and Interface loading system
 *****************************************************************************
 *
 * An Overview of PILS...
 *
 * PILS is fairly general and reasonably interesting plugin loading system.
 * We manage both plugins and their interfaces
 *
 * This plugin / interface management system is quite general, and should be
 * directly usable by basically any project on any platform on which it runs
 * - which should be many, since everything is build with automake
 * and libtool.
 *
 * Some terminology...
 *
 * There are two basic kinds of objects we deal with here:
 *
 * Plugins: dynamically loaded chunks of code which implement one or more
 *		interfaces.  The system treats all plugins as the same.
 *		In UNIX, these are dynamically loaded ".so" files.
 *
 * Interface: A set of functions which implement a particular capability
 * 		(or interface)
 * 	Generally interfaces are registered as part of a plugin.
 * 	The system treats all interfaces of the same type the same.
 * 	It is common to have exactly one interface inside of each plugin.
 * 	In this case, the interface name should match the plugin name.
 *
 * Each interface implementation exports certain functions for its clients
 * to use.   We refer to these those "Ops".  Every interface of the same type
 * "imports" the same interfaces from its interface manager,
 * and exports the same "Ops".
 *
 * Each interface implementation is provided certain interfaces which it
 * imports when it from its interface manager when it is registered.
 * We refer to these as "Imports".  Every interface of a given type
 * imports the same interfaces.
 *
 * The story with plugins is a little different...
 *
 * Every plugin exports a certain set of interfaces, regardless of what type
 * of interfaces is implemented by it.  These are described in the
 * PILPluginOps structure.
 *
 * Every plugin imports a certain set of interfaces, regardless of what type
 * of interfaces it may implement.  These are described by the
 * PILPluginImports structure.
 *
 * In the function parameters below, the following notation will
 * sometimes appear:
 *
 * (OP) == Output Parameter - a parameter which is modified by the
 * 	function being called
 *
 *
 *****************************************************************************
 *
 * The basic structures we maintain about plugins are as follows:
 *
 *	PILPlugin		The data which represents a plugin.
 *	PILPluginType		The data common to all plugins of a given type
 *	PILPluginUniv		The set of all plugin types in the Universe
 *					(well... at least *this* universe)
 *
 * The basic structures we maintain about interfaces are as follows:
 * 	PILInterface		The data which represents a interface
 * 	PILInterfaceType		The data which is common to all
 * 					interfaces of a given type
 *	PILPluginUniv		The set of all interface types in the Universe
 *					(well... at least *this* universe)
 *
 * Regarding "Universe"s.  It is our intent that a given program can deal
 * with plugins in more than one universe.  This might occur if you have two
 * independent libraries each of which uses the plugin loading environment
 * to manage their own independent interface components.  There should be
 * no restriction in creating a program which uses both of these libraries. 
 * At least that's what we hope ;-)
 *
 *
 ***************************************************************************
 * SOME MORE DETAILS ABOUT PLUGINS...
 ***************************************************************************
 *
 * Going back to more detailed data structures about plugins...
 *
 *	PILPluginImports		The set of standard functions all plugins
 *				import.
 *				This includes:
 *					register_plugin()
 *					unregister_plugin()
 *					register_interface()
 *					unregister_interface()
 *					load_plugin()
 *					log()	Preferred logging function
 *
 *	PILPluginOps		The set of standard operations all plugins
 *				export.
 *				This includes:
 *					pluginversion()
 *					pluginname()
 *					getdebuglevel()
 *					setdebuglevel()
 *					close()	    Prepare for unloading...
 *
 *	Although we treat plugins pretty much the same, they are still
 *	categorized into "types" - one type per directory.  These types
 *	generally correspond to interface types.
 *
 *	One can only cause a plugin to be loaded - not a interface.  But it is
 *	common to assume that loading a plugin named foo of type bar will
 *	cause a interface named foo of type bar to be registered.  If one
 *	wants to implement automatic plugin loading in a given interface type,
 *	this assumption is necessary.
 *
 *	The general way this works is...
 *
 *	- A request is made to load a particular plugin of a particular type.
 *
 *	- The plugin is loaded from the appropriate directory for plugins
 *		of that type.
 *
 *	- The ml_plugin_init() function is called once when the plugin is
 *		loaded.
 *
 *	The ml_plugin_init() function is passed a vector of functions which
 *		point to functions it can call to register itself, etc.
 *		(it's of type PILPluginImports)
 *
 * 	The ml_plugin_init function then uses this set of imported functions
 * 	to register itself and its interfaces.
 *
 * 	The mechanism of registering a interface is largely the same for
 * 	every interface.  However, the semantics of registering a interfaces
 * 	is determined by the interface manager for the particular type of
 * 	interface being discussed.
 *
 ***************************************************************************
 * SOME MORE DETAILS ABOUT PLUGINS...
 ***************************************************************************
 *
 *	There is only one built in type of interface.  That's the Interface
 *	manager interface.
 *	The interface manager for the interface of type "InterfaceMgr",
 *	named "InterfaceMgr" inserts itself into the system in order
 *	to bootstrap things...
 *
 *	When an attempt is made to register a interface of an unknown type,
 *	then the appropriate Interface manager is loaded automatically.
 *
 *	The name of an interface manager determines the type of
 *	interface it manages.
 *
 *	It handles requests for interfaces whose type is the same
 *	as its interface name.  If the interface manager's interface name
 *	is foo, then it is the interface manager for all interfaces whose
 *	type is foo.
 *
 * 	Types associated with interfaces of type Interface
 *
 *	PILInterfaceOps	The set of interfaces that every interface
 *				manager exports
 *	PILInterfaceImports	The set of interfaces which are supplied to
 *				(imported by) every interface of type
 *				Interface.  (that is, every interface
 *				manager).
 *
 *****************************************************************************
 *
 * Each plugin has only one entry point which is exported directly, regardless
 * of what kind of interface(s) it may implement...
 *
 * This entrypoint is named ml_plugin_init()	{more or less - see below}
 *
 * The ml_plugin_init() function is called once when the plugin is loaded.
 *
 *
 * All other function pointers are registered (exported) through parameters
 * passed to ml_plugin_init()
 *
 * It is the purpose of the Ml_plugin_init() to register the plugin,
 * and all the interfaces which this plugin implements.  A pointer to
 * the  registration function is in the parameters which are passed
 * to ml_plugin_init().
 *
 *****************************************************************************
 *
 * THINGS IN THIS DESIGN WHICH ARE PROBABLY BROKEN...
 *
 * It may also be the case that the plugin loading environment needs
 * to be able to have some kind of user_data passed to it which it can
 * also pass along to any interface ...
 *
 * Maybe this should be handled by a sort of global user_data registration
 * structure, so globals can be passed to interfaces when they're registered.
 *
 * A sort of "user_data" registry.  One for each interface type and one
 * for each interface...  Or maybe it could be even more flexible...
 *
 * This is all so that these nice pristene, beautiful concepts can come out
 * and work well in the real world where interfaces need to interact with
 * some kind of global system view, and with each other...
 *
 * Probably need some better way of managing interface versions, etc.
 *
 ****************************************************************************
 */

/*
 * If you want to use this funky export stuff, then you need to #define
 * PIL_PLUGINTYPE and PIL_PLUGIN *before* including this file.
 *
 * The way to use this stuff is to declare your primary entry point this way:
 *
 * This example is for an plugin of type "auth" named "sha1"
 *
 *	#define PIL_PLUGINTYPE	auth
 *	#define PIL_PLUGIN	sha1
 *	#include <upmls/PILPlugin.h>
 *
 *	static const char*	Ourpluginversion	(void);
 *	static const char*	Ourpluginname	(void);
 *	static int		Ourgetdebuglevel(void);
 *	static void		Oursetdebuglevel(int);
 *	static void		Ourclose	(PILPlugin*);
 *
 *	static struct PILPluginOps our_exported_plugin_operations =
 *	{	Ourpluginversion,
 *	,	Ourpluginname
 *	,	Ourgetdebuglevel
 *	,	Oursetdebuglevel
 *	,	Ourclose
 *	};
 *
 *	static const PILPluginImports*	PluginOps;
 *	static PILPlugin*		OurPlugin;
 *
 *	// Our plugin initialization and registration function
 *	// It gets called when the plugin gets loaded.
 *	PIL_rc
 *	PIL_PLUGIN_INIT(PILPlugin*us, const PILPluginImports* imports)
 *	{
 *		PluginOps = imports;
 *		OurPlugin = us;
 *
 *		// Register ourself as a plugin * /
 *		imports->register_plugin(us, &our_exported_plugin_operations);
 *
 *		// Register our interfaces
 *		imports->register_interface(us, "interfacetype", "interfacename"
 *			// Be sure and define "OurExports" and OurImports
 *			// above...
 *		,	&OurExports
 *		,	&OurImports);
 *		// Repeat for all interfaces in this plugin...
 *
 *	}
 *
 * Except for the PIL_PLUGINTYPE and the PIL_PLUGIN definitions, and changing
 * the names of various static variables and functions, every single plugin is
 * set up pretty much the same way
 *
 */

/*
 * No doubt there is a fancy preprocessor trick for avoiding these
 * duplications but I don't have time to figure it out.  Patches are
 * being accepted...
 */
#define	mlINIT_FUNC	_pil_plugin_init
#define mlINIT_FUNC_STR	"_pil_plugin_init"
#define PIL_INSERT	_LTX_
#define PIL_INSERT_STR	"_LTX_"

/*
 * snprintf-style format string for initialization entry point name:
 * 	arguments are: (plugintype, pluginname)
 */
#define	PIL_FUNC_FMT	"%s" PIL_INSERT_STR "%s" mlINIT_FUNC_STR

#ifdef __STDC__
#  define EXPORTHELPER1(plugintype, insert, pluginname, function)	\
	 plugintype##insert##pluginname##function
#else
#  define EXPORTHELPER1(plugintype, insert, pluginname, function)	\
 	plugintype/**/insert/**/pluginname/**/function
#endif

#define EXPORTHELPER2(a, b, c, d)    EXPORTHELPER1(a, b, c, d)
#define PIL_PLUGIN_INIT							\
	EXPORTHELPER2(PIL_PLUGINTYPE,PIL_INSERT,PIL_PLUGIN,mlINIT_FUNC)

/*
 *	Plugin loading return codes.  OK will always be zero.
 *
 *	There are many ways to fail, but only one kind of success ;-)
 */

typedef enum {
	PIL_OK=0,	/* Success */
	PIL_INVAL=1,	/* Invalid Parameters */
	PIL_BADTYPE=2,	/* Bad plugin/interface type */
	PIL_EXIST=3,	/* Duplicate Plugin/Interface name */
	PIL_OOPS=4,	/* Internal Error */
	PIL_NOPLUGIN=5	/* No such plugin or Interface */
}PIL_rc;			/* Return code from Plugin fns*/

const char * PIL_strerror(PIL_rc rc);

typedef struct PILPluginImports_s	PILPluginImports;
typedef struct PILPluginOps_s		PILPluginOps;
typedef struct PILPlugin_s		PILPlugin;
typedef struct PILPluginUniv_s		PILPluginUniv;
typedef struct PILPluginType_s		PILPluginType;

typedef struct PILInterface_s		PILInterface;
typedef struct PILInterfaceImports_s	PILInterfaceImports;
typedef struct PILInterfaceUniv_s	PILInterfaceUniv;
typedef struct PILInterfaceType_s	PILInterfaceType;

typedef PIL_rc(*PILInterfaceFun)(PILInterface*, void* ud_interface);

#define	PIL_MAGIC_PLUGIN	0xFEEDBEEFUL
#define	PIL_MAGIC_PLUGINTYPE	0xFEEDCEEFUL
#define	PIL_MAGIC_PLUGINUNIV	0xFEEDDEEFUL
#define	PIL_MAGIC_INTERFACE	0xFEEDEEEFUL
#define	PIL_MAGIC_INTERFACETYPE	0xFEEDFEEFUL
#define	PIL_MAGIC_INTERFACEUNIV	0xFEED0EEFUL

#define IS_PILPLUGIN(s)		((s)->MagicNum == PIL_MAGIC_PLUGIN)
#define IS_PILPLUGINTYPE(s)	((s)->MagicNum == PIL_MAGIC_PLUGINTYPE)
#define IS_PILPLUGINUNIV(s)	((s)->MagicNum == PIL_MAGIC_PLUGINUNIV)
#define IS_PILINTERFACE(s)	((s)->MagicNum == PIL_MAGIC_INTERFACE)
#define IS_PILINTERFACETYPE(s)	((s)->MagicNum == PIL_MAGIC_INTERFACETYPE)
#define IS_PILINTERFACEUNIV(s)	((s)->MagicNum == PIL_MAGIC_INTERFACEUNIV)

/* The type of a Plugin Initialization Function */
typedef PIL_rc (*PILPluginInitFun) (PILPlugin*us
,		PILPluginImports* imports
,		void*	plugin_user_data);

/*
 * struct PILPluginOps_s (typedef PILPluginOps) defines the set of functions
 * exported by all plugins...
 */
struct PILPluginOps_s {
	const char*	(*pluginversion) (void);
	int		(*getdebuglevel) (void);
	void		(*setdebuglevel) (int);
	const char*	(*license) (void);
	const char*	(*licenseurl) (void);
	void		(*close) (PILPlugin*);
};

/*
 *	Logging levels for the "standard" log interface.
 */

typedef enum {
	PIL_FATAL= 1,	/* BOOM! Causes program to stop */
	PIL_CRIT	= 2,	/* Critical -- serious error */
	PIL_WARN	= 3,	/* Warning */
	PIL_INFO	= 4,	/* Informative message */
	PIL_DEBUG= 5	/* Debug message */
}PILLogLevel;
typedef void (*PILLogFun)(PILLogLevel priority, const char * fmt, ...)
	G_GNUC_PRINTF(2,3);

/*
 * The size glib2 type du jour?
 * (once, this used to be size_t, so this change could break
 * distributions with older glib2 versions; if so, just add an
 * #ifelse below)
 */
#if GLIB_MINOR_VERSION <= 14
	typedef gulong glib_size_t;
#else
	typedef gsize glib_size_t;
#endif

/*
 * struct PILPluginImports_s (typedef PILPluginImports) defines
 * the functions and capabilities that every plugin imports when it is loaded.
 */


struct PILPluginImports_s {
	PIL_rc	(*register_plugin)(PILPlugin* piinfo
	,	const PILPluginOps* commonops);
	PIL_rc	(*unregister_plugin)(PILPlugin* piinfo);
/*
 *	A little explanation of the close_func parameter to register_interface
 *	is in order.
 *
 *	It is an exported operation function, just like the Ops structure.
 *	However, the Ops vector is exported to applications that
 *	are using the interface. Unlike the Ops structure, close_func is
 *	exported only to the interface system, since applications shouldn't
 *	call it directly, but should manage the reference counts for the
 *	interfaces instead.
 *	The generic interface system doesn't have any idea how to call
 *	any functions in the operations vector.  So, it's a separate
 *	parameter for two good reasons.
 */
	PIL_rc	(*register_interface)(PILPlugin* piinfo
	,	const char *	interfacetype	/* Type of interface	*/
	,	const char *	interfacename	/* Name of interface	*/
	,	void*		Ops		/* Info (functions) exported
						   by this interface	*/
		/* Function to call to shut down this interface */
	,	PILInterfaceFun	close_func

	,	PILInterface**	interfaceid /* Interface id 	(OP)	*/
	,	void**		Imports
	,	void*		ud_interface);	/* interface user data */

	PIL_rc	(*unregister_interface)(PILInterface* interfaceid);
	PIL_rc	(*load_plugin)(PILPluginUniv* universe
	,	const char * plugintype, const char * pluginname
	,	void*	plugin_private);

	void	(*log)	(PILLogLevel priority, const char * fmt, ...)
		G_GNUC_PRINTF(2,3);
        gpointer (*alloc)(glib_size_t size);
        gpointer (*mrealloc)(gpointer space, glib_size_t size);
	void	(*mfree)(gpointer space);
	char*	(*mstrdup)(const char *s);
};

/*
 * Function for logging with the given logging function
 * The reason why it's here is so we can get printf arg checking
 * You can't get that when you call a function pointer directly.
 */
void PILCallLog(PILLogFun logfun, PILLogLevel priority, const char * fmt, ...)
	G_GNUC_PRINTF(3,4);

/*
 * EXPORTED INTERFACES...
 */

/* Create a new plugin universe - start the plugin loading system up */
PILPluginUniv*	NewPILPluginUniv(const char * baseplugindirectory);

/* Change memory allocation functions right after creating universe */
void PilPluginUnivSetMemalloc(PILPluginUniv*
,       gpointer (*alloc)(glib_size_t size)
,       gpointer (*mrealloc)(gpointer, glib_size_t size)
,	void	(*mfree)(void* space)
,	char*	(*mstrdup)(const char *s));


void PilPluginUnivSetLog(PILPluginUniv*
,	void	(*log)	(PILLogLevel priority, const char * fmt, ...)
	G_GNUC_PRINTF(2,3));


/* Delete a plugin universe - shut the plugin loading system down */
/*	Best if used carefully ;-) */
void		DelPILPluginUniv(PILPluginUniv*);

/* Set the debug level for the plugin system itself */
void		PILpisysSetDebugLevel (int level);

/* Return a list of plugins of the given type */
char **		PILListPlugins(PILPluginUniv* u, const char *plugintype
,		int* plugincount /*can be NULL*/);

/* Free the plugin list returned by PILFreeListPlugins */
void		PILFreePluginList(char ** pluginlist);

/* Load the requested plugin */
PIL_rc		PILLoadPlugin(PILPluginUniv* piuniv
,		const char *	plugintype
,		const char *	pluginname
,		void *		pi_private);

/* Return  PIL_OK if the given  plugin exists */
PIL_rc		PILPluginExists(PILPluginUniv* piuniv
,		const char *	plugintype
,		const char *	pluginname);

/* Either or both of pitype and piname may be NULL */
void		PILSetDebugLevel(PILPluginUniv*u, const char * pitype
,		const char * piname
,		int level);

/* Neither pitype nor piname may be NULL */
int		PILGetDebugLevel(PILPluginUniv* u, const char * pitype
,		const char * piname);

PIL_rc		PILIncrIFRefCount(PILPluginUniv* piuniv
,		const char *	interfacetype
,		const char *	interfacename
,		int	plusminus);

int		PILGetIFRefCount(PILPluginUniv* piuniv
,		const char *	interfacetype
,		const char *	interfacename);

void PILLogMemStats(void);
/* The plugin/interface type of a interface manager */

#define	PI_IFMANAGER		"InterfaceMgr"
#define	PI_IFMANAGER_TYPE	InterfaceMgr

/*
 *      These functions are standard exported functions for all plugins.
 */

#define PIL_PLUGIN_BOILERPLATE_PROTOTYPES_GENERIC(PluginVersion, DebugName) \
/*								\
 * Prototypes for boilerplate functions				\
 */								\
static const char*      Ourpluginversion(void);			\
static int              GetOurDebugLevel(void);			\
static void             SetOurDebugLevel(int);			\
static const char *	ReturnOurLicense(void);			\
static const char *	ReturnOurLicenseURL(void);

#define	PIL_PLUGIN_BOILERPLATE_FUNCS(PluginVersion, DebugName)	\
/*								\
 * Definitions of boilerplate functions				\
 */								\
static const char*						\
Ourpluginversion(void)						\
{ return PluginVersion; }					\
								\
static int DebugName = 0;					\
								\
static int							\
GetOurDebugLevel(void)						\
{ return DebugName; }						\
								\
static void							\
SetOurDebugLevel(int level)					\
{ DebugName = level; }						\
								\
static const char *						\
ReturnOurLicense(void)						\
{ return PIL_PLUGINLICENSE; }					\
								\
static const char *						\
ReturnOurLicenseURL(void)					\
{ return PIL_PLUGINLICENSEURL; }

#define PIL_PLUGIN_BOILERPLATE(PluginVersion, DebugName, CloseName) \
PIL_PLUGIN_BOILERPLATE_PROTOTYPES_GENERIC(PluginVersion, DebugName) \
static void             CloseName(PILPlugin*);			\
/*								\
 * Initialize Plugin Exports structure				\
 */								\
static PILPluginOps OurPIExports =				\
{	Ourpluginversion					\
,	GetOurDebugLevel					\
,	SetOurDebugLevel					\
,	ReturnOurLicense					\
,	ReturnOurLicenseURL					\
,	CloseName						\
};								\
PIL_PLUGIN_BOILERPLATE_FUNCS(PluginVersion, DebugName)

#define PIL_PLUGIN_BOILERPLATE2(PluginVersion, DebugName)	\
PIL_PLUGIN_BOILERPLATE_PROTOTYPES_GENERIC(PluginVersion, DebugName) \
/*								\
 * Initialize Plugin Exports structure				\
 */								\
static PILPluginOps OurPIExports =				\
{	Ourpluginversion					\
,	GetOurDebugLevel					\
,	SetOurDebugLevel					\
,	ReturnOurLicense					\
,	ReturnOurLicenseURL					\
,	NULL							\
};								\
PIL_PLUGIN_BOILERPLATE_FUNCS(PluginVersion, DebugName)


/* A few sample licenses and URLs.  We can easily add to this */

#define	LICENSE_GPL	 "gpl"
#define	URL_GPL		"http://www.fsf.org/licenses/gpl.html"

#define	LICENSE_LGPL	"lgpl"
#define	URL_LGPL	"http://www.fsf.org/licenses/lgpl.html"

#define	LICENSE_X11	"x11"
#define	URL_X11		"http://www.x.org/terms.htm"

#define	LICENSE_PUBDOM	"publicdomain"
#define	URL_PUBDOM	"file:///dev/null"

#define	LICENSE_MODBSD	"modbsd"
#define	URL_MODBSD	"http://www.xfree86.org/3.3.6/COPYRIGHT2.html#5"

#define	LICENSE_OLDBSD	"origbsd"
#define	URL_OLDBSD	"http://www.xfree86.org/3.3.6/COPYRIGHT2.html#6"

#define	LICENSE_EXPAT	"expat"
#define	URL_EXPAT	"http://www.jclark.com/xml/copying.txt"

#define LICENSE_ZLIB	"zlib"
#define URL_ZLIB	"http://www.gzip.org/zlib/zlib_license.html"

#define	LICENSE_APACHE_10 "apache1_0"
#define	URL_APACHE_10	"http://www.apache.org/LICENSE-1.0"

#define	LICENSE_APACHE_11 "apache1_1"
#define	URL_APACHE_11	"http://www.apache.org/LICENSE-1.1"

#define	LICENSE_MPL	"mpl"
#define	URL_MPL		"http://www.mozilla.org/MPL/MPL-1.1.html"

#define	LICENSE_PROP	"proprietary"
#define	URL_PROP	""

#define	LICENSE_IBMPL	"ibmpl"
#define	URL_IBMPL	"http://oss.software.ibm.com/developerworks/opensource/license10.html"

#ifdef ENABLE_PIL_DEFS_PRIVATE
/* Perhaps these should be moved to a different header file */

/*
 * PILPluginType is the "class" for the basic plugin loading mechanism.
 *
 * To enable loading of plugins from a particular plugin type
 * one calls NewPILPluginType with the plugin type name, the plugin
 * base directory, and the set of functions to be imported to the plugin.
 *
 *
 * The general idea of these structures is as follows:
 *
 * The PILPluginUniv object contains information about all plugins of
 * all types.
 *
 * The PILPluginType object contains information about all the plugins of a
 * specific type.
 *
 * Note: for plugins which implement a single interface, the plugin type name
 * should be the same as the interface type name.
 *
 * For other plugins that implement more than one interface, one of
 * the interface names should normally match the plugin name.
 */


/*
 * struct PILPlugin_s (typedef PILPlugin) is the structure which
 * represents/defines a plugin, and is used to identify which plugin is
 * being referred to in various function calls.
 *
 * NOTE: It may be the case that this definition should be moved to
 * another header file - since no one ought to be messing with them anyway ;-)
 *
 * I'm not sure that we're putting the right stuff in here, either...
 */

struct PILPlugin_s {
	unsigned long	MagicNum;	
	char*		plugin_name;
	PILPluginType*	plugintype;	/* Parent structure */
	int		refcnt;		/* Reference count for this plugin */
	lt_dlhandle	dlhandle;	/* Reference to D.L. object */
	PILPluginInitFun dlinitfun;	/* Initialization function */
	const PILPluginOps* pluginops;	/* Exported plugin operations */

	void*		ud_plugin;	/* Plugin-Private data */
	/* Other stuff goes here ...  (?) */
};

/*
 *	PILPluginType		Information about all plugins of a given type.
 *					(i.e.,  in a given directory)
 *				(AKA struct PILPluginType_s)
 */

struct PILPluginType_s {
	unsigned long		MagicNum;	
	char *			plugintype;
	PILPluginUniv*		piuniv; /* The universe to which we belong */
	GHashTable*		Plugins;
				/* Key is plugin type, value is PILPlugin */

	char**	(*listplugins)(PILPluginType*, int* listlen);
};

/*
 *	PILPluginUniv (aka struct PILPluginUniv_s) is the structure which
 *	represents the universe of all PILPluginType objects.
 *	There is one PILPluginType object for each Plugin type.
 */

struct PILPluginUniv_s {
	unsigned long		MagicNum;	
	char **			rootdirlist;
			/* key is plugin type, data is PILPluginType* */
	GHashTable*		PluginTypes;
	struct PILInterfaceUniv_s*ifuniv; /* Universe of interfaces */
	PILPluginImports*	imports;
};

#  endif /* ENABLE_PIL_DEFS_PRIVATE */
#endif /*PILS_PLUGIN_H */
