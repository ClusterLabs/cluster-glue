/*
 * Copyright (C) 2000 Alan Robertson <alanr@unix.sh>
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
#ifndef PILS_INTERFACE_H
#  define PILS_INTERFACE_H
#  ifndef PILS_PLUGIN_H
#    include <pils/plugin.h>
#  endif

/*****************************************************************************
 *
 * The most basic interface type is the "IFManager" interface.
 * Each interface manager registers and deals with interfaces of a given type.
 *
 * Such an interface must be loaded before any plugins of it's type can
 * be loaded.
 *
 * In order to register any plugin of type "foo", we must load a interface of
 * type "Interface" named "foo".  This interface then manages the
 * registration of all interfaces of type foo.
 *
 * To bootstrap, we load a interface of type "Interface" named "Interface"
 * during the initialization of the plugin system.
 *
 * IFManagers will be autoloaded if certain conditions are met...
 *
 * If a IFManager is to be autoloaded, there must be one interface manager
 * per file, and the file must be named according to the type of the
 * interface it implements, and loaded in the directory named PI_IFMANAGER
 * ("Interface").
 *
 */


/*
 *	I'm unsure exactly which of the following structures
 *	are needed to write a interface, or a interface manager.
 *	We'll get that figured out and scope the defintions accordingly...
 */

/*
 *	PILInterface (AKA struct PILInterface_s) holds the information
 *	we use to track a single interface manager.
 */


struct PILInterface_s {
	unsigned long		MagicNum;	
	PILInterfaceType*	interfacetype;	/* Parent pointer	*/
	char *			interfacename;	/* malloced interface name */
	PILInterface*		ifmanager;	/* plugin managing us	*/
	void*			exports;	/* Exported Functions	*/
						/* for this interface	*/
	PILInterfaceFun		if_close;	/* Interface close operation*/
	void*			ud_interface;	/* per-interface user data */
	int			refcnt;		/* Ref count for plugin	*/
	PILPlugin*		loadingpi;	/* Plugin that loaded us */
};
/*
 *	PILInterfaceType (AKA struct PILInterfaceType_s) holds the info
 *	we use to track the set of all interfaces of a single kind.
 */
struct PILInterfaceType_s {
	unsigned long		MagicNum;	
	char*			typename;	/* Our interface type name */
	GHashTable*		interfaces;	/* The set of interfaces
						 * of our type.  The
						 * "values" are all
						 * PILInterface * objects
						 */
	void*			ud_if_type;	/* per-interface-type user
						   data*/
	PILInterfaceUniv*	universe;	/* Pointer to parent (up) */
	PILInterface*		ifmgr_ref;	/* Pointer to our interface
						   manager */
};

/*
 *	PILInterfaceUniv (AKA struct PILInterfaceUniv_s) holds the information
 *	for all interfaces of all types.  From our point of view this is
 *	our universe ;-)
 */

struct PILInterfaceUniv_s{
	unsigned long		MagicNum;	
	GHashTable*		iftypes;	/*
						 * Set of Interface Types
						 * The values are all
						 * PILInterfaceType objects
						 */
	struct PILPluginUniv_s*	piuniv;		/* parallel universe of
						 * plugins
						 */
};

#ifdef ENABLE_PLUGIN_MANAGER_PRIVATE
/*
 * From here to the end is specific to interface managers.
 * This data is only needed by interface managers, and the interface
 * management system itself.
 *
 */
typedef struct PILInterfaceOps_s		PILInterfaceOps;


/* Interfaces imported by a IFManager interface */
struct PILInterfaceImports_s {

		/* Return current reference count */
	int (*RefCount)(PILInterface * eifinfo);

		/* Incr/Decr reference count */
	int (*ModRefCount)(PILInterface*eifinfo, int plusminus);

		/* Unregister us as a interface */
	void (*ForceUnRegister)(PILInterface *eifinfo);

		/* For each client */
	void (*ForEachClientDel)(PILInterface* manangerif
	,	gboolean(*f)(PILInterface* clientif, void * other)
	,	void* other);

};

/* Interfaces exported by an InterfaceManager interface */
struct PILInterfaceOps_s{
/*
 *	These are the interfaces exported by an InterfaceManager to the
 *	interface management infrastructure.  These are not imported
 *	by interfaces - only the interface management infrastructure.
 */

	/* RegisterInterface - register this interface */
 	PIL_rc (*RegisterInterface)(PILInterface* newif
		,	void**	imports);

	PIL_rc	(*UnRegisterInterface)(PILInterface*ifinfo); /* Unregister IF*/
				/* And destroy PILInterface object */
};

#endif /* ENABLE_PLUGIN_MANAGER_PRIVATE */
#endif /* PILS_INTERFACE_H */
