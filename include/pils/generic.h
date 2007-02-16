#ifndef PILS_GENERIC_H
#define PILS_GENERIC_H
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
 *
 * Generic interface (implementation) manager
 *
 * This manager will manage any number of types of interfaces.
 *
 * This means that when any implementations of our client interfaces register
 * or unregister, it is us that makes their interfaces show up in the outside
 * world.
 *
 * And, of course, we have to do this in a very generic way, since we have
 * no idea about the client programs or interface types, or anything else.
 *
 * We do that by getting a parameter passed to us which tell us the names
 * of the interface types we want to manage, and the address of a GHashTable
 * for each type that we put the implementation in when they register
 * themselves.
 *
 * So, each type of interface that we manage gets its own private
 * GHashTable of the implementations of that type that are currently
 * registered.
 *
 * For example, if we manage communication modules, their exported
 * interfaces will be registered in a hash table.  If we manage
 * authentication modules, they'll have their (separate) hash table that
 * their exported interfaces are registered in.
 * 
 */
#include <pils/interface.h>

/*
 * Header defintions for using the generic interface/implementation
 * manager plugin.
 */

/*
 *	Notification types for the callback function.
 */
typedef enum {
	PIL_REGISTER,	/* Someone has registered an implementation */
	PIL_UNREGISTER 	/* Someone has unregistered an implementation */
}GenericPILCallbackType;
 
/* A user callback for the generic interface manager */
typedef int (*GenericPILCallback)
(	GenericPILCallbackType	type	/* Event type */
,	PILPluginUniv*		univ	/* pointer to plugin universe */
,	const char * 		iftype	/* Interface type */
,	const char *		ifname	/* Implementation (interface) name */
,	void *			userptr	/* Whatever you want it to be ;-) */
);

/*
 * Structures to declare the set of interface types we're managing.
 */
typedef struct {
	const char *	   iftype;	/* What type of interface is this? */
	GHashTable**	   ifmap;	/* Table with implementation info */
	void*		   importfuns;	/* Functions for interface to import */
	GenericPILCallback callback;	/* Function2call when events occur */
	void*		   userptr;	/* Passed to Callback function */
}PILGenericIfMgmtRqst;
/*
 * What does this look like in practice?
 *
 * GHashTable*	authmodules = NULL;
 * GHashTable*	commmodules = NULL;
 * PILGenericIfMgmtRqst RegisterRequests[] =
 * {
 * 	{"auth",	&authmodules,	&authimports,	NULL,	NULL},
 * 	{"comm",	&commmodules,	&commimports,	NULL,	NULL},
 * 	{NULL,		NULL,		NULL,		NULL,	NULL}
	// NULL entry must be here
 * };
 *
 * PILPlugin*	PluginUniverse;
 *
 * PluginUniverse = NewPILPlugin("/usr/lib/whatever/plugins");
 *
 * PILLoadPlugin(PluginUniverse, "InterfaceMgr", "generic", &RegisterRequests);
 *	// N. B.: Passing RegisterRequests as an argument is essential
 *
 * Then, when you load an auth module, its exported interface gets added
 * to "authmodules". When you unload an auth module, it gets removed
 * from authmodules.
 *
 * Then, when you load a comm module, its exported interfaces gets added
 * to "commodules".  When you unload a comm module, its exported
 * interfaces get removed from "commodules"
 *
 * If there are simple changes that would be useful for this generic
 * plugin manager, then "patches are being accepted" :-)
 * 
 * On the other hand, If you don't like the way this plugin manager works
 * in a broader way, you're free to write your own  - it's just another
 * plugin ;-)
 */
#endif
