/* $Id: GSource.h,v 1.4 2004/02/17 22:11:58 lars Exp $ */
#ifndef _CLPLUMBING_GSOURCE_H
#	define _CLPLUMBING_GSOURCE_H
#	include <clplumbing/ipc.h>

typedef	struct GFDSource_s	GFDSource;
typedef struct GCHSource_s	GCHSource;
typedef struct GWCSource_s	GWCSource;

/***********************************************************************
 *	Functions for interfacing "raw" file descriptors to the mainloop
 ***********************************************************************/
/*
*	Add a file descriptor to the gmainloop world...
 */
GFDSource* G_main_add_fd(int priority, int fd, gboolean can_recurse
,	gboolean (*dispatch)(int fd, gpointer user_data)
,	gpointer userdata
,	GDestroyNotify notify);

/*
 *	Delete a file descriptor from the gmainloop world...
 *	Note: destroys the GFDSource object.
 */
gboolean G_main_del_fd(GFDSource* fdp);

/*
 *	Notify us that a file descriptor is blocked on output.
 *	(i.e., we should poll for output events)
 */
void g_main_output_is_blocked(GFDSource* fdp);


/**************************************************************
 *	Functions for interfacing IPC_Channels to the mainloop
 **************************************************************/
/*
 *	Add an IPC_channel to the gmainloop world...
 */
GCHSource* G_main_add_IPC_Channel(int priority, IPC_Channel* ch
,	gboolean can_recurse
,	gboolean (*dispatch)(IPC_Channel* source_data
,		gpointer        user_data)
,	gpointer userdata
,	GDestroyNotify notify);

/*
 *	Delete an IPC_channel from the gmainloop world...
 *	Note: destroys the GCHSource object, and the IPC_Channel
 *	object automatically.
 */
gboolean G_main_del_IPC_Channel(GCHSource* chp);


/*********************************************************************
 *	Functions for interfacing IPC_WaitConnections to the mainloop
 ********************************************************************/
/*
 *	Add an IPC_WaitConnection to the gmainloop world...
 *	Note that the dispatch function is called *after* the
 *	connection is accepted.
 */
GWCSource* G_main_add_IPC_WaitConnection(int priority, IPC_WaitConnection* ch
,	IPC_Auth* auth_info
,	gboolean can_recurse
,	gboolean (*dispatch)(IPC_Channel* source_data
,		gpointer user_data)
,	gpointer userdata
,	GDestroyNotify notify);

/*
 *	Delete an IPC_WaitConnection from the gmainloop world...
 *	Note: destroys the GWCSource object, and the IPC_WaitConnection
 *	object automatically.
 */
gboolean G_main_del_IPC_WaitConnection(GWCSource* wcp);

#endif
