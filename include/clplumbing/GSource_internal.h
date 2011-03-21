/*
 * Author:	Alan Robertson <alanr@unix.sh>
 * Copyright (C) 2005 International Business Machines Inc.
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <clplumbing/longclock.h>
#include <clplumbing/GSource.h>

#define	MAG_GFDSOURCE	0xfeed0001U
#define	MAG_GCHSOURCE	0xfeed0002U
#define	MAG_GWCSOURCE	0xfeed0003U
#define	MAG_GSIGSOURCE	0xfeed0004U
#define	MAG_GTRIGSOURCE	0xfeed0005U
#define	MAG_GTIMEOUTSRC	0xfeed0006U

#define	IS_FDSOURCE(p)	(p && (p)->magno == MAG_GFDSOURCE)
#define	IS_CHSOURCE(p)	(p && (p)->magno == MAG_GCHSOURCE)
#define	IS_WCSOURCE(p)	(p && (p)->magno == MAG_GWCSOURCE)
#define	IS_SIGSOURCE(p)	(p && (p)->magno == MAG_GSIGSOURCE)
#define	IS_TRIGSOURCE(p) (p && (p)->magno == MAG_GTRIGSOURCE)
#define	IS_TIMEOUTSRC(p) (p && (p)->magno == MAG_GTIMEOUTSRC)

#define IS_ONEOFOURS(p)	(IS_CHSOURCE(p)|IS_FDSOURCE(p)|IS_WCSOURCE(p)||	\
			IS_SIGSOURCE(p)|IS_TRIGSOURCE(p)||IS_TIMEOUTSRC(p))


#define		DEFAULT_MAXDISPATCH	0
#define		DEFAULT_MAXDELAY	0
#define		OTHER_MAXDELAY		100

#define	COMMON_STRUCTSTART						\
GSource		source;		/* Common glib struct -  must be 1st */	\
unsigned	magno;		/* Magic number */			\
long		maxdispatchms;	/* Time limit for dispatch function */	\
long		maxdispatchdelayms; /* Max delay before processing */	\
char		detecttime[sizeof(longclock_t)];			\
				/* Time last input detected */		\
void*		udata;		/* User-defined data */			\
guint		gsourceid;	/* Source id of this source */		\
const char *	description;	/* Description of this source */	\
GDestroyNotify	dnotify

struct GFDSource_s {
	COMMON_STRUCTSTART;
	gboolean	(*dispatch)(int fd, gpointer user_data);
	GPollFD		gpfd;
};


typedef gboolean 	(*GCHdispatch)(IPC_Channel* ch, gpointer user_data);

struct GCHSource_s {
	COMMON_STRUCTSTART;
	IPC_Channel*	ch;
	gboolean	fd_fdx;
	GPollFD		infd;
	GPollFD		outfd;
	gboolean	dontread;	/* TRUE when we don't want to read
					 * more input for a while - we're
					 * flow controlling the writer off
					 */
	gboolean 	(*dispatch)(IPC_Channel* ch, gpointer user_data);
};

struct GWCSource_s {
	COMMON_STRUCTSTART;
	GPollFD			gpfd;
	IPC_WaitConnection*	wch;
	IPC_Auth*		auth_info;
	gboolean (*dispatch)(IPC_Channel* accept_ch, gpointer udata);
};

struct GSIGSource_s {
	COMMON_STRUCTSTART;
	clock_t		sh_detecttime;
	int		signal;
	gboolean	signal_triggered;
	gboolean 	(*dispatch)(int signal, gpointer user_data);
};

struct GTRIGSource_s {
	COMMON_STRUCTSTART;
	gboolean	manual_trigger;
	gboolean 	(*dispatch)(gpointer user_data);
};

/************************************************************
 *		Functions for IPC_Channels
 ***********************************************************/
gboolean G_CH_prepare_int(GSource* source, gint* timeout);
gboolean G_CH_check_int(GSource* source);
gboolean G_CH_dispatch_int(GSource* source, GSourceFunc callback,
			      gpointer user_data);
void G_CH_destroy_int(GSource* source);
GCHSource*
G_main_IPC_Channel_constructor(GSource* source, IPC_Channel* ch
,	gpointer userdata, GDestroyNotify notify);
