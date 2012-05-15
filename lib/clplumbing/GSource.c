/*
 * Copyright (c) 2002 Alan Robertson <alanr@unix.sh>
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

#include <lha_internal.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/GSource_internal.h>
#include <clplumbing/proctrack.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/timers.h>

#ifdef events
#  undef events
#endif
#ifdef revents
#  undef revents
#endif

#define		DEFAULT_MAXDISPATCH	0
#define		DEFAULT_MAXDELAY	0
#define		OTHER_MAXDELAY		100

/*
 * On architectures with alignment constraints, our casting between
 * "(GSource*)" and "(GFDSource_s*)" etc. causes trouble, because of
 * the massive alignment requirements of "longclock_t".
 *
 * Use the following to store and fetch.
 */
static
void
lc_store(char *destptr, longclock_t value) {
	longclock_t _ltt;
	_ltt = value;
	memcpy((destptr), &_ltt, sizeof(longclock_t));
}

static
longclock_t
lc_fetch(char *ptr) {
	longclock_t _ltt;
	memcpy(&_ltt, (ptr), sizeof(longclock_t));
	return _ltt;
}

#define	ERR_EVENTS	(G_IO_ERR|G_IO_NVAL)
#define	INPUT_EVENTS	(G_IO_IN|G_IO_PRI|G_IO_HUP)
#define	OUTPUT_EVENTS	(G_IO_OUT)
#define	DEF_EVENTS	(INPUT_EVENTS|ERR_EVENTS)

#define	WARN_DELAY(ms, mx, input)	cl_log(LOG_WARNING		\
	,	"%s: Dispatch function for %s was delayed"		\
	" %lu ms (> %lu ms) before being called (GSource: 0x%lx)"	\
	,	__FUNCTION__,	(input)->description, ms, mx		\
	,	POINTER_TO_ULONG(input))

#define EXPLAINDELAY(started, detected) cl_log(LOG_INFO			\
	,	"%s: started at %llu should have started at %llu"	\
	,	__FUNCTION__, (unsigned long long)started 		\
	,	(unsigned long long)detected)
	

#define	WARN_TOOLONG(ms, mx, input)	cl_log(LOG_WARNING		\
	,	"%s: Dispatch function for %s took too long to execute"	\
	": %lu ms (> %lu ms) (GSource: 0x%lx)"				\
	,	__FUNCTION__,	(input)->description, ms, mx		\
	,	POINTER_TO_ULONG(input))

#define CHECK_DISPATCH_DELAY(i)	{ 					\
	unsigned long	ms;						\
	longclock_t dettime;						\
	dispstart = time_longclock();					\
	dettime = lc_fetch((i)->detecttime);				\
	ms = longclockto_ms(sub_longclock(dispstart,dettime));		\
	if ((i)->maxdispatchdelayms > 0					\
	&&	ms > (i)->maxdispatchdelayms) {				\
		WARN_DELAY(ms, (i)->maxdispatchdelayms, (i));		\
		EXPLAINDELAY(dispstart, dettime);			\
	}								\
}

#define CHECK_DISPATCH_TIME(i)	{ 					\
	unsigned long	ms;						\
	longclock_t	dispend = time_longclock();			\
	ms = longclockto_ms(sub_longclock(dispend, dispstart));		\
	if ((i)->maxdispatchms > 0 && ms > (i)->maxdispatchms) {	\
		WARN_TOOLONG(ms, (i)->maxdispatchms, (i));		\
	}								\
	lc_store(((i)->detecttime), zero_longclock);		\
}

#define	WARN_TOOMUCH(ms, mx, input)	cl_log(LOG_WARNING		\
	,	"%s: working on %s took %ld ms (> %ld ms)"		\
	,	__FUNCTION__,	(input)->description, ms, mx);

#define	SAVESTART	{funstart = time_longclock();}

#define	CHECKEND(input)	{						\
	longclock_t	funend = time_longclock();			\
	long		ms;						\
	ms = longclockto_ms(sub_longclock(funend, funstart));		\
	if (ms > OTHER_MAXDELAY){					\
		WARN_TOOMUCH(ms, ((long) OTHER_MAXDELAY), input);	\
	}								\
}									\


#ifndef _NSIG
# define _NSIG 2*NSIG
#endif

static gboolean G_fd_prepare(GSource* source,
			     gint* timeout);
static gboolean G_fd_check(GSource* source);
static gboolean G_fd_dispatch(GSource* source,
			      GSourceFunc callback,
			      gpointer user_data);
static void G_fd_destroy(GSource* source);

static GSourceFuncs G_fd_SourceFuncs = {
	G_fd_prepare,
	G_fd_check,
	G_fd_dispatch,
	G_fd_destroy,
};

GSource*
G_main_add_input(int priority, 
		 gboolean can_recurse,
		 GSourceFuncs* funcs)
{
	GSource * input_source = g_source_new(funcs, sizeof(GSource));
	if (input_source == NULL){
		cl_log(LOG_ERR, "create glib source for input failed!");		
	}else {
		g_source_set_priority(input_source, priority);
		g_source_set_can_recurse(input_source, can_recurse);
		if(g_source_attach(input_source, NULL) == 0){
			cl_log(LOG_ERR, "attaching input_source to main context"
			       " failed!! ");
		}
	}
	
	return input_source;
}


/*
 *	Add the given file descriptor to the gmainloop world.
 */


GFDSource*
G_main_add_fd(int priority, int fd, gboolean can_recurse
,	gboolean (*dispatch)(int fd, gpointer user_data)
,	gpointer userdata
,	GDestroyNotify notify)
{

	GSource* source = g_source_new(&G_fd_SourceFuncs, 
				       sizeof(GFDSource));
	GFDSource* ret = (GFDSource*)source;
	
	ret->magno = MAG_GFDSOURCE;
	ret->maxdispatchdelayms = DEFAULT_MAXDELAY;
	ret->maxdispatchms = DEFAULT_MAXDISPATCH;
	ret->udata = userdata;
	ret->dispatch = dispatch;
	ret->gpfd.fd = fd;
	ret->gpfd.events = DEF_EVENTS;
	ret->gpfd.revents = 0;
	ret->dnotify = notify;
	lc_store((ret->detecttime), zero_longclock);
	
	g_source_add_poll(source, &ret->gpfd);
	
	
	g_source_set_priority(source, priority);
	
	g_source_set_can_recurse(source, can_recurse);	
	
	ret->gsourceid = g_source_attach(source, NULL);
	ret->description = "file descriptor";
	
	if (ret->gsourceid == 0) {
		g_source_remove_poll(source, &ret->gpfd);
		memset(ret, 0, sizeof(GFDSource));
		g_source_unref(source);
		source = NULL;
		ret = NULL;
	}
	return ret;
}

gboolean
G_main_del_fd(GFDSource* fdp)
{
	GSource * source = (GSource*) fdp;


	if (fdp->gsourceid <= 0) {
		return FALSE;
	}
	
	g_source_remove_poll(source, &fdp->gpfd);
	g_source_remove(fdp->gsourceid);
	fdp->gsourceid = 0;
	g_source_unref(source);
	
	return TRUE;

}

void
g_main_output_is_blocked(GFDSource* fdp)
{
	fdp->gpfd.events |= OUTPUT_EVENTS;
}


/*
 *	For pure file descriptor events, return FALSE because we
 *	have to poll to get events.
 *
 *	Note that we don't modify 'timeout' either.
 */
static gboolean
G_fd_prepare(GSource* source,
	     gint* timeout)
{
	GFDSource*	fdp =  (GFDSource*)source;
	g_assert(IS_FDSOURCE(fdp));
	return FALSE;
}

/*
 *	Did we notice any I/O events?
 */

static gboolean
G_fd_check(GSource* source)
     
{
	GFDSource*	fdp =  (GFDSource*)source;
	g_assert(IS_FDSOURCE(fdp));
	if (fdp->gpfd.revents) {
		lc_store((fdp->detecttime), time_longclock());
		return TRUE;
	}
	return FALSE;
}

/*
 *	Some kind of event occurred - notify the user.
 */
static gboolean
G_fd_dispatch(GSource* source,
	      GSourceFunc callback,
	      gpointer user_data)
{

	GFDSource*	fdp =  (GFDSource*)source;
	longclock_t	dispstart;
	g_assert(IS_FDSOURCE(fdp));
	CHECK_DISPATCH_DELAY(fdp);
	

	/*
	 * Is output now unblocked? 
	 *
	 * If so, turn off OUTPUT_EVENTS to avoid going into
	 * a tight poll(2) loop.
	 */
	if (fdp->gpfd.revents & OUTPUT_EVENTS) {
		fdp->gpfd.events &= ~OUTPUT_EVENTS;
	}
	
	if(fdp->dispatch) {
		if(!(fdp->dispatch(fdp->gpfd.fd, fdp->udata))){
			g_source_remove_poll(source,&fdp->gpfd);
			g_source_unref(source);
			CHECK_DISPATCH_TIME(fdp);
			return FALSE;
		}
		CHECK_DISPATCH_TIME(fdp);
	}
	
	return TRUE;
}

/*
 *	Free up our data, and notify the user process...
 */
static void
G_fd_destroy(GSource* source)
{
	GFDSource*	fdp =  (GFDSource*)source;	
	g_assert(IS_FDSOURCE(fdp));
	fdp->gsourceid = 0;
	if (fdp->dnotify) {
		fdp->dnotify(fdp->udata);
	}
}


/************************************************************
 *		Functions for IPC_Channels
 ***********************************************************/
gboolean G_CH_prepare_int(GSource* source,
			     gint* timeout);
gboolean G_CH_check_int(GSource* source);

gboolean G_CH_dispatch_int(GSource* source,
			      GSourceFunc callback,
			      gpointer user_data);
void G_CH_destroy_int(GSource* source);


static GSourceFuncs G_CH_SourceFuncs = {
	G_CH_prepare_int,
	G_CH_check_int,
	G_CH_dispatch_int,
	G_CH_destroy_int,
};




void
set_IPC_Channel_dnotify(GCHSource* chp,
			GDestroyNotify notify){
	chp->dnotify = notify;	
}

/*
 *	Add an IPC_channel to the gmainloop world...
 */
GCHSource*
G_main_IPC_Channel_constructor(GSource* source, IPC_Channel* ch
	       ,	gpointer userdata
	       ,	GDestroyNotify notify)
{
	int		rfd, wfd;
	GCHSource* chp;

	if( !source ) {
		cl_log(LOG_WARNING, "%s:%d: got null source", __FUNCTION__,__LINE__);
		return NULL;
	}
	if( !ch ) {
		cl_log(LOG_WARNING, "%s:%d: got null channel", __FUNCTION__,__LINE__);
		return NULL;
	}
	chp = (GCHSource*)source;
	
	chp->magno = MAG_GCHSOURCE;
	chp->maxdispatchdelayms = DEFAULT_MAXDELAY;
	chp->maxdispatchms = DEFAULT_MAXDISPATCH;
	lc_store((chp->detecttime), zero_longclock);
	ch->refcount++;
	chp->ch = ch;
	chp->udata=userdata;
	chp->dnotify = notify;
	chp->dontread = FALSE;

	rfd = ch->ops->get_recv_select_fd(ch);
	wfd = ch->ops->get_send_select_fd(ch);
	
	chp->fd_fdx = (rfd == wfd);
	
	if (debug_level > 1) {
		cl_log(LOG_DEBUG, "%s(sock=%d,%d)",__FUNCTION__, rfd,wfd);
	}
	chp->infd.fd      = rfd;
	chp->infd.events  = DEF_EVENTS;
	g_source_add_poll(source, &chp->infd);
	if (!chp->fd_fdx) {
		chp->outfd.fd      = wfd;
		chp->outfd.events  = DEF_EVENTS;
		g_source_add_poll(source, &chp->outfd);
	}
	chp->dispatch = NULL;
	chp->description = "IPC channel(base)";
	chp->gsourceid = 0;
	return chp;
}

GCHSource*
G_main_add_IPC_Channel(int priority, IPC_Channel* ch
		       ,	gboolean can_recurse
		       ,	gboolean (*dispatch)(IPC_Channel* source_data,
						     gpointer        user_data)
		       ,	gpointer userdata
		       ,	GDestroyNotify notify)
{
	GCHSource *chp;
	GSource *source;

	if( !ch ) {
		cl_log(LOG_WARNING, "%s:%d: got null channel", __FUNCTION__,__LINE__);
		return NULL;
	}
	source = g_source_new(&G_CH_SourceFuncs, 
					sizeof(GCHSource));
	G_main_IPC_Channel_constructor(source,ch,userdata,notify);
	
	chp = (GCHSource*)source;
	chp->dispatch = dispatch;
	
	g_source_set_priority(source, priority);
	g_source_set_can_recurse(source, can_recurse);
	
	chp->gsourceid = g_source_attach(source, NULL);
	chp->description = "IPC channel";
	

	if (chp->gsourceid == 0) {
		g_source_remove_poll(source, &chp->infd);
		if (!chp->fd_fdx) {
			g_source_remove_poll(source, &chp->outfd);
		}
		g_source_unref(source);
		source = NULL;
		chp = NULL;
	}
	return chp;
}


void	/* Suspend reading from far end writer (flow control) */
G_main_IPC_Channel_pause(GCHSource* chp)
{
	if (chp == NULL){
		cl_log(LOG_ERR, "%s: invalid input", __FUNCTION__);
		return;
	}
	
	chp->dontread = TRUE;
	return;
}


void 	/* Resume reading from far end writer (un-flow-control) */
G_main_IPC_Channel_resume(GCHSource* chp)
{
	if (chp == NULL){
		cl_log(LOG_ERR, "%s: invalid input", __FUNCTION__);
		return;
	}
	
	chp->dontread = FALSE;
	return;	

}

/*
 *	Delete an IPC_channel from the gmainloop world...
 */
gboolean 
G_main_del_IPC_Channel(GCHSource* chp)
{
	GSource* source = (GSource*) chp;

	if (chp == NULL || chp->gsourceid <= 0) {
		return FALSE;
	}

	if (debug_level > 1) {
		cl_log(LOG_DEBUG, "%s(sock=%d)",__FUNCTION__, chp->infd.fd);
	}
	g_source_remove(chp->gsourceid);
	chp->gsourceid = 0;
	/* chp should (may) now be undefined */
	g_source_unref(source);
	
	return TRUE;
}

/*
 *	For  IPC_CHANNEL events, enable output checking when needed
 *	and note when unread input is already queued.
 *
 *	Note that we don't modify 'timeout' either.
 */
gboolean
G_CH_prepare_int(GSource* source,
	     gint* timeout)
{
	GCHSource* chp = (GCHSource*)source;
	longclock_t	funstart;
	gboolean	ret;
	
	g_assert(IS_CHSOURCE(chp));
	SAVESTART;
	
	
	if (chp->ch->ops->is_sending_blocked(chp->ch)) {
		if (chp->fd_fdx) {
			chp->infd.events |= OUTPUT_EVENTS;
		}else{
			chp->outfd.events |= OUTPUT_EVENTS;
		}
	}

	if (chp->ch->recv_queue->current_qlen < chp->ch->recv_queue->max_qlen) {
		chp->infd.events |= INPUT_EVENTS;
	}else{
		/*
		 * This also disables EOF events - until we 
		 * read some of the packets we've already gotten
		 * This prevents a tight loop in poll(2).
		 */
		chp->infd.events &= ~INPUT_EVENTS;
	}

	if (chp->dontread){
		return FALSE;
	}
	ret = chp->ch->ops->is_message_pending(chp->ch);
	if (ret) {
		lc_store((chp->detecttime), time_longclock());
	}
	CHECKEND(chp);
	return ret;
}

/*
 *	Did we notice any I/O events?
 */

gboolean
G_CH_check_int(GSource* source)
{

	GCHSource* chp = (GCHSource*)source;
	gboolean	ret;
	longclock_t	funstart;

	g_assert(IS_CHSOURCE(chp));
	SAVESTART;
	

	if (chp->dontread){
		/* Make sure output gets unblocked */
		chp->ch->ops->resume_io(chp->ch);
		return FALSE;
	}
	
	ret = (chp->infd.revents != 0
		||	(!chp->fd_fdx && chp->outfd.revents != 0)
		||	chp->ch->ops->is_message_pending(chp->ch));
	if (ret) {
		lc_store((chp->detecttime), time_longclock());
	}
	CHECKEND(chp);
	return ret;
}

/*
 *	Some kind of event occurred - notify the user.
 */
gboolean
G_CH_dispatch_int(GSource * source,
	      GSourceFunc callback,
	      gpointer user_data)
{
	GCHSource* chp = (GCHSource*)source;
	longclock_t	dispstart;
	longclock_t	resume_start = zero_longclock;

	g_assert(IS_CHSOURCE(chp));
	CHECK_DISPATCH_DELAY(chp);


	if (chp->dontread){
		return TRUE;
	}

	/* Is output now unblocked? 
	 *
	 * If so, turn off OUTPUT_EVENTS to avoid going into
	 * a tight poll(2) loop.
	 */
	if (chp->fd_fdx) {
		if (chp->infd.revents & OUTPUT_EVENTS) {
			chp->infd.events &= ~OUTPUT_EVENTS;
		}
	}else if (chp->outfd.revents & OUTPUT_EVENTS) {
		chp->outfd.events &= ~OUTPUT_EVENTS;
	}
		
	if (ANYDEBUG) {
		resume_start = time_longclock();
	}

	chp->ch->ops->resume_io(chp->ch);

	if (ANYDEBUG) {
		longclock_t resume_end = time_longclock();
		unsigned long	ms;
		ms = longclockto_ms(sub_longclock(resume_end
		,	resume_start));
		if (ms > 10) {
			cl_log(LOG_WARNING
			,	"%s: resume_io() for %s took %lu ms"
			,	__FUNCTION__
			,	chp->description, ms);
		}
	}


	if(chp->dispatch && chp->ch->ops->is_message_pending(chp->ch)) {
		if(!(chp->dispatch(chp->ch, chp->udata))){
			g_source_remove_poll(source, &chp->infd);
			if (!chp->fd_fdx) {
				g_source_remove_poll(source, &chp->outfd);
			}
			CHECK_DISPATCH_TIME(chp);
			g_source_unref(source);
			return FALSE;
		}
	}
	CHECK_DISPATCH_TIME(chp);

	if (chp->ch->ch_status == IPC_DISCONNECT){
		return FALSE;
	}
	return TRUE;
}

/*
 *	Free up our data, and notify the user process...
 */
void
G_CH_destroy_int(GSource* source)
{
	GCHSource* chp = (GCHSource*)source;
	
	g_assert(IS_CHSOURCE(chp));
	if (debug_level > 1) {
		cl_log(LOG_DEBUG, "%s(chp=0x%lx, sock=%d) {", __FUNCTION__
		,	(unsigned long)chp, chp->infd.fd);
	}
	
	if (chp->dnotify) {
		if (debug_level > 1) {
			cl_log(LOG_DEBUG
			,	"%s: Calling dnotify(sock=%d, arg=0x%lx) function"
			,	__FUNCTION__, chp->infd.fd, (unsigned long)chp->udata);
		}
		chp->dnotify(chp->udata);
	}else{
		if (debug_level > 1) {
			cl_log(LOG_DEBUG
			,	"%s: NOT calling dnotify(sock=%d) function"
			,	__FUNCTION__, chp->infd.fd);
		}
	}
	if (chp->ch) {
		if (debug_level > 1) {
			cl_log(LOG_DEBUG
			,	"%s: calling IPC destroy (chp->ch=0x%lx, sock=%d)"
			,	__FUNCTION__ ,	(unsigned long)chp->ch, chp->infd.fd);
		}
		chp->ch->ops->destroy(chp->ch);
		chp->ch = NULL;
	}
	/*chp->gsourceid = 0; ?*/
	if (debug_level > 1) {
		cl_log(LOG_DEBUG, "}/*%s(sock=%d)*/", __FUNCTION__, chp->infd.fd);
	}
}


/************************************************************
 *		Functions for IPC_WaitConnections
 ***********************************************************/
static gboolean G_WC_prepare(GSource * source,
			     gint* timeout);
static gboolean G_WC_check(GSource* source);
static gboolean G_WC_dispatch(GSource* source, 
			      GSourceFunc callback,
			      gpointer user_data);
static void G_WC_destroy(GSource* source);

static GSourceFuncs G_WC_SourceFuncs = {
	G_WC_prepare,
	G_WC_check,
	G_WC_dispatch,
	G_WC_destroy,
};


/*
 *	Add an IPC_WaitConnection to the gmainloop world...
 */
GWCSource*
G_main_add_IPC_WaitConnection(int priority
,	IPC_WaitConnection* wch
,	IPC_Auth* auth_info
,	gboolean can_recurse
,	gboolean (*dispatch)(IPC_Channel* wch
,		gpointer        user_data)
,	gpointer userdata
,	GDestroyNotify notify)
{

	GWCSource* wcp;
	GSource * source = g_source_new(&G_WC_SourceFuncs, 
					sizeof(GWCSource));
	
	wcp = (GWCSource*)source;
	
	wcp->magno = MAG_GWCSOURCE;
	wcp->maxdispatchdelayms = DEFAULT_MAXDELAY;
	wcp->maxdispatchms = DEFAULT_MAXDISPATCH;
	lc_store((wcp->detecttime), zero_longclock);
	wcp->udata = userdata;
	wcp->gpfd.fd = wch->ops->get_select_fd(wch);
	wcp->gpfd.events = DEF_EVENTS;
	wcp->gpfd.revents = 0;
	wcp->wch = wch;
	wcp->dnotify = notify;
	wcp->auth_info = auth_info;
	wcp->dispatch = dispatch;
	
	g_source_add_poll(source, &wcp->gpfd);
	
	g_source_set_priority(source, priority);
	
	g_source_set_can_recurse(source, can_recurse);
	
	wcp->gsourceid = g_source_attach(source, NULL);
	wcp->description = "IPC wait for connection";
	
	if (wcp->gsourceid == 0) {
		g_source_remove_poll(source, &wcp->gpfd);
		g_source_unref(source);
		source = NULL;
		wcp = NULL;
	}
	return wcp;
}


/* Delete the given IPC_WaitConnection from the gmainloop world */
gboolean
G_main_del_IPC_WaitConnection(GWCSource* wcp)
{

	GSource* source =  (GSource*) wcp;

	
	if (wcp->gsourceid <= 0) {
		return FALSE;
	}
	
	g_source_remove(wcp->gsourceid);
	wcp->gsourceid = 0;
	g_source_unref(source);
	
	return TRUE;
}



/*
 *	For IPC_WaitConnection events, return FALSE because we
 *	have to poll to get events.
 *
 *	We don't modify 'timeout' either.
 */
static gboolean
G_WC_prepare(GSource* source,
	     gint* timeout)
{
	GWCSource* wcp = (GWCSource*)source;
	g_assert(IS_WCSOURCE(wcp));
	return FALSE;
}

/*
 *	Did we notice any I/O (connection pending) events?
 */

static gboolean
G_WC_check(GSource * source)
{
	GWCSource* wcp = (GWCSource*)source;
	g_assert(IS_WCSOURCE(wcp));

	if (wcp->gpfd.revents != 0) {
		lc_store((wcp->detecttime), time_longclock());
		return TRUE;
	}
	return FALSE;
}

/*
 *	Someone is trying to connect.
 *	Try to accept the connection and notify the user.
 */
static gboolean
G_WC_dispatch(GSource* source,
	      GSourceFunc callback,
	      gpointer user_data)
{
	GWCSource* wcp = (GWCSource*)source;
	IPC_Channel*	ch;
	gboolean	rc = TRUE;
	int		count = 0;
	longclock_t	dispstart;
	
	g_assert(IS_WCSOURCE(wcp));
	CHECK_DISPATCH_DELAY(wcp);
	
        while(1) {
		ch = wcp->wch->ops->accept_connection(wcp->wch, wcp->auth_info);
		if (ch == NULL) {
			if (errno == EBADF) {
				cl_perror("%s: Stopping accepting connections(socket=%d)!!"
				,	__FUNCTION__, wcp->gpfd.fd);
				rc = FALSE;
			}
			break;
	  	}
		++count;
		
		if(!wcp->dispatch) {
			continue;
		}

		rc = wcp->dispatch(ch, wcp->udata);
		if(!rc) {
			g_source_remove_poll(source, &wcp->gpfd);
			g_source_unref(source);
			break;
		}
	}
	CHECK_DISPATCH_TIME(wcp);
	return rc;
}

/*
 *	Free up our data, and notify the user process...
 */
static void
G_WC_destroy(GSource* source)
{
	
	GWCSource* wcp = (GWCSource*)source;
	wcp->gsourceid = 0;
	g_assert(IS_WCSOURCE(wcp));
	wcp->wch->ops->destroy(wcp->wch);
	if (wcp->dnotify) {
		wcp->dnotify(wcp->udata);
	}
}


/************************************************************
 *		Functions for Signals
 ***********************************************************/
static gboolean G_SIG_prepare(GSource* source,
			     gint* timeout);
static gboolean G_SIG_check(GSource* source);

static gboolean G_SIG_dispatch(GSource* source,
			      GSourceFunc callback,
			      gpointer user_data);
static void G_SIG_destroy(GSource* source);

static void G_main_signal_handler(int nsig);

static GSourceFuncs G_SIG_SourceFuncs = {
	G_SIG_prepare,
	G_SIG_check,
	G_SIG_dispatch,
	G_SIG_destroy,
};

static GSIGSource *G_main_signal_list[_NSIG];

void
set_SignalHandler_dnotify(GSIGSource* sig_src, GDestroyNotify notify)
{
	sig_src->dnotify = notify;	
}

/*
 *	Add an Signal to the gmainloop world...
 */
GSIGSource*
G_main_add_SignalHandler(int priority, int signal,
			 gboolean (*dispatch)(int nsig, gpointer user_data),
			 gpointer userdata, GDestroyNotify notify)
{
	GSIGSource* sig_src;
	GSource * source = g_source_new(&G_SIG_SourceFuncs, sizeof(GSIGSource));
	gboolean failed = FALSE;
	
	sig_src = (GSIGSource*)source;
	
	sig_src->magno		= MAG_GSIGSOURCE;
	sig_src->maxdispatchdelayms = DEFAULT_MAXDELAY;
	sig_src->maxdispatchms	= DEFAULT_MAXDISPATCH;
	sig_src->signal		= signal;
	sig_src->dispatch	= dispatch;
	sig_src->udata		= userdata;
	sig_src->dnotify	= notify;

	sig_src->signal_triggered = FALSE;

	g_source_set_priority(source, priority);
	g_source_set_can_recurse(source, FALSE);

	if(G_main_signal_list[signal] != NULL) {
		cl_log(LOG_ERR
		,	"%s: Handler already present for signal %d"
		,	__FUNCTION__, signal);
		failed = TRUE;
	}
	if(!failed) {
		sig_src->gsourceid = g_source_attach(source, NULL);
		sig_src->description = "signal";
		if (sig_src->gsourceid < 1) {
			cl_log(LOG_ERR
			,	"%s: Could not attach source for signal %d (%d)"
			,	__FUNCTION__
			,	signal, sig_src->gsourceid);
			failed = TRUE;
		}
	}
	
	if(failed) {
		cl_log(LOG_ERR
		,	"%s: Signal handler for signal %d NOT added"
		,	__FUNCTION__, signal);
		g_source_remove(sig_src->gsourceid);
		g_source_unref(source);
		source = NULL;
		sig_src = NULL;
	} else {
		if (debug_level > 1) {
			cl_log(LOG_DEBUG
			, "%s: Added signal handler for signal %d"
			,	__FUNCTION__, signal);
		}
		G_main_signal_list[signal] = sig_src;
		CL_SIGNAL(signal, G_main_signal_handler);
		/*
		 * If we don't set this on, then the mainloop poll(2) call
		 * will never be interrupted by this signal - which sort of
		 * defeats the whole purpose of a signal handler in a
		 * mainloop program
		 */
		cl_signal_set_interrupt(signal, TRUE);
	}
	return sig_src;
}


/*
 *	Delete a Signal from the gmainloop world...
 */
gboolean 
G_main_del_SignalHandler(GSIGSource* sig_src)
{
	GSource* source = (GSource*) sig_src;

	if (sig_src->gsourceid <= 0) {
		return FALSE;
	}
	if(_NSIG <= sig_src->signal) {
		g_assert(_NSIG > sig_src->signal);
		return FALSE;
	}
	
	CL_SIGNAL(sig_src->signal, NULL);

	sig_src->signal_triggered = FALSE;
	g_source_remove(sig_src->gsourceid);
	G_main_signal_list[sig_src->signal] = NULL;
	sig_src->gsourceid = 0;
	g_source_unref(source);
	
	return TRUE;
}

static gboolean
G_SIG_prepare(GSource* source, gint* timeoutms)
{
	GSIGSource* sig_src = (GSIGSource*)source;
	
	g_assert(IS_SIGSOURCE(sig_src));
	
	/* Don't let a timing window keep us in poll() forever
	 *
	 * The timing window in question looks like this:
	 * No signal has occurred up to the point of prepare being called.
	 * Signal comes in _after_ prepare was called, but _before_ poll.
	 * signal_detected gets set, but no one checks it before going into poll
	 * We wait in poll forever...  It's not a pretty sight :-(.
	 */
	*timeoutms = 1000;	/* Sigh... */

	if (sig_src->signal_triggered) {
		clock_t			now;
		clock_t			diff;

		/* detecttime is reset in the dispatch function */
		if (cmp_longclock(lc_fetch(sig_src->detecttime), zero_longclock) != 0) {
			cl_log(LOG_ERR, "%s: detecttime already set?", __FUNCTION__);
			return TRUE;
		}
		/* Otherwise, this is when it was first detected */
		now = cl_times();
		diff = now - sig_src->sh_detecttime;	/* How long since signal occurred? */
		lc_store(
			sig_src->detecttime,
			sub_longclock(time_longclock(), (longclock_t)diff)
		);
		return TRUE;
	}
	return FALSE;
}

/*
 *	Did we notice any I/O events?
 */

static gboolean
G_SIG_check(GSource* source)
{

	GSIGSource* sig_src = (GSIGSource*)source;

	g_assert(IS_SIGSOURCE(sig_src));
	
	if (sig_src->signal_triggered) {
		clock_t			now;
		clock_t			diff;
		if (cmp_longclock(lc_fetch(sig_src->detecttime), zero_longclock) != 0){
			return TRUE;
		}
		/* Otherwise, this is when it was first detected */
		now = cl_times();
		diff = now - sig_src->sh_detecttime;
		lc_store(
			sig_src->detecttime,
			sub_longclock(time_longclock(), (longclock_t)diff)
		);
		return TRUE;
	}
	return FALSE;
}

/*
 *	Some kind of event occurred - notify the user.
 */
static gboolean
G_SIG_dispatch(GSource * source,
	      GSourceFunc callback,
	      gpointer user_data)
{
	GSIGSource* sig_src = (GSIGSource*)source;
	longclock_t	dispstart;

	g_assert(IS_SIGSOURCE(sig_src));
	CHECK_DISPATCH_DELAY(sig_src);

	sig_src->sh_detecttime = 0UL;
	sig_src->signal_triggered = FALSE;

	if(sig_src->dispatch) {
		if(!(sig_src->dispatch(sig_src->signal, sig_src->udata))){
			G_main_del_SignalHandler(sig_src);
			CHECK_DISPATCH_TIME(sig_src);
			return FALSE;
		}
	}
	CHECK_DISPATCH_TIME(sig_src);
	
	return TRUE;
}

/*
 *	Free up our data, and notify the user process...
 */
static void
G_SIG_destroy(GSource* source)
{
	GSIGSource* sig_src = (GSIGSource*)source;
	
	g_assert(IS_SIGSOURCE(sig_src));
	sig_src->gsourceid = 0;

	if (sig_src->dnotify) {
		sig_src->dnotify(sig_src->udata);
	}	
}

/* Find and set the correct mainloop input */

static void
G_main_signal_handler(int nsig)
{
	GSIGSource* sig_src = NULL;

	if(G_main_signal_list == NULL) {
		g_assert(G_main_signal_list != NULL);
		return;
	}
	if(_NSIG <= nsig) {
		g_assert(_NSIG > nsig);
		return;
	}
	
	sig_src = G_main_signal_list[nsig];

	if(sig_src == NULL) {
		/* cl_log(LOG_CRIT, "No handler for signal -%d", nsig); */
		return;
	}
	
	g_assert(IS_SIGSOURCE(sig_src));
	/* Time from first occurance of signal */
	if (!sig_src->signal_triggered) {
		/* Avoid calling longclock_time() on a signal */
		sig_src->sh_detecttime=cl_times();
	}
	sig_src->signal_triggered = TRUE;
}

/*
 * Functions to handle child process
 */

#define	WAITALARM	5000L /* milliseconds */

static int	alarm_count = 0;
static void
G_main_alarm_helper(int nsig)
{
	++alarm_count;
}

static gboolean
child_death_dispatch(int sig, gpointer notused)
{
	int 			status;
	pid_t			pid;
	const int		waitflags = WNOHANG;
	struct sigaction	saveaction;
	int			childcount = 0;

	/*
	 * wait3(WNOHANG) isn't _supposed_ to hang
	 * Unfortunately, it seems to do just that on some OSes.
	 *
	 * The workaround is to set an alarm.  I don't think for this purpose
	 * that it matters if siginterrupt(SIGALRM) is set TRUE or FALSE since
	 * the tiniest little excuse seems to cause the wait3() to finish.
	 */
	
	memset(&saveaction, 0, sizeof(saveaction));
	cl_signal_set_simple_handler(SIGALRM, G_main_alarm_helper, &saveaction);

	alarm_count = 0;
	cl_signal_set_interrupt(SIGALRM, TRUE);
	setmsrepeattimer(WAITALARM); /* Might as well be persistent ;-) */
	while((pid=wait3(&status, waitflags, NULL)) > 0
	||	(pid < 0 && errno == EINTR)) {
		cancelmstimer();
		if (pid > 0) {
			++childcount;
			ReportProcHasDied(pid, status);
		}
		setmsrepeattimer(WAITALARM); /* Let's be persistent ;-) */
	}
	cancelmstimer();
	cl_signal_set_simple_handler(SIGALRM, saveaction.sa_handler, &saveaction);

	if (pid < 0 && errno != ECHILD) {
		cl_perror("%s: wait3() failed"
		,	__FUNCTION__);
	}
#if defined(DEBUG)
	if (childcount < 1) {
		/*
		 * This happens when we receive a SIGCHLD after we clear
		 * 'sig_src->signal_triggered' in G_SIG_dispatch() but
		 * before the last wait3() call returns no child above.
		 */
		cl_log(LOG_DEBUG, "NOTE: %s called without children to wait on"
		,	__FUNCTION__);
	}
#endif
	if (alarm_count) {
		cl_log(LOG_ERR
		,	"%s: wait3() call hung %d times. childcount = %d"
		,	__FUNCTION__, alarm_count, childcount);
		alarm_count = 0;
	}
	return TRUE;
}

void
set_sigchld_proctrack(int priority, unsigned long maxdisptime)
{
	GSIGSource* src = G_main_add_SignalHandler(priority, SIGCHLD
	,	child_death_dispatch, NULL, NULL);

	G_main_setmaxdispatchdelay((GSource*) src, 100);
	G_main_setmaxdispatchtime((GSource*) src, maxdisptime);
	G_main_setdescription((GSource*)src, "SIGCHLD");
	return;
}


/************************************************************
 *		Functions for Trigger inputs
 ***********************************************************/
static gboolean G_TRIG_prepare(GSource* source,
			     gint* timeout);
static gboolean G_TRIG_check(GSource* source);

static gboolean G_TRIG_dispatch(GSource* source,
			      GSourceFunc callback,
			      gpointer user_data);
static void G_TRIG_destroy(GSource* source);

static GSourceFuncs G_TRIG_SourceFuncs = {
	G_TRIG_prepare,
	G_TRIG_check,
	G_TRIG_dispatch,
	G_TRIG_destroy
};

void
set_TriggerHandler_dnotify(GTRIGSource* trig_src, GDestroyNotify notify)
{
	trig_src->dnotify = notify;	
}

/*
 *	Add an Trigger to the gmainloop world...
 */
GTRIGSource*
G_main_add_TriggerHandler(int priority,
			 gboolean (*dispatch)(gpointer user_data),
			 gpointer userdata, GDestroyNotify notify)
{
	GTRIGSource* trig_src = NULL;
	GSource * source = g_source_new(&G_TRIG_SourceFuncs, sizeof(GTRIGSource));
	gboolean failed = FALSE;
	
	trig_src = (GTRIGSource*)source;
	
	trig_src->magno		= MAG_GTRIGSOURCE;
	trig_src->maxdispatchdelayms = DEFAULT_MAXDELAY;
	trig_src->maxdispatchms	= DEFAULT_MAXDISPATCH;
	trig_src->dispatch	= dispatch;
	trig_src->udata		= userdata;
	trig_src->dnotify	= notify;
	lc_store((trig_src->detecttime), zero_longclock);

	trig_src->manual_trigger = FALSE;

	g_source_set_priority(source, priority);
	g_source_set_can_recurse(source, FALSE);

	if(!failed) {
		trig_src->gsourceid = g_source_attach(source, NULL);
		trig_src->description = "trigger";
		if (trig_src->gsourceid < 1) {
			cl_log(LOG_ERR, "G_main_add_TriggerHandler: Could not attach new source (%d)",
			       trig_src->gsourceid);
			failed = TRUE;
		}
	}
	
	if(failed) {
		cl_log(LOG_ERR, "G_main_add_TriggerHandler: Trigger handler NOT added");
		g_source_remove(trig_src->gsourceid);
		g_source_unref(source);
		source = NULL;
		trig_src = NULL;
	} else {
		if (debug_level > 1) {
			cl_log(LOG_DEBUG, "G_main_add_TriggerHandler: Added signal manual handler");
		}
	}
	
	return trig_src;
}

void 
G_main_set_trigger(GTRIGSource* source)
{
	GTRIGSource* trig_src = (GTRIGSource*)source;
	
	g_assert(IS_TRIGSOURCE(trig_src));
	
	trig_src->manual_trigger = TRUE;
	lc_store((trig_src->detecttime), time_longclock());
}


/*
 *	Delete a Trigger from the gmainloop world...
 */
gboolean 
G_main_del_TriggerHandler(GTRIGSource* trig_src)
{
	GSource* source = (GSource*) trig_src;

	if (trig_src->gsourceid <= 0) {
		return FALSE;
	}
	trig_src->gsourceid = 0;
	trig_src->manual_trigger = FALSE;
	g_source_remove(trig_src->gsourceid);
	g_source_unref(source);
	
	return TRUE;
}

static gboolean
G_TRIG_prepare(GSource* source, gint* timeout)
{
	GTRIGSource* trig_src = (GTRIGSource*)source;
	
	g_assert(IS_TRIGSOURCE(trig_src));
	

	if (trig_src->manual_trigger
	&&	cmp_longclock(lc_fetch(trig_src->detecttime), zero_longclock) == 0) {
		lc_store((trig_src->detecttime), time_longclock());
	}
	return trig_src->manual_trigger;
}

/*
 *	Did we notice any I/O events?
 */

static gboolean
G_TRIG_check(GSource* source)
{

	GTRIGSource* trig_src = (GTRIGSource*)source;

	g_assert(IS_TRIGSOURCE(trig_src));
	if (trig_src->manual_trigger
	&&	cmp_longclock(lc_fetch(trig_src->detecttime), zero_longclock) == 0) {
		lc_store((trig_src->detecttime), time_longclock());
	}
	return trig_src->manual_trigger;
}

/*
 *	Some kind of event occurred - notify the user.
 */
static gboolean
G_TRIG_dispatch(GSource * source,
	      GSourceFunc callback,
	      gpointer user_data)
{
	GTRIGSource* trig_src = (GTRIGSource*)source;
	longclock_t	dispstart;

	g_assert(IS_TRIGSOURCE(trig_src));
	CHECK_DISPATCH_DELAY(trig_src);

	trig_src->manual_trigger = FALSE;

	if(trig_src->dispatch) {
		if(!(trig_src->dispatch(trig_src->udata))){
			G_main_del_TriggerHandler(trig_src);
			CHECK_DISPATCH_TIME(trig_src);
			return FALSE;
		}
		CHECK_DISPATCH_TIME(trig_src);
	}
	lc_store((trig_src->detecttime), zero_longclock);
	
	return TRUE;
}

/*
 *	Free up our data, and notify the user process...
 */
static void
G_TRIG_destroy(GSource* source)
{
	GTRIGSource* trig_src = (GTRIGSource*)source;
	
	g_assert(IS_TRIGSOURCE(trig_src));
	trig_src->gsourceid = 0;

	if (trig_src->dnotify) {
		trig_src->dnotify(trig_src->udata);
	}	
}
/*
 * Glib mainloop timeout handling code.
 *
 * These functions work correctly even if someone resets the 
 * time-of-day clock.  The g_main_timeout_add() function does not have
 * this property, since it relies on gettimeofday().
 *
 * Our functions have the same semantics - except they always work ;-)
 *
 * This is because we use longclock_t for our time values.
 *
 */


static gboolean
Gmain_timeout_prepare(GSource* src,  gint* timeout);

static gboolean
Gmain_timeout_check(GSource* src);

static gboolean
Gmain_timeout_dispatch(GSource* src, GSourceFunc func, gpointer user_data);

static GSourceFuncs Gmain_timeout_funcs = {
	Gmain_timeout_prepare,
	Gmain_timeout_check,
	Gmain_timeout_dispatch,
};


struct GTimeoutAppend {
	COMMON_STRUCTSTART;
	longclock_t	nexttime;
	guint		interval;
};

#define        GTIMEOUT(GS)    ((struct GTimeoutAppend*)((void*)(GS)))

guint
Gmain_timeout_add(guint interval
,	GSourceFunc	function
,	gpointer	data)
{
	return Gmain_timeout_add_full(G_PRIORITY_DEFAULT
	,	interval, function, data, NULL);
}

guint
Gmain_timeout_add_full(gint priority
,	guint interval
,	GSourceFunc	function
,	gpointer	data
,	GDestroyNotify	notify)
{
	
	struct GTimeoutAppend* append;
	
	GSource* source = g_source_new( &Gmain_timeout_funcs, 
					sizeof(struct GTimeoutAppend));
	
	append = GTIMEOUT(source);
	append->magno = MAG_GTIMEOUTSRC;
	append->maxdispatchms = DEFAULT_MAXDISPATCH;
	append->maxdispatchdelayms = DEFAULT_MAXDELAY;
	append->description = "(timeout)";
	lc_store((append->detecttime), zero_longclock);
	append->udata = NULL;
	
	append->nexttime = add_longclock(time_longclock()
	,	msto_longclock(interval));
  	append->interval = interval; 
	
	g_source_set_priority(source, priority);
	
	g_source_set_can_recurse(source, FALSE);
	
	g_source_set_callback(source, function, data, notify); 

	append->gsourceid = g_source_attach(source, NULL);
	g_source_unref(source);
	return append->gsourceid;

}

void
Gmain_timeout_remove(guint tag)
{
	GSource* source = g_main_context_find_source_by_id(NULL,tag);
	struct GTimeoutAppend* append = GTIMEOUT(source);
	
	if (source == NULL){
		cl_log(LOG_ERR, "Attempt to remove timeout (%u)"
		" with NULL source",	tag);
	}else{
		g_assert(IS_TIMEOUTSRC(append));
		g_source_remove(tag);
	}
	
	return;
}

/* g_main_loop-style prepare function */
static gboolean
Gmain_timeout_prepare(GSource* src,  gint* timeout)
{
	
	struct GTimeoutAppend* append = GTIMEOUT(src);
	longclock_t	lnow = time_longclock();
	longclock_t	remain;
	
	g_assert(IS_TIMEOUTSRC(append));
	if (cmp_longclock(lnow, append->nexttime) >= 0) {
		*timeout = 0L;
		return TRUE;
	}
	/* This is safe - we will always have a positive result */
	remain = sub_longclock(append->nexttime, lnow);
	/* This is also safe - we started out in 'ms' */
	*timeout = longclockto_ms(remain);
	return ((*timeout) == 0);
}

/* g_main_loop-style check function */
static gboolean
Gmain_timeout_check    (GSource* src)
{
	struct GTimeoutAppend* append = GTIMEOUT(src);
	longclock_t	lnow = time_longclock();
	
	g_assert(IS_TIMEOUTSRC(append));
	if (cmp_longclock(lnow, append->nexttime) >= 0) {
		return TRUE;
	}
	return FALSE;
}

/* g_main_loop-style dispatch function */
static gboolean
Gmain_timeout_dispatch(GSource* src, GSourceFunc func, gpointer user_data)
{
	struct GTimeoutAppend* append = GTIMEOUT(src);
	longclock_t	dispstart;
	gboolean	ret;

	g_assert(IS_TIMEOUTSRC(append));
	lc_store(append->detecttime, append->nexttime);
	CHECK_DISPATCH_DELAY(append);
	

	/* Schedule our next dispatch */
	append->nexttime = add_longclock(time_longclock()
	,	msto_longclock(append->interval));

	/* Then call the user function */
	ret = func(user_data);

	CHECK_DISPATCH_TIME(append);
	return ret;
}
void
G_main_setmaxdispatchdelay(GSource* s, unsigned long delayms)
{
	GFDSource*	fdp =  (GFDSource*)s;
	if (!IS_ONEOFOURS(fdp)) {
		cl_log(LOG_ERR
		,	"Attempt to set max dispatch delay on wrong object");
		return;
	}
	fdp->maxdispatchdelayms = delayms;
}
void
G_main_setmaxdispatchtime(GSource* s, unsigned long dispatchms)
{
	GFDSource*	fdp =  (GFDSource*)s;
	if (!IS_ONEOFOURS(fdp)) {
		cl_log(LOG_ERR
		,	"Attempt to set max dispatch time on wrong object");
		return;
	}
	fdp->maxdispatchms = dispatchms;
}
void
G_main_setdescription(GSource* s, const char * description)
{
	GFDSource*	fdp =  (GFDSource*)s;
	if (!IS_ONEOFOURS(fdp)) {
		cl_log(LOG_ERR
		,	"Attempt to set max dispatch time on wrong object");
		return;
	}
	fdp->description = description;
}
void
G_main_setmaxdispatchdelay_id(guint id, unsigned long delayms)
{
	GSource* source = g_main_context_find_source_by_id(NULL,id);
	
	if (source) {
		G_main_setmaxdispatchdelay(source, delayms);
	}
}
void
G_main_setmaxdispatchtime_id(guint id, unsigned long dispatchms)
{
	GSource* source = g_main_context_find_source_by_id(NULL,id);
	
	if (source) {
		G_main_setmaxdispatchtime(source, dispatchms);
	}
}
void
G_main_setdescription_id(guint id, const char * description)
{
	GSource* source = g_main_context_find_source_by_id(NULL,id);
	
	if (source) {
		G_main_setdescription(source, description);
	}
}
void
G_main_setall_id(guint id, const char * description, unsigned long delay
,	unsigned long elapsed)
{
	G_main_setdescription_id(id, description);
	G_main_setmaxdispatchdelay_id(id, delay);
	G_main_setmaxdispatchtime_id(id, elapsed);
}

static void		TempProcessRegistered(ProcTrack* p);
static void		TempProcessDied(ProcTrack* p, int status, int signo
,			int exitcode, int waslogged);
static const char*	TempProcessName(ProcTrack* p);

/***********************************************************************
 * Track our temporary child processes...
 *
 * We run no more than one of each type at once.
 * If we need to run some and one is still running we run another one
 * when this one exits.
 *
 * Requests to run a child process don't add up.  So, 3 requests to run
 * a child while one is running only cause it to be run once more, not
 * three times.
 * 
 * The only guarantee is that a new child process will run after a request
 * was made.
 *
 * To create the possibility of running a particular type of child process
 * call G_main_add_tempproc_trigger().
 *
 * To cause it to be run, call G_main_set_trigger().
 *
 ***********************************************************************/

static ProcTrack_ops		TempProcessTrackOps = {
	TempProcessDied,
	TempProcessRegistered,
	TempProcessName
};

/*
 *	Information for tracking our generic temporary child processes.
 */
struct tempproc_track {
	const char *	procname;	/* name of the process*/
	GTRIGSource*	trigger;	/* Trigger for this event */
	int		(*fun)(gpointer userdata); /* Function to call
					 * in child process */
	void		(*prefork)(gpointer userdata);/* Call before fork */
	void		(*postfork)(gpointer userdata);/* Call after fork */
	void		(*complete)(gpointer userdata, int status, int signo, int exitcode);/* Call after complete */
	gpointer	userdata;	/* Info to pass 'fun' */
	gboolean	isrunning;	/* TRUE if child is running */
	gboolean	runagain;	/* TRUE if we need to run
						 * again after child process
						 * finishes.
						 */
};
static void
TempProcessRegistered(ProcTrack* p)
{
	return;	 /* Don't need to do much here... */
}

static void
TempProcessDied(ProcTrack* p, int status, int signo, int exitcode
,	int waslogged)
{
	struct tempproc_track *	pt = p->privatedata;
 
	if (pt->complete) {
		if (debug_level > 1) {
			cl_log(LOG_DEBUG
			,	"%s: Calling 'complete' for temp process %s"
			,	__FUNCTION__, pt->procname);
		}
		pt->complete(pt->userdata, status, signo, exitcode);
	}

	pt->isrunning=FALSE;
	if (pt->runagain) {
		pt->runagain=FALSE;

 		/*  Do it again, Sam! */
		G_main_set_trigger(pt->trigger);

		/* Note that we set the trigger for this, we don't
		 * fork or call the function now.
		 *
		 * This allows the mainloop scheduler to decide
		 * when the fork should happen according to the priority
		 * of this trigger event - NOT according to the priority
		 * of general SIGCHLD handling.
		 */
	}
	p->privatedata = NULL;	/* Don't free until trigger is destroyed */
	return;
}

static const char *
TempProcessName(ProcTrack* p)
{
	struct tempproc_track *	pt = p->privatedata;
	return pt->procname;
}
/*
 *	 Make sure only one copy is running at a time...
 */
static gboolean
TempProcessTrigger(gpointer ginfo)
{
	struct tempproc_track*	info = ginfo;
	int			pid;

 	/* Make sure only one copy is running at a time. */
	/* This avoids concurrency problems. */
	if (info->isrunning) {
		info->runagain = TRUE;
		return TRUE;
	}
	info->isrunning = TRUE;

	if (info->prefork) {
		if (debug_level > 1) {
			cl_log(LOG_DEBUG
			,	"%s: Calling prefork for temp process %s"
			,	__FUNCTION__, info->procname);
		}
		info->prefork(info->userdata);
	}
	if (ANYDEBUG) {
		cl_log(LOG_DEBUG, "Forking temp process %s", info->procname);
	}
	switch ((pid=fork())) {
		int		rc;
		case -1:	cl_perror("%s: Can't fork temporary child"
				" process [%s]!",	__FUNCTION__
				,	info->procname);
				info->isrunning = FALSE;
				break;

		case 0:		/* Child */
				if ((rc=info->fun(info->userdata)) == HA_OK) {
					exit(0);
				}
				cl_log(LOG_WARNING
				,	"%s: %s returns %d", __FUNCTION__
				,	info->procname, rc);
				exit(1);
				break;
		default:
				/* Fall out */;

	}
	if (pid > 0) {
		NewTrackedProc(pid, 0, (ANYDEBUG? PT_LOGVERBOSE : PT_LOGNORMAL)
		,	ginfo, &TempProcessTrackOps);
		if (info->postfork) {
			if (debug_level > 1) {
				cl_log(LOG_DEBUG
				,	"%s: Calling postfork for temp process %s"
				,	__FUNCTION__, info->procname);
			}
			info->postfork(info->userdata);
		}
	}
	return TRUE;
}

static void
tempproc_destroy_notify(gpointer userdata)
{
	if (userdata != NULL) {
		free(userdata);
		userdata = NULL;
	}
}

GTRIGSource*
G_main_add_tempproc_trigger(int priority
,	int		(*triggerfun) (gpointer p)
,	const char *	procname
,	gpointer	userdata
,	void		(*prefork)(gpointer p)
,	void		(*postfork)(gpointer p)
,	void		(*complete)(gpointer userdata, int status, int signo, int exitcode))
{

	struct tempproc_track* 	p;
	GTRIGSource*		ret;

	p = (struct tempproc_track *) malloc(sizeof(struct tempproc_track));
	if (p == NULL) {
		return NULL;
	}

	memset(p, 0, sizeof(*p));
	p->procname = procname;
	p->fun = triggerfun;
	p->userdata = userdata;
	p->prefork = prefork;
	p->postfork = postfork;
	p->complete = complete;

	ret = G_main_add_TriggerHandler(priority
	,	TempProcessTrigger, p,	tempproc_destroy_notify);

	if (ret == NULL) {
		free(p);
		p = NULL;
	}else{
		p->trigger = ret;
	}
	return ret;
}
