/* $Id: GSource.c,v 1.42 2005/05/23 02:52:36 sunjd Exp $ */
#include <portability.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>

#include <clplumbing/cl_log.h>
#include <clplumbing/cl_malloc.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/GSource.h>
#include <clplumbing/proctrack.h>
#include <clplumbing/timers.h>

#define	MAG_GFDSOURCE	0xfeed0001U
#define	MAG_GCHSOURCE	0xfeed0002U
#define	MAG_GWCSOURCE	0xfeed0003U
#define	MAG_GSIGSOURCE	0xfeed0004U
#define	MAG_GTRIGSOURCE	0xfeed0005U

#define	IS_FDSOURCE(p)	((p)->magno == MAG_GFDSOURCE)
#define	IS_CHSOURCE(p)	((p)->magno == MAG_GCHSOURCE)
#define	IS_WCSOURCE(p)	((p)->magno == MAG_GWCSOURCE)
#define	IS_SIGSOURCE(p)	((p)->magno == MAG_GSIGSOURCE)
#define	IS_TRIGSOURCE(p) ((p)->magno == MAG_GTRIGSOURCE)

#ifndef _NSIG
# define _NSIG 2*NSIG
#endif

struct GFDSource_s {
	GSource source;
	unsigned	magno;	/* MAG_GFDSOURCE */
	void*		udata;
	gboolean	(*dispatch)(int fd, gpointer user_data);
	GPollFD		gpfd;
	GDestroyNotify	dnotify;
	guint		gsourceid;
};


typedef gboolean 	(*GCHdispatch)(IPC_Channel* ch, gpointer user_data);

struct GCHSource_s {
	GSource source;
	unsigned	magno;	/* MAG_GCHSOURCE */
	void*		udata;
	IPC_Channel*	ch;
	gboolean 	(*dispatch)(IPC_Channel* ch, gpointer user_data);
	GDestroyNotify	dnotify;
	gboolean	fd_fdx;
	GPollFD		infd;
	GPollFD		outfd;
	guint		gsourceid;
	gboolean	dontread;	/* TRUE when we don't want to read
					 * more input for a while - we're
					 * flow controlling the writer off
					 */
};

struct GWCSource_s {
	GSource source;
	unsigned		magno;	/* MAG_GWCSOURCE */
	void*			udata;
	GPollFD			gpfd;
	GDestroyNotify		dnotify;
	IPC_WaitConnection*	wch;
	IPC_Auth*		auth_info;
	gboolean (*dispatch)(IPC_Channel* accept_ch, gpointer udata);
	guint			gsourceid;
};

struct GSIGSource_s {
	GSource source;
	unsigned	magno;	/* MAG_GCHSOURCE */
	void*		udata;
	int		signal;
	gboolean	signal_triggered;
	gboolean 	(*dispatch)(int signal, gpointer user_data);
	GDestroyNotify	dnotify;
	guint		gsourceid;
};

struct GTRIGSource_s {
	GSource source;
	unsigned	magno;	/* MAG_GCHSOURCE */
	void*		udata;
	gboolean	manual_trigger;
	gboolean 	(*dispatch)(gpointer user_data);
	GDestroyNotify	dnotify;
	guint		gsourceid;
};

#define	ERR_EVENTS	(G_IO_ERR|G_IO_NVAL)
#define	INPUT_EVENTS	(G_IO_IN|G_IO_PRI|G_IO_HUP)
#define	OUTPUT_EVENTS	(G_IO_OUT)
#define	DEF_EVENTS	(INPUT_EVENTS|ERR_EVENTS)


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
	ret->udata = userdata;
	ret->dispatch = dispatch;
	ret->gpfd.fd = fd;
	ret->gpfd.events = DEF_EVENTS;
	ret->gpfd.revents = 0;
	ret->dnotify = notify;
	
	g_source_add_poll(source, &ret->gpfd);
	
	
	g_source_set_priority(source, priority);
	
	g_source_set_can_recurse(source, can_recurse);	
	
	ret->gsourceid = g_source_attach(source, NULL);
	
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
	GSource * source;


	if (fdp->gsourceid <= 0) {
		cl_log(LOG_CRIT, "Bad gsource in G_main_del_fd");
		return FALSE;
	}
	
	source = g_main_context_find_source_by_id(NULL, fdp->gsourceid);
	if (source == NULL){
		cl_log(LOG_ERR, "Cannot find source using source id");
		return FALSE;
	}

	g_source_unref(source);
	
	fdp->gsourceid = 0;

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
	return fdp->gpfd.revents != 0;
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
	g_assert(IS_FDSOURCE(fdp));
	

	/* Is output now unblocked? 
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
			return FALSE;
		}
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
	if (fdp->dnotify) {
		fdp->dnotify(fdp->udata);
	}
	g_source_unref(source);
}


/************************************************************
 *		Functions for IPC_Channels
 ***********************************************************/
static gboolean G_CH_prepare(GSource* source,
			     gint* timeout);
static gboolean G_CH_check(GSource* source);

static gboolean G_CH_dispatch(GSource* source,
			      GSourceFunc callback,
			      gpointer user_data);
static void G_CH_destroy(GSource* source);


static GSourceFuncs G_CH_SourceFuncs = {
	G_CH_prepare,
	G_CH_check,
	G_CH_dispatch,
	G_CH_destroy,
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
G_main_add_IPC_Channel(int priority, IPC_Channel* ch
		       ,	gboolean can_recurse
		       ,	gboolean (*dispatch)(IPC_Channel* source_data,
						     gpointer        user_data)
		       ,	gpointer userdata
		       ,	GDestroyNotify notify)
{
	int		rfd, wfd;
	
	GCHSource* chp;
	
	GSource * source = g_source_new(&G_CH_SourceFuncs, 
					sizeof(GCHSource));
	
	chp = (GCHSource*)source;
	
	chp->magno = MAG_GCHSOURCE;
	chp->ch = ch;
	chp->dispatch = dispatch;
	chp->udata=userdata;
	chp->dnotify = notify;
	chp->dontread = FALSE;

	rfd = ch->ops->get_recv_select_fd(ch);
	wfd = ch->ops->get_send_select_fd(ch);
	
	chp->fd_fdx = (rfd == wfd);
	
	chp->infd.fd      = rfd;
	chp->infd.events  = DEF_EVENTS;
	g_source_add_poll(source, &chp->infd);
	if (!chp->fd_fdx) {
		chp->outfd.fd      = wfd;
		chp->outfd.events  = DEF_EVENTS;
		g_source_add_poll(source, &chp->outfd);
	}

	g_source_set_priority(source, priority);
	
	g_source_set_can_recurse(source, can_recurse);
	
	chp->gsourceid = g_source_attach(source, NULL);
	

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
	if (chp->gsourceid <= 0) {
		cl_log(LOG_CRIT, "Bad gsource in G_main_del_IPC_channel");
		return FALSE;
	}

	g_source_remove(chp->gsourceid);
	chp->gsourceid = 0;
	return TRUE;
}

/*
 *	For  IPC_CHANNEL events, enable output checking when needed
 *	and note when unread input is already queued.
 *
 *	Note that we don't modify 'timeout' either.
 */
static gboolean
G_CH_prepare(GSource* source,
	     gint* timeout)
{
	GCHSource* chp = (GCHSource*)source;
	
	g_assert(IS_CHSOURCE(chp));
	
	
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
	return chp->ch->ops->is_message_pending(chp->ch);
}

/*
 *	Did we notice any I/O events?
 */

static gboolean
G_CH_check(GSource* source)
{

	GCHSource* chp = (GCHSource*)source;

	g_assert(IS_CHSOURCE(chp));
	

	if (chp->dontread){
		/* Make sure output gets unblocked */
		chp->ch->ops->resume_io(chp->ch);
		return FALSE;
	}
	
	return (chp->infd.revents != 0
		||	(!chp->fd_fdx && chp->outfd.revents != 0)
		||	chp->ch->ops->is_message_pending(chp->ch));
}

/*
 *	Some kind of event occurred - notify the user.
 */
static gboolean
G_CH_dispatch(GSource * source,
	      GSourceFunc callback,
	      gpointer user_data)
{
	GCHSource* chp = (GCHSource*)source;

	g_assert(IS_CHSOURCE(chp));


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
#if 0
	/* If we got a HUP then mark channel as disconnected */
	if ((apend->infd.revents|chp->outfd.revents) & G_IO_HUP) {
		/* CHEAT!! */
		chp->ch->ch_status = IPC_DISCONNECT;
	}else{
		chp->ch->ops->resume_io(chp->ch);
	}
#else
	chp->ch->ops->resume_io(chp->ch);
#endif

	if(chp->dispatch) {
		if(!(chp->dispatch(chp->ch, chp->udata))){
			g_source_remove_poll(source, &chp->infd);
			if (!chp->fd_fdx) {
				g_source_remove_poll(source, &chp->outfd);
			}
			g_source_unref(source);
			return FALSE;
		}
	}

	if (chp->ch->ch_status == IPC_DISCONNECT){
		return FALSE;
	}
	return TRUE;
}

/*
 *	Free up our data, and notify the user process...
 */
static void
G_CH_destroy(GSource* source)
{
	GCHSource* chp = (GCHSource*)source;
	

	g_assert(IS_CHSOURCE(chp));
	
	if (chp->dnotify) {
		chp->dnotify(chp->udata);
	}	
	chp->ch->ops->destroy(chp->ch);
	
	g_source_destroy(source);
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
	
	if (wcp->gsourceid == 0) {
		g_source_remove_poll(source, &wcp->gpfd);
		g_source_unref(source);
		source = NULL;
		wcp = NULL;
	}
	return wcp;
}


/* Delete the given IPC_WaitConnection from the gmainloop world */
gboolean G_main_del_IPC_WaitConnection(GWCSource* wcp)
{

	GSource* source = g_main_context_find_source_by_id(NULL, wcp->gsourceid);
	if (source == NULL){
		cl_log(LOG_ERR, "G_main_del_IPC_WaitConnection: Cannot find source using source id");
		return FALSE;
	}

	g_source_unref(source);
	
	wcp->gsourceid = 0;

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

	return wcp->gpfd.revents != 0;
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
	
	g_assert(IS_WCSOURCE(wcp));
	
        while(1) {
		ch = wcp->wch->ops->accept_connection(wcp->wch, wcp->auth_info);
		if (ch == NULL) {
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
	return rc;
}

/*
 *	Free up our data, and notify the user process...
 */
static void
G_WC_destroy(GSource* source)
{
	
	GWCSource* wcp = (GWCSource*)source;
	
	g_assert(IS_WCSOURCE(wcp));
	wcp->wch->ops->destroy(wcp->wch);
	if (wcp->dnotify) {
		wcp->dnotify(wcp->udata);
	}
	g_source_destroy(source);
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
	sig_src->signal		= signal;
	sig_src->dispatch	= dispatch;
	sig_src->udata		= userdata;
	sig_src->dnotify	= notify;

	sig_src->signal_triggered = FALSE;

	g_source_set_priority(source, priority);
	g_source_set_can_recurse(source, FALSE);

	if(G_main_signal_list[signal] != NULL) {
		cl_log(LOG_ERR,
		       "G_main_add_SignalHandler: Handler already present for signal %d",
		       signal);
		failed = TRUE;
	}
	if(!failed) {
		sig_src->gsourceid = g_source_attach(source, NULL);
		if (sig_src->gsourceid < 1) {
			cl_log(LOG_ERR, "G_main_add_SignalHandler: Could not attach source for signal %d (%d)",
			       signal, sig_src->gsourceid);
			failed = TRUE;
		}
	}
	
	if(failed) {
		cl_log(LOG_ERR, "G_main_add_SignalHandler: Signal handler for signal %d NOT added",
			signal);
		g_source_remove(sig_src->gsourceid);
		g_source_unref(source);
		source = NULL;
		sig_src = NULL;
	} else {
		cl_log(LOG_INFO, "G_main_add_SignalHandler: Added signal handler for signal %d",
			signal);
		G_main_signal_list[signal] = sig_src;
		CL_SIGNAL(signal, G_main_signal_handler);
	}
	
	return sig_src;
}


/*
 *	Delete a Signal from the gmainloop world...
 */
gboolean 
G_main_del_SignalHandler(GSIGSource* sig_src)
{
	if (sig_src->gsourceid <= 0) {
		cl_log(LOG_CRIT, "Bad gsource in G_main_del_IPC_channel");
		return FALSE;
	}
	g_assert(_NSIG > sig_src->signal);

	CL_SIGNAL(sig_src->signal, NULL);

	sig_src->gsourceid = 0;
	sig_src->signal_triggered = FALSE;
	g_source_remove(sig_src->gsourceid);

	G_main_signal_list[sig_src->signal] = NULL;

	return TRUE;
}

static gboolean
G_SIG_prepare(GSource* source, gint* timeout)
{
	GSIGSource* sig_src = (GSIGSource*)source;
	
	g_assert(IS_SIGSOURCE(sig_src));
	
	return sig_src->signal_triggered;
}

/*
 *	Did we notice any I/O events?
 */

static gboolean
G_SIG_check(GSource* source)
{

	GSIGSource* sig_src = (GSIGSource*)source;

	g_assert(IS_SIGSOURCE(sig_src));
	
	return sig_src->signal_triggered;
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

	g_assert(IS_SIGSOURCE(sig_src));

	sig_src->signal_triggered = FALSE;

	if(sig_src->dispatch) {
		if(!(sig_src->dispatch(sig_src->signal, sig_src->udata))){
			G_main_del_SignalHandler(sig_src);
			return FALSE;
		}
	}
	
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
	
	if (sig_src->dnotify) {
		sig_src->dnotify(sig_src->udata);
	}	
	g_source_destroy(source);
}

/* Find and set the correct mainloop input */

static void
G_main_signal_handler(int nsig)
{
	GSIGSource* sig_src = NULL;

	g_assert(G_main_signal_list != NULL);
	g_assert(_NSIG > nsig);
	
	sig_src = G_main_signal_list[nsig];

/* 	g_assert(sig_src != NULL); */
	if(sig_src == NULL) {
		cl_log(LOG_CRIT, "No handler for signal -%d", nsig);
		return;
	}
	
	g_assert(IS_SIGSOURCE(sig_src));
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
	setmsrepeattimer(WAITALARM); /* Might as well be persistent ;-) */
	while((pid=wait3(&status, waitflags, NULL)) > 0
	||	errno == EINTR) {
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
	if (alarm_count) {
		cl_log(LOG_ERR
		,	"%s: wait3() call hung %d times. childcount = %d"
		,	__FUNCTION__, alarm_count, childcount);
		alarm_count = 0;
	}
	return TRUE;
}

void
set_sigchld_proctrack(int priority)
{
	G_main_add_SignalHandler(priority, SIGCHLD
	,	child_death_dispatch, NULL, NULL);
	cl_signal_set_interrupt(SIGCHLD, TRUE);
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
	trig_src->dispatch	= dispatch;
	trig_src->udata		= userdata;
	trig_src->dnotify	= notify;

	trig_src->manual_trigger = FALSE;

	g_source_set_priority(source, priority);
	g_source_set_can_recurse(source, FALSE);

	if(!failed) {
		trig_src->gsourceid = g_source_attach(source, NULL);
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
		cl_log(LOG_INFO, "G_main_add_TriggerHandler: Added signal manual handler");
	}
	
	return trig_src;
}

void 
G_main_set_trigger(GTRIGSource* source)
{
	GTRIGSource* trig_src = (GTRIGSource*)source;
	
	g_assert(IS_TRIGSOURCE(trig_src));
	
	trig_src->manual_trigger = TRUE;
}


/*
 *	Delete a Trigger from the gmainloop world...
 */
gboolean 
G_main_del_TriggerHandler(GTRIGSource* trig_src)
{
	if (trig_src->gsourceid <= 0) {
		cl_log(LOG_CRIT, "Bad gsource in G_main_del_TriggerHandler");
		return FALSE;
	}
	trig_src->gsourceid = 0;
	trig_src->manual_trigger = FALSE;
	g_source_remove(trig_src->gsourceid);

	return TRUE;
}

static gboolean
G_TRIG_prepare(GSource* source, gint* timeout)
{
	GTRIGSource* trig_src = (GTRIGSource*)source;
	
	g_assert(IS_TRIGSOURCE(trig_src));
	
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

	g_assert(IS_TRIGSOURCE(trig_src));

	trig_src->manual_trigger = FALSE;

	if(trig_src->dispatch) {
		if(!(trig_src->dispatch(trig_src->udata))){
			G_main_del_TriggerHandler(trig_src);
			return FALSE;
		}
	}
	
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
	
	if (trig_src->dnotify) {
		trig_src->dnotify(trig_src->udata);
	}	
	g_source_destroy(source);
}

