/* $Id: GSource.c,v 1.19 2004/12/16 19:25:02 gshi Exp $ */
#include <portability.h>
#include <string.h>

#include <clplumbing/cl_log.h>
#include <clplumbing/GSource.h>


#define	MAG_GFDSOURCE	0xfeed0001U
#define	MAG_GCHSOURCE	0xfeed0002U
#define	MAG_GWCSOURCE	0xfeed0003U

#define	IS_FDSOURCE(p)	((p)->magno == MAG_GFDSOURCE)
#define	IS_CHSOURCE(p)	((p)->magno == MAG_GCHSOURCE)
#define	IS_WCSOURCE(p)	((p)->magno == MAG_GWCSOURCE)

struct GFDSource_s {
	unsigned	magno;	/* MAG_GFDSOURCE */
	void*		udata;
	gboolean	(*dispatch)(int fd, gpointer user_data);
	GPollFD		gpfd;
	GDestroyNotify	dnotify;
	guint		gsourceid;
};


typedef gboolean 	(*GCHdispatch)(IPC_Channel* ch, gpointer user_data);

struct GCHSource_s {
	unsigned	magno;	/* MAG_GCHSOURCE */
	void*		udata;
	IPC_Channel*	ch;
	gboolean 	(*dispatch)(IPC_Channel* ch, gpointer user_data);
	GDestroyNotify	dnotify;
	gboolean	fd_fdx;
	GPollFD		infd;
	GPollFD		outfd;
	guint		gsourceid;
};

struct GWCSource_s {
	unsigned		magno;	/* MAG_GWCSOURCE */
	void*			udata;
	GPollFD			gpfd;
	GDestroyNotify		dnotify;
	IPC_WaitConnection*	wch;
	IPC_Auth*		auth_info;
	gboolean (*dispatch)(IPC_Channel* accept_ch, gpointer udata);
	guint			gsourceid;
};

#define	DEF_EVENTS	(G_IO_IN|G_IO_PRI|G_IO_HUP|G_IO_ERR|G_IO_NVAL)
#define	OUTPUT_EVENTS	(G_IO_OUT)


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

#define GET_FD_SOURCE(src) (GFDSource*)((GSource*)(src)+1)

GFDSource*
G_main_add_fd(int priority, int fd, gboolean can_recurse
,	gboolean (*dispatch)(int fd, gpointer user_data)
,	gpointer userdata
,	GDestroyNotify notify)
{

	GSource* source = g_source_new(&G_fd_SourceFuncs, 
				      sizeof(GSource)
				      + sizeof(GFDSource));
	GFDSource* ret = GET_FD_SOURCE(source);
	
	memset(ret, 0, sizeof(GFDSource));
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
	GFDSource*	fdp = GET_FD_SOURCE(source);
	g_assert(IS_FDSOURCE(fdp));
	return FALSE;
}

/*
 *	Did we notice any I/O events?
 */

static gboolean
G_fd_check(GSource* source)
     
{
	GFDSource*	fdp = GET_FD_SOURCE(source);
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
	GFDSource*	fdp = GET_FD_SOURCE(source);

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

	GFDSource*	fdp = GET_FD_SOURCE(source);
	
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



#define GET_CH_SOURCE(src)	(GCHSource*)(src +1)

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
					sizeof(GSource)
					+ sizeof(GCHSource));
	
	chp = GET_CH_SOURCE(source);

	memset(chp, 0, sizeof(GCHSource));
	
	chp->magno = MAG_GCHSOURCE;
	chp->ch = ch;
	chp->dispatch = dispatch;
	chp->udata=userdata;
	chp->dnotify = notify;

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
	GCHSource* chp = GET_CH_SOURCE(source);
	
	g_assert(IS_CHSOURCE(chp));
	if (chp->ch->ops->is_sending_blocked(chp->ch)) {
		if (chp->fd_fdx) {
			chp->infd.events |= OUTPUT_EVENTS;
		}else{
			chp->outfd.events |= OUTPUT_EVENTS;
		}
	}
	return chp->ch->ops->is_message_pending(chp->ch);
}

/*
 *	Did we notice any I/O events?
 */

static gboolean
G_CH_check(GSource* source)
{

	GCHSource* chp = GET_CH_SOURCE(source);
	
	g_assert(IS_CHSOURCE(chp));
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
	GCHSource* chp = GET_CH_SOURCE(source);

	g_assert(IS_CHSOURCE(chp));
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
	
	return TRUE;
}

/*
 *	Free up our data, and notify the user process...
 */
static void
G_CH_destroy(GSource* source)
{
	GCHSource* chp = GET_CH_SOURCE(source);

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

#define GET_WC_SOURCE(src)	(GWCSource*)(src +1)

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
					sizeof(GSource)
					+ sizeof(GWCSource));
	
	wcp = GET_WC_SOURCE(source);
	
	memset(wcp, 0, sizeof(GWCSource));
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
	GWCSource*  wcp = GET_WC_SOURCE(source);
	
	g_assert(IS_WCSOURCE(wcp));
	return FALSE;
}

/*
 *	Did we notice any I/O (connection pending) events?
 */

static gboolean
G_WC_check(GSource * source)
{
	GWCSource*  wcp = GET_WC_SOURCE(source);
	
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
	GWCSource*  wcp = GET_WC_SOURCE(source);
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
	
	GWCSource*  wcp = GET_WC_SOURCE(source);
	
	g_assert(IS_WCSOURCE(wcp));
	wcp->wch->ops->destroy(wcp->wch);
	if (wcp->dnotify) {
		wcp->dnotify(wcp->udata);
	}
	g_source_destroy(source);
}
