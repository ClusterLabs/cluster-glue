#include <portability.h>
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

#define	DEF_EVENTS	(G_IO_IN|G_IO_PRI||G_IO_HUP|G_IO_ERR|G_IO_NVAL)
#define	OUTPUT_EVENTS	(G_IO_OUT)

static gboolean G_fd_prepare(gpointer source_data
,       GTimeVal* current_time
,       gint* timeout, gpointer user_data);
static gboolean G_fd_check(gpointer source_data
,       GTimeVal* current_time
,       gpointer user_data);
static gboolean G_fd_dispatch(gpointer source_data
,       GTimeVal* current_time
,       gpointer user_data);
static void G_fd_destroy(gpointer user_data);

static GSourceFuncs G_fd_SourceFuncs = {
	G_fd_prepare,
	G_fd_check,
	G_fd_dispatch,
	G_fd_destroy,
};

/*
 *	Add the given file descriptor to the gmainloop world.
 */

GFDSource*
G_main_add_fd(int priority, int fd, gboolean can_recurse
,	gboolean (*dispatch)(int fd, gpointer user_data)
,	gpointer userdata
,	GDestroyNotify notify)
{
	GFDSource*	ret = g_new(GFDSource, 1);

	memset(ret, 0, sizeof(*ret));
	ret->magno = MAG_GFDSOURCE;
	ret->udata = userdata;
	ret->dispatch = dispatch;
	ret->gpfd.fd = fd;
	ret->gpfd.events = DEF_EVENTS;
	ret->gpfd.revents = 0;
	ret->dnotify = notify;

	g_main_add_poll(&ret->gpfd, priority);

	ret->gsourceid = g_source_add(priority, can_recurse
	,	&G_fd_SourceFuncs
	,	ret, ret, NULL);

	if (ret->gsourceid == 0) {
		g_free(ret);
		g_main_remove_poll(&ret->gpfd);
		memset(ret, 0, sizeof(*ret));
		ret = NULL;
	}
	return ret;
}

gboolean
G_main_del_fd(GFDSource* fdp)
{
	return g_source_remove(fdp->gsourceid);
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
G_fd_prepare(gpointer source_data
,       GTimeVal* current_time
,       gint* timeout, gpointer user_data)
{
	GFDSource*	fdp = source_data;
	g_assert(IS_FDSOURCE(fdp));
	return FALSE;
}

/*
 *	Did we notice any I/O events?
 */

static gboolean
G_fd_check(gpointer source_data
,       GTimeVal* current_time
,       gpointer user_data)
{
	GFDSource*	fdp = source_data;

	g_assert(IS_FDSOURCE(fdp));
	return fdp->gpfd.revents != 0;
}

/*
 *	Some kind of event occurred - notify the user.
 */
static gboolean
G_fd_dispatch(gpointer source_data
,       GTimeVal* current_time
,       gpointer user_data)
{
	GFDSource*	fdp = source_data;

	g_assert(IS_FDSOURCE(fdp));
	/* Is output now unblocked? 
	 *
	 * If so, turn off OUTPUT_EVENTS to avoid going into
	 * a tight poll(2) loop.
	 */
	if (fdp->gpfd.revents & OUTPUT_EVENTS) {
		fdp->gpfd.events &= ~OUTPUT_EVENTS;
	}

	return fdp->dispatch(fdp->gpfd.fd, fdp->udata);
}

/*
 *	Free up our data, and notify the user process...
 */
static void
G_fd_destroy(gpointer user_data)
{
	GFDSource*	fdp = user_data;

	g_assert(IS_FDSOURCE(fdp));
	if (fdp->dnotify) {
		fdp->dnotify(fdp->udata);
	}
	g_main_remove_poll(&fdp->gpfd);
	g_source_remove(fdp->gsourceid);
	memset(fdp, 0, sizeof(*fdp));
	g_free(fdp);
	fdp = NULL;
}

/************************************************************
 *		Functions for IPC_Channels
 ***********************************************************/
static gboolean G_CH_prepare(gpointer source_data
,       GTimeVal* current_time
,       gint* timeout, gpointer user_data);
static gboolean G_CH_check(gpointer source_data
,       GTimeVal* current_time
,       gpointer user_data);
static gboolean G_CH_dispatch(gpointer source_data
,       GTimeVal* current_time
,       gpointer user_data);
static void G_CH_destroy(gpointer user_data);

static GSourceFuncs G_CH_SourceFuncs = {
	G_CH_prepare,
	G_CH_check,
	G_CH_dispatch,
	G_CH_destroy,
};

/*
 *	Add an IPC_channel to the gmainloop world...
 */
GCHSource* G_main_add_IPC_Channel(int priority, IPC_Channel* ch
,	gboolean can_recurse
,	gboolean (*dispatch)(IPC_Channel* source_data
,		gpointer        user_data)
,	gpointer userdata
,	GDestroyNotify notify)
{
	GCHSource*	ret = g_new(GCHSource, 1);
	int		rfd, wfd;

	memset(ret, 0, sizeof(*ret));
	ret->magno = MAG_GCHSOURCE;
	ret->udata = userdata;
	ret->ch = ch;
	ret->dispatch = dispatch;
	ret->dnotify = notify;

	rfd = ch->ops->get_recv_select_fd(ch);
	wfd = ch->ops->get_send_select_fd(ch);

	ret->fd_fdx = (rfd == wfd);

	ret->infd.fd      = rfd;
	ret->infd.events  = DEF_EVENTS;
	g_main_add_poll(&ret->infd, priority);
	if (!ret->fd_fdx) {
		ret->outfd.fd      = wfd;
		ret->outfd.events  = DEF_EVENTS;
		g_main_add_poll(&ret->outfd, priority);
	}
	ret->gsourceid = g_source_add(priority, can_recurse
	,	&G_CH_SourceFuncs
	,	ret, ret, NULL);

	if (ret->gsourceid == 0) {
		g_main_remove_poll(&ret->infd);
		if (!ret->fd_fdx) {
			g_main_remove_poll(&ret->outfd);
		}
		memset(ret, 0, sizeof(*ret));
		g_free(ret);
		ret = NULL;
	}
	return ret;
}


/*
 *	Delete an IPC_channel from the gmainloop world...
 */
gboolean G_main_del_IPC_Channel(GCHSource* fdp)
{
	return g_source_remove(fdp->gsourceid);
}

/*
 *	For  IPC_CHANNEL events, enable output checking when needed
 *	and note when unread input is already queued.
 *
 *	Note that we don't modify 'timeout' either.
 */
static gboolean
G_CH_prepare(gpointer source_data
,       GTimeVal* current_time
,       gint* timeout, gpointer user_data)
{
	GCHSource*	chp = source_data;

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
G_CH_check(gpointer source_data
,       GTimeVal* current_time
,       gpointer user_data)
{
	GCHSource*	chp = source_data;

	g_assert(IS_CHSOURCE(chp));
	return (chp->infd.revents != 0
	||	(!chp->fd_fdx && chp->outfd.revents != 0)
	||	chp->ch->ops->is_message_pending(chp->ch));
}

/*
 *	Some kind of event occurred - notify the user.
 */
static gboolean
G_CH_dispatch(gpointer source_data
,       GTimeVal* current_time
,       gpointer user_data)
{
	GCHSource*	chp = source_data;

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
	/* If we got a HUP then marke channel as disconnected */
	if ((chp->infd.revents|chp->outfd.revents) & G_IO_HUP) {
		/* CHEAT!! */
		chp->ch->ch_status = IPC_DISCONNECT;
	}
	chp->ch->ops->resume_io(chp->ch);
	return chp->dispatch(chp->ch, chp->udata);
}

/*
 *	Free up our data, and notify the user process...
 */
static void
G_CH_destroy(gpointer user_data)
{
	/* This was the source_data parameter passed to g_source_add */
	/* It is a GCHSource* object */
	GCHSource*	chp = user_data;

	g_assert(IS_CHSOURCE(chp));
	g_main_remove_poll(&chp->infd);
	if (!chp->fd_fdx) {
		g_main_remove_poll(&chp->outfd);
	}
	chp->ch->ops->destroy(chp->ch);
	if (chp->dnotify) {
		chp->dnotify(chp->udata);
	}
	g_source_remove(chp->gsourceid);
	memset(chp, 0, sizeof(*chp));
	g_free(chp);
}

/************************************************************
 *		Functions for IPC_WaitConnections
 ***********************************************************/
static gboolean G_WC_prepare(gpointer source_data
,       GTimeVal* current_time
,       gint* timeout, gpointer user_data);
static gboolean G_WC_check(gpointer source_data
,       GTimeVal* current_time
,       gpointer user_data);
static gboolean G_WC_dispatch(gpointer source_data
,       GTimeVal* current_time
,       gpointer user_data);
static void G_WC_destroy(gpointer user_data);

static GSourceFuncs G_WC_SourceFuncs = {
	G_WC_prepare,
	G_WC_check,
	G_WC_dispatch,
	G_WC_destroy,
};
/*
 *	Add an IPC_WaitConnection to the gmainloop world...
 */
GWCSource* G_main_add_IPC_WaitConnection(int priority
,	IPC_WaitConnection* wch
,	IPC_Auth* auth_info
,	gboolean can_recurse
,	gboolean (*dispatch)(IPC_Channel* wch
,		gpointer        user_data)
,	gpointer userdata
,	GDestroyNotify notify)
{


	GWCSource*	ret = g_new(GWCSource, 1);

	memset(ret, 0, sizeof(*ret));
	ret->magno = MAG_GWCSOURCE;
	ret->udata = userdata;
	ret->gpfd.fd = wch->ops->get_select_fd(wch);
	ret->gpfd.events = DEF_EVENTS;
	ret->gpfd.revents = 0;
	ret->wch = wch;
	ret->dnotify = notify;
	ret->auth_info = auth_info;
	ret->dispatch = dispatch;

	g_main_add_poll(&ret->gpfd, priority);

	ret->gsourceid = g_source_add(priority, can_recurse
	,	&G_WC_SourceFuncs
	,	ret, ret, NULL);

	if (ret->gsourceid == 0) {
		g_free(ret);
		g_main_remove_poll(&ret->gpfd);
		memset(ret, 0, sizeof(*ret));
		ret = NULL;
	}
	return ret;
}


/* Delete the given IPC_WaitConnection from the gmainloop world */
gboolean G_main_del_IPC_WaitConnection(GWCSource* wcp)
{
	return g_source_remove(wcp->gsourceid);
}



/*
 *	For IPC_WaitConnection events, return FALSE because we
 *	have to poll to get events.
 *
 *	We don't modify 'timeout' either.
 */
static gboolean
G_WC_prepare(gpointer source_data
,       GTimeVal* current_time
,       gint* timeout, gpointer user_data)
{
	GWCSource*	wcp = source_data;
	g_assert(IS_WCSOURCE(wcp));
	return FALSE;
}

/*
 *	Did we notice any I/O (connection pending) events?
 */

static gboolean
G_WC_check(gpointer source_data
,       GTimeVal* current_time
,       gpointer user_data)
{
	GWCSource*	wcp = source_data;

	g_assert(IS_WCSOURCE(wcp));
	return wcp->gpfd.revents != 0;
}

/*
 *	Someone is trying to connect.
 *	Try to accept the connection and notify the user.
 */
static gboolean
G_WC_dispatch(gpointer source_data
,       GTimeVal* current_time
,       gpointer user_data)
{
	GWCSource*	wcp = source_data;
	IPC_Channel*	ch;
	gboolean	rc = TRUE;
	int		count = 0;

	g_assert(IS_WCSOURCE(wcp));
       
        do {
	  ch = wcp->wch->ops->accept_connection(wcp->wch, wcp->auth_info);
          if (!ch) {
		break;
	  }
	  ++count;
	}while ((rc = wcp->dispatch(ch, wcp->udata)));
	return rc;
}

/*
 *	Free up our data, and notify the user process...
 */
static void
G_WC_destroy(gpointer user_data)
{
	GWCSource*	wcp = user_data;

	g_assert(IS_WCSOURCE(wcp));
	g_main_remove_poll(&wcp->gpfd);
	g_source_remove(wcp->gsourceid);
	wcp->wch->ops->destroy(wcp->wch);
	if (wcp->dnotify) {
		wcp->dnotify(wcp->udata);
	}
	memset(wcp, 0, sizeof(*wcp));
	g_free(wcp);
	wcp = NULL;
}
