#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_poll.h>
#include <clplumbing/GSource.h>
#include <clplumbing/ipc.h>

typedef int (*TestFunc_t)(IPC_Channel*chan, int count);

static int channelpair(TestFunc_t client, TestFunc_t server, int count);
#if 0
static void clientserverpair(IPC_Channel* channels[2]);
#endif
static int echoserver(IPC_Channel*, int repcount);
static int echoclient(IPC_Channel*, int repcount);
static int asyn_echoserver(IPC_Channel*, int repcount);
static int asyn_echoclient(IPC_Channel*, int repcount);
static int mainloop_server(IPC_Channel* chan, int repcount);
static int mainloop_client(IPC_Channel* chan, int repcount);

static int checksock(IPC_Channel* channel);
static void checkifblocked(IPC_Channel* channel);

static int (*PollFunc)(struct pollfd * fds, unsigned int, int)
=	(int (*)(struct pollfd * fds, unsigned int, int))  poll;

static int
channelpair(TestFunc_t	clientfunc, TestFunc_t serverfunc, int count)
{
	IPC_Channel* channels[2];
	int		rc;
	int		waitstat = 0;

	if (ipc_channel_pair(channels) != IPC_OK) {
		cl_perror("Can't create ipc channel pair");
		exit(1);
	}
	checksock(channels[0]);
	checksock(channels[1]);
	switch (fork()) {
		case -1:
			cl_perror("can't fork");
			exit(1);
			break;

		case 0:		/* Child */
			channels[1]->ops->destroy(channels[1]);
			rc = clientfunc(channels[0], count);
			exit (rc > 127 ? 127 : rc);
			break;

		default:	 /* Server */
			channels[0]->ops->destroy(channels[0]);
			rc = serverfunc(channels[1], count);
			wait(&waitstat);
			if (WIFEXITED(waitstat)) {
				rc += WEXITSTATUS(waitstat);
			}else{
				rc += 1;
			}
			return rc;
	}
	return -1; /* This can't happen ;-) */
}

#if 0
static void
clientserverpair(IPC_Channel* channels[2])
{
	char			path[] = IPC_PATH_ATTR;
	char			commpath[] = "/tmp/foobar"
	GHashTable *		wattrs;
	IPC_WAIT_CONNECTION*	wconn;

	wattrs = g_hash_table_new(g_str_hash, g_str_equal);

	g_hash_table_insert(wattrs, path, commpath);

	wconn = ipc_wait_conn_constructor(IPC_ANYTYPE, wconnattrs);

	if (wconn == NULL) {
		cl_perror("Can't create wait connection");
		exit(1);
	}

}
#endif
static void
checkifblocked(IPC_Channel* chan)
{
	if (chan->ops->is_sending_blocked(chan)) {
		cl_log(LOG_INFO, "Sending is blocked.");
		chan->ops->resume_io(chan);
	}
}

int
main(int argc, char ** argv)
{
	int	rc = 0;

	cl_log_set_entity("ipctest");
	cl_log_enable_stderr(TRUE);


	rc += channelpair(echoclient, echoserver, 10000);
	rc += channelpair(asyn_echoclient, asyn_echoserver, 20000);
	rc += channelpair(mainloop_client, mainloop_server, 20000);

	cl_log(LOG_INFO, "NOTE: Enabling poll(2) replacement code.");
	PollFunc = cl_poll;
	g_main_set_poll_func(cl_glibpoll);
	rc += channelpair(asyn_echoclient, asyn_echoserver, 100000);
	rc += channelpair(mainloop_client, mainloop_server, 100000);

	cl_log(LOG_INFO, "TOTAL errors: %d", rc);

	return (rc > 127 ? 127 : rc);
}
static int
checksock(IPC_Channel* channel)
{

	if (channel->ch_status != IPC_CONNECT) {
		cl_log(LOG_ERR, "Channel status is %d"
		", not IPC_CONNECT", channel->ch_status);
		return 1;
	}
	return 0;
}

static int
echoserver(IPC_Channel* wchan, int repcount)
{
	char	str[256];
	int	j;
	int	errcount = 0;
	IPC_Message	wmsg;
	IPC_Message*	rmsg;


	wmsg.msg_private = NULL;
	wmsg.msg_done = NULL;
	wmsg.msg_body = str;
	wmsg.msg_ch = wchan;

	cl_log(LOG_INFO, "Echo server: %d reps pid %d.", repcount, getpid());
	for (j=1; j <= repcount
	;++j, rmsg != NULL && (rmsg->msg_done(rmsg),1)) {
		int	rc;
		snprintf(str, sizeof(str)-1, "String-%d", j);
		wmsg.msg_len = strlen(str)+1;
		if ((rc = wchan->ops->send(wchan, &wmsg)) != IPC_OK) {
			cl_log(LOG_ERR
			,	"echotest: send failed %d rc iter %d"
			,	rc, j);
			++errcount;
			continue;
		}

		//fprintf(stderr, "+");
		wchan->ops->waitout(wchan);
		checkifblocked(wchan);
		//fprintf(stderr, "S");

		/* Try and induce a failure... */
		if (j == repcount) {
			sleep(1);
		}
		if ((rc = wchan->ops->waitin(wchan)) != IPC_OK) {
			cl_log(LOG_ERR
			,	"echotest server: waitin failed %d rc iter %d"
			" errno=%d"
			,	rc, j, errno);
			cl_perror("waitin");
			exit(1);
		}

		//fprintf(stderr, "-");
		if ((rc = wchan->ops->recv(wchan, &rmsg)) != IPC_OK) {
			cl_log(LOG_ERR
			,	"echotest server: recv failed %d rc iter %d"
			" errno=%d"
			,	rc, j, errno);
			cl_perror("recv");
			++errcount;
			rmsg=NULL;
			continue;
		}
		//fprintf(stderr, "s");
		if (rmsg->msg_len != wmsg.msg_len) {
			cl_log(LOG_ERR
			,	"echotest: length mismatch [%lu,%lu] iter %d"
			,	(unsigned long)rmsg->msg_len
			,	(unsigned long)wmsg.msg_len, j);
			++errcount;
			continue;
		}
		if (strncmp(rmsg->msg_body, wmsg.msg_body, wmsg.msg_len)
		!= 0) {
			cl_log(LOG_ERR
			,	"echotest: data mismatch. iteration %d"
			,	j);
			++errcount;
			continue;
		}
		
	}
	wchan->ops->waitout(wchan);
	wchan->ops->destroy(wchan);  wchan=NULL;
	cl_log(LOG_INFO, "echoserver: %d errors", errcount);
	return errcount;
}
static int
echoclient(IPC_Channel* rchan, int repcount)
{
	int	j;
	int	errcount = 0;
	IPC_Message*	rmsg;



	cl_log(LOG_INFO, "Echo client: %d reps pid %d."
	,	repcount, (int)getpid());
	for (j=1; j <= repcount ;++j) {

		int	rc;

		if ((rc = rchan->ops->waitin(rchan)) != IPC_OK) {
			cl_log(LOG_ERR
			,	"echotest client: waitin failed %d rc iter %d"
			" errno=%d"
			,	rc, j, errno);
			cl_perror("waitin");
			exit(1);
		}
		//fprintf(stderr, "/");

		if ((rc = rchan->ops->recv(rchan, &rmsg)) != IPC_OK) {
			cl_log(LOG_ERR
			,	"echoclient: recv failed %d rc iter %d"
			" errno=%d"
			,	rc, j, errno);
			cl_perror("recv");
			++errcount;
			rmsg=NULL;
			continue;
		}
		//fprintf(stderr, "c");
		if ((rc = rchan->ops->send(rchan, rmsg)) != IPC_OK) {
			cl_log(LOG_ERR
			,	"echoclient: send failed %d rc iter %d"
			,	rc, j);
			cl_log(LOG_INFO, "Message being sent: %s"
			,		(char*)rmsg->msg_body);
			++errcount;
			continue;
		}
		//fprintf(stderr, "%%");
		rchan->ops->waitout(rchan);
		checkifblocked(rchan);
		//fprintf(stderr, "C");
	}
	rchan->ops->waitout(rchan);
	rchan->ops->destroy(rchan);  rchan=NULL;
	cl_log(LOG_INFO, "echoclient: %d errors", errcount);
	return errcount;
}

static void
echomsgbody(void * body, int niter, size_t * len)
{
	char *	str = body;
	sprintf(str, "String-%d", niter);
	*len = strlen(str)+1;
}

static void
msg_free(IPC_Message* msg)
{
	free(msg->msg_body);
	free(msg);
}

static IPC_Message*
newmessage(IPC_Channel* chan, int niter)
{
	IPC_Message*	msg;

	msg = malloc(sizeof(*msg));
	msg->msg_private = NULL;
	msg->msg_done = msg_free;
	msg->msg_ch = chan;
	msg->msg_body = malloc(32);
	echomsgbody(msg->msg_body, niter, &msg->msg_len);
	return msg;
}
static int
checkinput(IPC_Channel* chan, int* rdcount, int maxcount)
{
	IPC_Message*	rmsg = NULL;
	int		errs = 0;
	char		str[256];
	size_t		rdlen;
	int		rc;

	while (chan->ops->is_message_pending(chan)
	&&	errs < 10 && *rdcount < maxcount) {

		if (rmsg != NULL) {
			rmsg->msg_done(rmsg);
			rmsg = NULL;
		}
		if ((rc = chan->ops->recv(chan, &rmsg)) != IPC_OK) {
			if (chan->ch_status == IPC_DISCONNECT) {
				cl_log(LOG_ERR
				,	"checkinput: EOF in iter %d"
				,	*rdcount);
				return errs;
			}
			cl_log(LOG_ERR
			,	"checkinput: recv"
			" failed: rc %d  rdcount %d errno=%d"
			,	rc, *rdcount, errno);
			cl_perror("recv");
			rmsg=NULL;
			++errs;
			continue;
		}
		*rdcount += 1;
		echomsgbody(str, *rdcount, &rdlen);
		if (rmsg->msg_len != rdlen) {
			cl_log(LOG_ERR
			,	"checkinput: length mismatch"
			" [%u,%lu] iter %d"
			,	(unsigned)rdlen
			,	(unsigned long)rmsg->msg_len
			,	*rdcount);
			++errs;
			continue;
		}
		if (strncmp(rmsg->msg_body, str, rdlen) != 0) {
			cl_log(LOG_ERR
			,	"checkinput: data mismatch"
			". input iteration %d"
			,	*rdcount);
			++errs;
			continue;
		}
	}
	return errs;
}

static int
asyn_echoserver(IPC_Channel* wchan, int repcount)
{
	int		rdcount = 0;
	int		wrcount = 0;
	int		errcount = 0;
	int		blockedcount = 0;
	IPC_Message*	wmsg;
	int		lastcount = -1;



	cl_log(LOG_INFO, "Asyn echo server: %d reps pid %d."
	,	repcount, (int)getpid());
	while (rdcount < repcount) {
		int	rc;

		do {
			++wrcount;
			if (wrcount > repcount) {
				break;
			}
			wmsg = newmessage(wchan, wrcount);

			//fprintf(stderr, "s");
			if ((rc = wchan->ops->send(wchan, wmsg)) != IPC_OK) {
				cl_log(LOG_ERR
				,	"asyn_echotest: send failed"
				" %d rc iter %d"
				,	rc, wrcount);
				++errcount;
				continue;
			}
			lastcount = wrcount;
			
			if (wchan->ops->is_sending_blocked(wchan)) {
				// fprintf(stderr, "b");
				++blockedcount;
			}else{
				blockedcount = 0;
			}
			errcount += checkinput(wchan, &rdcount, repcount);
			if (wrcount < repcount
			&&	wchan->ch_status == IPC_DISCONNECT) {
				++errcount;
				break;
			}
		}while (wrcount < repcount && blockedcount < 10
		&&	wchan->ch_status != IPC_DISCONNECT);

		if (wrcount < repcount) {
			// fprintf(stderr, "B");
		}
		wchan->ops->waitout(wchan);
		errcount += checkinput(wchan, &rdcount, repcount);
		if (wrcount >= repcount && rdcount < repcount) {
			if ((rc = wchan->ops->waitin(wchan)) != IPC_OK) {
				cl_log(LOG_ERR
				,	"asyn_echotest server: waitin"
				" failed %d rc rdcount %d errno=%d"
				,	rc, rdcount, errno);
				cl_perror("waitin");
				exit(1);
			}
		}
		if (wchan->ch_status == IPC_DISCONNECT
		&&	rdcount < repcount) {
			cl_log(LOG_ERR
			,	"asyn_echoserver: EOF in iter %d"
			,	rdcount);
			++errcount;
			break;
		}

	}

	wchan->ops->waitout(wchan);
	wchan->ops->destroy(wchan);  wchan=NULL;
	cl_log(LOG_INFO, "asyn_echoserver: %d errors", errcount);
	return errcount;
}

static int
asyn_echoclient(IPC_Channel* chan, int repcount)
{
	int		rdcount = 0;
	int		errcount = 0;
	IPC_Message*	rmsg;
	int		rfd = chan->ops->get_recv_select_fd(chan);
	int		wfd = chan->ops->get_send_select_fd(chan);
	gboolean	rdeqwr = (rfd == wfd);


	cl_log(LOG_INFO, "Async Echo client: %d reps pid %d."
	,	repcount, (int)getpid());
	ipc_set_pollfunc(PollFunc);

	while (rdcount < repcount && errcount < repcount) {

		int		rc;
		struct pollfd 	pf[2];
		int		nfd = 1;

		pf[0].fd	= rfd;
		pf[0].events	= POLLIN|POLLHUP;


		if (chan->ops->is_sending_blocked(chan)) {
			if (rdeqwr) {
				pf[0].events |= POLLOUT;
			}else{
				nfd = 2;
				pf[1].fd = wfd;
				pf[1].events = POLLOUT|POLLHUP;
			}
		}

		/* Have input? */
		// fprintf(stderr, "i");
		while (chan->ops->is_message_pending(chan)
		&&	rdcount < repcount) {
			//fprintf(stderr, "r");

			if ((rc = chan->ops->recv(chan, &rmsg)) != IPC_OK) {
				if (chan->ch_status != IPC_CONNECT) {
					cl_log(LOG_ERR
					,	"Async echoclient: disconnect"
					" iter %d", rdcount+1);
					++errcount;
					return errcount;
				}
				cl_log(LOG_ERR
				,	"Async echoclient: recv"
				" failed %d rc iter %d errno=%d"
				,	rc, rdcount+1, errno);
				cl_perror("recv");
				rmsg=NULL;
				++errcount;
				cl_log(LOG_INFO, "sleep(1)");
				sleep(1);
				continue;
			}
			//fprintf(stderr, "c");
			++rdcount;
			if ((rc = chan->ops->send(chan, rmsg))
			!=	IPC_OK) {
				++errcount;
				cl_perror("send");
				cl_log(LOG_ERR
				,	"Async echoclient: send failed"
				" rc %d, iter %d", rc, rdcount);
				cl_log(LOG_INFO, "Message being sent: %s"
				,		(char*)rmsg->msg_body);
				if (chan->ch_status != IPC_CONNECT) {
					cl_log(LOG_ERR
					,	"Async echoclient: EOF(2)"
					" iter %d", rdcount+1);
					return errcount;
				}
				continue;
			}
			//fprintf(stderr, "x");
		}
		if (rdcount >= repcount) {
			break;
		}
		/*
		 * At this point it is possible that the POLLOUT bit
		 * being on is no longer necessary, but this will only
		 * cause an extra (false) output poll iteration at worst...
		 * This is because (IIRC) both is_sending_blocked(), and 
		 * is_message_pending() both perform a resume_io().
		 * This might be confusing, but -- oh well...
		 */
		//fprintf(stderr, "P");
		//cl_log(LOG_INFO, "poll[%d, 0x%x]"
		//,	pf[0].fd, pf[0].events);
		//cl_log(LOG_DEBUG, "poll[%d, 0x%x]..."
		//,	pf[0].fd, pf[0].events);
		//fprintf(stderr, "%%");
		//cl_log(LOG_DEBUG, "CallingPollFunc()");
		rc = PollFunc(pf, nfd, -1);

		/* Bad poll? */
		if (rc <= 0) {
			cl_log(LOG_ERR
			,	"Async echoclient: bad poll rc."
			" %d rc iter %d", rc, rdcount);
			++errcount;
			continue;
		}

		/* Error indication? */
		if ((pf[0].revents & (POLLERR|POLLNVAL)) != 0) {
			cl_log(LOG_ERR
			,	"Async echoclient: bad poll revents."
			" revents: 0x%x iter %d", pf[0].revents, rdcount);
			++errcount;
			continue;
		}

		/* HUP without input... Premature EOF... */
		if ((pf[0].revents & POLLHUP)
		&&	((pf[0].revents&POLLIN) == 0)) {
			cl_log(LOG_ERR
			,	"Async echoclient: premature pollhup."
			" revents: 0x%x iter %d", pf[0].revents, rdcount);
			++errcount;
			continue;
		}

		/* Error indication? */
		if (nfd > 1
		&&	(pf[1].revents & (POLLERR|POLLNVAL)) != 0) {
			cl_log(LOG_ERR
			,	"Async echoclient: bad poll revents[1]."
			" revents: 0x%x iter %d", pf[1].revents, rdcount);
			++errcount;
			continue;
		}

		/* Output unblocked (only) ? */
		if (pf[nfd-1].revents & POLLOUT) {
			//fprintf(stderr, "R");
			chan->ops->resume_io(chan);
		}else if ((pf[0].revents & POLLIN) == 0) {
			/* Neither I nor O available... */
			cl_log(LOG_ERR
			,	"Async echoclient: bad events."
			" revents: 0x%x iter %d", pf[0].revents, rdcount);
			++errcount;
		}
	}
	cl_poll_ignore(rfd);
	cl_poll_ignore(wfd);
	chan->ops->waitout(chan);
	chan->ops->destroy(chan);  chan=NULL;
	cl_log(LOG_INFO, "Async echoclient: %d errors", errcount);
	return errcount;
}


struct iterinfo {
	int		wcount;
	int		rcount;
	int		errcount;
	IPC_Channel*	chan;
	int		max;
	gboolean	sendingsuspended;
};

static GMainLoop*	loop = NULL;

static gboolean
s_send_msg(gpointer data)
{
	struct iterinfo*i = data;
	IPC_Message*	wmsg;
	int		rc;
	
	/* Flow control? */
	if (i->chan->send_queue->current_qlen
	>=	i->chan->send_queue->max_qlen-2) {
		i->sendingsuspended = TRUE;
		return FALSE;
	}
	i->sendingsuspended = FALSE;
	++i->wcount;
	
	wmsg = newmessage(i->chan, i->wcount);
	//fprintf(stderr, "s");
	if ((rc = i->chan->ops->send(i->chan, wmsg)) != IPC_OK) {
		cl_log(LOG_ERR
		,	"s_send_msg: send failed"
		" %d rc iter %d"
		,	rc, i->wcount);
		cl_log(LOG_ERR
		,	"s_send_msg: channel status: %d qlen: %d"
		,	i->chan->ch_status
		,	i->chan->send_queue->current_qlen);
		++i->errcount;
	}
	return i->wcount <= i->max;
}

static gboolean
s_rcv_msg(IPC_Channel* chan, gpointer data)
{
	struct iterinfo*i = data;

	i->errcount += checkinput(chan, &i->rcount, i->max);

	if (i->sendingsuspended
	&&	!chan->ops->is_sending_blocked(chan)) {
		g_idle_add(s_send_msg, data);
	}

	if (chan->ch_status == IPC_DISCONNECT
	||	i->rcount >= i->max) {
		if (i->rcount < i->max) {
			++i->errcount;
		}
		g_main_quit(loop);
		return FALSE;
	}

	return TRUE;
}

static gboolean
s_echo_msg(IPC_Channel* chan, gpointer data)
{
	struct iterinfo*	i = data;
	int			rc;
	IPC_Message*		rmsg;

	while (chan->ops->is_message_pending(chan)) {
		if (chan->ch_status == IPC_DISCONNECT) {
			break;
		}
		if ((rc = chan->ops->recv(chan, &rmsg)) != IPC_OK) {
			cl_log(LOG_ERR
			,	"s_echo_msg: recv failed %d rc iter %d"
			" errno=%d"
			,	rc, i->rcount+1, errno);
			cl_perror("recv");
			++i->errcount;
			return TRUE;
		}
		i->rcount++;

		//fprintf(stderr, "c");
		if ((rc = chan->ops->send(chan, rmsg)) != IPC_OK) {
			cl_log(LOG_ERR
			,	"s_echo_msg: send failed %d rc iter %d qlen %d"
			,	rc, i->rcount, chan->send_queue->current_qlen);
			cl_perror("s_echo_msg:send");
			++i->errcount;
		}
	}
	//fprintf(stderr, "%%");
	if (i->rcount >= i->max || chan->ch_status == IPC_DISCONNECT) {
		chan->ops->waitout(chan);
		g_main_quit(loop);
	}
	return i->rcount < i->max;
}

static void
init_iterinfo(struct iterinfo * i, IPC_Channel* chan, int max)
{
	memset(i, 0, sizeof(*i));
	i->chan = chan;
	i->max = max;
}

static int
mainloop_server(IPC_Channel* chan, int repcount)
{
	struct iterinfo info;
	loop = g_main_new(FALSE);
	init_iterinfo(&info, chan, repcount);
	g_idle_add(s_send_msg, &info);
	G_main_add_IPC_Channel(G_PRIORITY_DEFAULT, chan
	,	FALSE, s_rcv_msg, &info, NULL);
	cl_log(LOG_INFO, "Mainloop echo server: %d reps pid %d.", repcount, (int)getpid());
	g_main_run(loop);
	g_main_destroy(loop);
	loop = NULL;
	cl_log(LOG_INFO, "Mainloop echo server: %d errors", info.errcount);
	return info.errcount;
}
static int
mainloop_client(IPC_Channel* chan, int repcount)
{
	struct iterinfo info;
	loop = g_main_new(FALSE);
	init_iterinfo(&info, chan, repcount);
	G_main_add_IPC_Channel(G_PRIORITY_DEFAULT, chan
	,	FALSE, s_echo_msg, &info, NULL);
	cl_log(LOG_INFO, "Mainloop echo client: %d reps pid %d.", repcount, (int)getpid());
	g_main_run(loop);
	g_main_destroy(loop);
	loop = NULL;
	cl_log(LOG_INFO, "Mainloop echo client: %d errors", info.errcount);
	return info.errcount;
}
