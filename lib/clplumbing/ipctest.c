/*
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

#undef _GNU_SOURCE  /* in case it was defined on the command line */
#define _GNU_SOURCE
#include <lha_internal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
/* libgen.h: for 'basename()' on Solaris */
#include <libgen.h>
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_poll.h>
#include <clplumbing/GSource.h>
#include <clplumbing/ipc.h>

#define	MAXERRORS	1000
#define	MAXERRORS_RECV	10

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
static gboolean checkmsg(IPC_Message* rmsg, const char * who, int rcount);

static const char *procname;

static const int iter_def = 10000;	/* number of iterations */
static int verbosity;			/* verbosity level */

/*
 * The ipc interface can be invoked as either:
 * 1. pair (pipe/socketpair);
 * 2. separate connect/accept (like server with multiple independent clients).
 *
 * If number of clients is given as 0, the "pair" mechanism is used,
 * otherwise the client/server mechanism.
 */
/* *** CLIENTS_MAX currently 1 while coding *** */
#define CLIENTS_MAX 1	/* max. number of independent clients */
static int clients_def;	/* number of independent clients */

static int
channelpair(TestFunc_t	clientfunc, TestFunc_t serverfunc, int count)
{
	IPC_Channel* channels[2];
	int		rc  = 0;
	int		waitstat = 0;

	if (verbosity >= 1) {
		cl_log(LOG_DEBUG, "%s[%d]%d: main process",
		  procname, (int)getpid(), __LINE__);
	}
	switch (fork()) {
		case -1:
			cl_perror("can't fork");
			exit(1);
			break;
		default: /* Parent */
			if (verbosity >= 1) {
				cl_log(LOG_DEBUG, "%s[%d]%d: main waiting...",
				  procname, (int)getpid(), __LINE__);
			}
			while (wait(&waitstat) > 0) {
				if (WIFEXITED(waitstat)) {
					rc += WEXITSTATUS(waitstat);
				}else{
					rc += 1;
				}
			}
			if (verbosity >= 1) {
				cl_log(LOG_DEBUG, "%s[%d]%d: main ended rc: %d",
				  procname, (int)getpid(), __LINE__, rc);
			}
			if (rc > 127) {
				rc = 127;
			}
			exit(rc);
			break;
		case 0:	/* Child */
			break;
	}
	/* Child continues here... */
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

		case 0:		/* echo "client" Child */
			channels[1]->ops->destroy(channels[1]);
			channels[1] = NULL;
			if (verbosity >= 1) {
				cl_log(LOG_DEBUG, "%s[%d]%d: client starting...",
				  procname, (int)getpid(), __LINE__);
			}
			rc = clientfunc(channels[0], count);
			if (verbosity >= 1) {
				cl_log(LOG_DEBUG, "%s[%d]%d: client ended rc:%d",
				  procname, (int)getpid(), __LINE__, rc);
			}
			exit (rc > 127 ? 127 : rc);
			break;

		default:
			break;
	}
	channels[0]->ops->destroy(channels[0]);
	channels[0] = NULL;
	if (verbosity >= 1) {
		cl_log(LOG_DEBUG, "%s[%d]%d: server starting...",
		  procname, (int)getpid(), __LINE__);
	}
	rc = serverfunc(channels[1], count);
	wait(&waitstat);
	if (WIFEXITED(waitstat)) {
		rc += WEXITSTATUS(waitstat);
	}else{
		rc += 1;
	}
	if (verbosity >= 1) {
		cl_log(LOG_DEBUG, "%s[%d]%d: server ended rc:%d",
		  procname, (int)getpid(), __LINE__, rc);
	}
	return(rc);
}

/* server with many clients */
static int
clientserver(TestFunc_t clientfunc, TestFunc_t serverfunc, int count, int clients)
{
	IPC_Channel* channel;
	int rc  = 0;
	int waitstat = 0;
	struct IPC_WAIT_CONNECTION *wconn;
	char path[] = IPC_PATH_ATTR;
	char commpath[] = "/tmp/foobar";	/* *** CHECK/FIX: Is this OK? */
	GHashTable * wattrs;
	int i;
	pid_t pid;

	if (verbosity >= 1) {
		cl_log(LOG_DEBUG, "%s[%d]%d: main process",
		  procname, (int)getpid(), __LINE__);
	}

	switch (fork()) {
		case -1:
			cl_perror("can't fork");
			exit(1);
			break;
		default: /* Parent */
			if (verbosity >= 1) {
				cl_log(LOG_DEBUG, "%s[%d]%d: main waiting...",
				  procname, (int)getpid(), __LINE__);
			}
			while ((pid = wait(&waitstat)) > 0) {
				if (WIFEXITED(waitstat)) {
					rc += WEXITSTATUS(waitstat);
				}else{
					rc += 1;
				}
			}
			if (verbosity >= 1) {
				cl_log(LOG_DEBUG, "%s[%d]%d: main ended rc: %d",
				  procname, (int)getpid(), __LINE__, rc);
			}
			if (rc > 127) {
				rc = 127;
			}
			exit(rc);
			break;
		case 0: /* Child */
			break;
	}

	if (verbosity >= 1) {
		cl_log(LOG_DEBUG, "%s[%d]%d:",
		  procname, (int)getpid(), __LINE__);
	}

	/* set up a server */
	wattrs = g_hash_table_new(g_str_hash, g_str_equal);
	if (! wattrs) {
		cl_perror("g_hash_table_new() failed");
		exit(1);
	}
	g_hash_table_insert(wattrs, path, commpath);

	if (verbosity >= 1) {
		cl_log(LOG_DEBUG, "%s[%d]%d:",
		  procname, (int)getpid(), __LINE__);
	}

	wconn = ipc_wait_conn_constructor(IPC_ANYTYPE, wattrs);
	if (! wconn) {
		cl_perror("could not establish server");
		exit(1);
	}

	if (verbosity >= 1) {
		cl_log(LOG_DEBUG, "%s[%d]%d:",
		  procname, (int)getpid(), __LINE__);
	}

	/* spawn the clients */
	for (i = 1; i <= clients; i++) {
		if (verbosity >= 1) {
			cl_log(LOG_DEBUG, "%s[%d]%d: fork client %d of %d",
			  procname, (int)getpid(), __LINE__, i, clients);
		}
		switch (fork()) {
			case -1:
				cl_perror("can't fork");
				exit(1);
				break;

			case 0:	/* echo "client" Child */
				if (verbosity >= 1) {
					cl_log(LOG_DEBUG, "%s[%d]%d: client %d starting...",
					  procname, (int)getpid(), __LINE__, i);
				}
				channel = ipc_channel_constructor(IPC_ANYTYPE, wattrs);
				if (channel == NULL) {
					cl_perror("client: channel creation failed");
					exit(1);
				}

				rc = channel->ops->initiate_connection(channel);
				if (rc != IPC_OK) {
					cl_perror("channel[1] failed to connect");
					exit(1);
				}
				checksock(channel);
				rc = clientfunc(channel, count);
				if (verbosity >= 1) {
					cl_log(LOG_DEBUG, "%s[%d]%d: client %d ended rc:%d",
					  procname, (int)getpid(), __LINE__, rc, i);
				}
				exit (rc > 127 ? 127 : rc);
				break;

			default:
				break;
		}
	}

	if (verbosity >= 1) {
		cl_log(LOG_DEBUG, "%s[%d]%d: server starting...",
		  procname, (int)getpid(), __LINE__);
	}
	/* accept on server */
	/* ***
	 * Two problems (or more) here:
	 * 1. What to do if no incoming call pending?
	 *    At present, fudge by sleeping a little so client gets started.
	 * 2. How to handle multiple clients?
	 *    Would need to be able to await both new connections and
	 *    data on existing connections.
	 *    At present, fudge CLIENTS_MAX as 1.
	 * ***
	 */
	sleep(1); /* *** */
	channel = wconn->ops->accept_connection(wconn, NULL);
	if (channel == NULL) {
		cl_perror("server: acceptance failed");
	}

	checksock(channel);

	rc = serverfunc(channel, count);

	/* server finished: tidy up */
	wconn->ops->destroy(wconn);

	if (verbosity >= 1) {
		cl_log(LOG_DEBUG, "%s[%d]%d: server ended rc:%d",
		  procname, (int)getpid(), __LINE__, rc);
	}

	/* reap the clients */
	for (i = 1; i <= clients; i++) {
		pid_t pid;

		pid = wait(&waitstat);
		if (verbosity >= 1) {
			cl_log(LOG_DEBUG, "%s[%d]%d: client %d reaped:%d",
			  procname, (int)getpid(), __LINE__,
			  (int) pid, WIFEXITED(waitstat));
		}
		if (WIFEXITED(waitstat)) {
			rc += WEXITSTATUS(waitstat);
		}else{
			rc += 1;
		}
	}

	return(rc);
}

static void
echomsgbody(void * body, int n, int niter, size_t * len)
{
	char *str = body;
	int l;

	l = snprintf(str, n-1, "String-%d", niter);
	if (l < (n-1)) {
		memset(&str[l], 'a', (n - (l+1)));
	}
	str[n-1] = '\0';
	*len = n;
}

static void
checkifblocked(IPC_Channel* chan)
{
	if (chan->ops->is_sending_blocked(chan)) {
		cl_log(LOG_INFO, "Sending is blocked.");
		chan->ops->resume_io(chan);
	}
}

#ifdef CHEAT_CHECKS
extern long	SeqNums[32];
#endif

static int
transport_tests(int iterations, int clients)
{
	int	rc = 0;

#ifdef CHEAT_CHECKS
	memset(SeqNums, 0, sizeof(SeqNums));
#endif
	rc += (clients <= 0)
	  ? channelpair(echoclient, echoserver, iterations)
	  : clientserver(echoclient, echoserver, iterations, clients);

#ifdef CHEAT_CHECKS
	memset(SeqNums, 0, sizeof(SeqNums));
#endif
	rc += (clients <= 0)
	  ? channelpair(asyn_echoclient, asyn_echoserver, iterations)
	  : clientserver(asyn_echoclient, asyn_echoserver, iterations, clients);

#ifdef CHEAT_CHECKS
	memset(SeqNums, 0, sizeof(SeqNums));
#endif
	rc += (clients <= 0)
	  ? channelpair(mainloop_client, mainloop_server, iterations)
	  : clientserver(mainloop_client, mainloop_server, iterations, clients);

	return rc;
}

static int data_size = 20;

int
main(int argc, char ** argv)
{
	int argflag, argerrs;
	int iterations;
	int clients;
	int	rc = 0;

	/*
	 * Check and process arguments.
	 *	-v: verbose
	 *	-i: number of iterations
	 *	-c: number of clients (invokes client/server mechanism)
	 *	-s: data-size
	 */
	procname = basename(argv[0]);

	argerrs = 0;
	iterations = iter_def;
	clients = clients_def;
	while ((argflag = getopt(argc, argv, "i:vuc:s:")) != EOF) {
		switch (argflag) {
		case 'i':	/* iterations */
			iterations = atoi(optarg);
			break;
		case 'v':	/* verbosity */
			verbosity++;
			break;
		case 'c':	/* number of clients */
			clients = atoi(optarg);
			if (clients < 1 || clients > CLIENTS_MAX) {
				fprintf(stderr, "number of clients out of range"
				  "(1 to %d)\n", CLIENTS_MAX);
				argerrs++;
			}
			break;
		case 's':	/* data size */
			data_size = atoi(optarg);
			if (data_size < 0) {
				fprintf(stderr, "data size must be >=0\n");
				argerrs++;
			}
			if (data_size > MAXMSG) {
				fprintf(stderr, "maximum data size is %d\n", MAXMSG);
				argerrs++;
			}
			break;
		default:
			argerrs++;
			break;
		}
	}
	if (argerrs) {
		fprintf(stderr,
		  "Usage: %s [-v] [-i iterations] [-c clients] [-s size]\n"
			"\t-v : verbose\n"
			"\t-i : iterations (default %d)\n"
			"\t-c : number of clients (default %d; nonzero invokes client/server)\n"
			"\t-s : data size (default 20 bytes)\n",
		  procname, iter_def, clients_def);
		exit(1);
	}

	cl_log_set_entity(procname);
	cl_log_enable_stderr(TRUE);



	rc += transport_tests(iterations, clients);

#if 0
	/* Broken for the moment - need to fix it long term */
	cl_log(LOG_INFO, "NOTE: Enabling poll(2) replacement code.");
	PollFunc = cl_poll;
	g_main_set_poll_func(cl_glibpoll);
	ipc_set_pollfunc(cl_poll);

	rc += transport_tests(5 * iterations, clients);
#endif
	
	cl_log(LOG_INFO, "TOTAL errors: %d", rc);

	return (rc > 127 ? 127 : rc);
}

static int
checksock(IPC_Channel* channel)
{

	if (!channel) {
		cl_log(LOG_ERR, "Channel null");
		return 1;
	}
	if (!IPC_ISRCONN(channel)) {
		cl_log(LOG_ERR, "Channel status is %d"
		", not IPC_CONNECT", channel->ch_status);
		return 1;
	}
	return 0;
}

static void
EOFcheck(IPC_Channel* chan)
{
	int		fd = chan->ops->get_recv_select_fd(chan);
	struct pollfd 	pf[1];
	int		rc;

	cl_log(LOG_INFO, "channel state: %d", chan->ch_status);

	if (chan->recv_queue->current_qlen > 0) {
		cl_log(LOG_INFO, "EOF Receive queue has %ld messages in it"
		,	(long)chan->recv_queue->current_qlen);
	}
	if (fd <= 0) {
		cl_log(LOG_INFO, "EOF receive fd: %d", fd);
	}


	pf[0].fd	= fd;
	pf[0].events	= POLLIN|POLLHUP;
	pf[0].revents	= 0;

	rc = poll(pf, 1, 0);

	if (rc < 0) {
		cl_perror("failed poll(2) call in EOFcheck");
		return;
	}

	/* Got input? */
	if (pf[0].revents & POLLIN) {
		cl_log(LOG_INFO, "EOF socket %d (still) has input ready (real poll)"
		,	fd);
	}
	if ((pf[0].revents & ~(POLLIN|POLLHUP)) != 0) {
		cl_log(LOG_INFO, "EOFcheck poll(2) bits: 0x%lx"
		,	(unsigned long)pf[0].revents);
	}
	pf[0].fd	= fd;
	pf[0].events	= POLLIN|POLLHUP;
	pf[0].revents	= 0;
	rc = PollFunc(pf, 1, 0);
	if (rc < 0) {
		cl_perror("failed PollFunc() call in EOFcheck");
		return;
	}

	/* Got input? */
	if (pf[0].revents & POLLIN) {
		cl_log(LOG_INFO, "EOF socket %d (still) has input ready (PollFunc())"
		,	fd);
	}
	if ((pf[0].revents & ~(POLLIN|POLLHUP)) != 0) {
		cl_log(LOG_INFO, "EOFcheck PollFunc() bits: 0x%lx"
		,	(unsigned long)pf[0].revents);
	}
}

static int
echoserver(IPC_Channel* wchan, int repcount)
{
	char	*str;
	int	j;
	int	errcount = 0;
	IPC_Message	wmsg;
	IPC_Message*	rmsg = NULL;
	
	if (!(str = malloc(data_size))) {
		cl_log(LOG_ERR, "Out of memory");
		exit(1);
	}
	
	memset(&wmsg, 0, sizeof(wmsg));
	wmsg.msg_private = NULL;
	wmsg.msg_done = NULL;
	wmsg.msg_body = str;
	wmsg.msg_buf = NULL;
	wmsg.msg_ch = wchan;

	cl_log(LOG_INFO, "Echo server: %d reps pid %d.", repcount, getpid());
	for (j=1; j <= repcount
	;++j, rmsg != NULL && (rmsg->msg_done(rmsg),1)) {
		int	rc;

		echomsgbody(str, data_size, j, &(wmsg.msg_len));
		if ((rc = wchan->ops->send(wchan, &wmsg)) != IPC_OK) {
			cl_log(LOG_ERR
			,	"echotest: send failed %d rc iter %d"
			,	rc, j);
			++errcount;
			continue;
		}

		/*fprintf(stderr, "+"); */
		wchan->ops->waitout(wchan);
		checkifblocked(wchan);
		/*fprintf(stderr, "S"); */

		/* Try and induce a failure... */
		if (j == repcount) {
			sleep(1);
		}

		while ((rc = wchan->ops->waitin(wchan)) == IPC_INTR);
		
		if (rc != IPC_OK) {
			cl_log(LOG_ERR
			,	"echotest server: waitin failed %d rc iter %d"
			" errno=%d"
			,	rc, j, errno);
			cl_perror("waitin");
			exit(1);
		}

		/*fprintf(stderr, "-"); */
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
		/*fprintf(stderr, "s"); */
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
	cl_log(LOG_INFO, "echoserver: %d errors", errcount);
#if 0
	cl_log(LOG_INFO, "destroying channel 0x%lx", (unsigned long)wchan);
#endif
	wchan->ops->destroy(wchan); wchan = NULL;

	free(str);

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

		while ((rc = rchan->ops->waitin(rchan)) == IPC_INTR);
		
		if (rc != IPC_OK) {
			cl_log(LOG_ERR
			,	"echotest client: waitin failed %d rc iter %d"
			" errno=%d"
			,	rc, j, errno);
			cl_perror("waitin");
			exit(1);
		}
		/*fprintf(stderr, "/"); */

		if ((rc = rchan->ops->recv(rchan, &rmsg)) != IPC_OK) {
			cl_log(LOG_ERR
			,	"echoclient: recv failed %d rc iter %d"
			" errno=%d"
			,	rc, j, errno);
			cl_perror("recv");
			++errcount;
			if (errcount > MAXERRORS_RECV) {
				cl_log(LOG_ERR,
				  "echoclient: errcount excessive: %d: abandoning",
				  errcount);
				exit(1);
			}
			--j;
			rmsg=NULL;
			continue;
		}
		/*fprintf(stderr, "c"); */
		if ((rc = rchan->ops->send(rchan, rmsg)) != IPC_OK) {
			cl_log(LOG_ERR
			,	"echoclient: send failed %d rc iter %d"
			,	rc, j);
			cl_log(LOG_INFO, "Message being sent: %s"
			,		(char*)rmsg->msg_body);
			++errcount;
			continue;
		}
		/*fprintf(stderr, "%%"); */
		rchan->ops->waitout(rchan);
		checkifblocked(rchan);
		/*fprintf(stderr, "C"); */
	}
	cl_log(LOG_INFO, "echoclient: %d errors", errcount);
#if 0
	cl_log(LOG_INFO, "destroying channel 0x%lx", (unsigned long)rchan);
#endif
	rchan->ops->destroy(rchan); rchan = NULL;
	return errcount;
}

void dump_ipc_info(IPC_Channel* chan);

static int
checkinput(IPC_Channel* chan, const char * where, int* rdcount, int maxcount)
{
	IPC_Message*	rmsg = NULL;
	int		errs = 0;
	int		rc;

	while (chan->ops->is_message_pending(chan)
	&&	errs < 10 && *rdcount < maxcount) {

		if (chan->ch_status == IPC_DISCONNECT && *rdcount < maxcount){
			cl_log(LOG_ERR
			,	"checkinput1[0x%lx %s]: EOF in iter %d"
			,	(unsigned long)chan, where, *rdcount);
			EOFcheck(chan);
		}

		if (rmsg != NULL) {
			rmsg->msg_done(rmsg);
			rmsg = NULL;
		}

		if ((rc = chan->ops->recv(chan, &rmsg)) != IPC_OK) {
			if (chan->ch_status == IPC_DISCONNECT) {
				cl_log(LOG_ERR
				,	"checkinput2[0x%lx %s]: EOF in iter %d"
				,	(unsigned long)chan, where, *rdcount);
				EOFcheck(chan);
				return errs;
			}
			cl_log(LOG_ERR
			,	"checkinput[%s]: recv"
			" failed: rc %d  rdcount %d errno=%d"
			,	where, rc, *rdcount, errno);
			cl_perror("recv");
			rmsg=NULL;
			++errs;
			continue;
		}
		*rdcount += 1;
		if (!checkmsg(rmsg, where, *rdcount)) {
			dump_ipc_info(chan);
			++errs;
		}
		if (*rdcount < maxcount && chan->ch_status == IPC_DISCONNECT){
			cl_log(LOG_ERR
			,	"checkinput3[0x%lx %s]: EOF in iter %d"
			,	(unsigned long)chan, where, *rdcount);
			EOFcheck(chan);
		}

	}
	return errs;
}

static void
async_high_flow_callback(IPC_Channel* ch, void* userdata)
{
	int* stopsending = userdata;
	
	if (userdata == NULL){
		cl_log(LOG_ERR, "userdata is NULL");
		return;
	}
	
	*stopsending = 1;
	
}

static void
async_low_flow_callback(IPC_Channel* ch, void* userdata)
{

	int* stopsending = userdata;
	
	if (userdata == NULL){
		cl_log(LOG_ERR, "userdata is NULL");
		return;
	}

	*stopsending = 0;
	
}


static int
asyn_echoserver(IPC_Channel* wchan, int repcount)
{
	int		rdcount = 0;
	int		wrcount = 0;
	int		errcount = 0;
	int		blockedcount = 0;
	IPC_Message*	wmsg;
	const char*	w = "asyn_echoserver";
	int		stopsending = 0;

	cl_log(LOG_INFO, "Asyn echo server: %d reps pid %d."
	,	repcount, (int)getpid());
	
	(void)async_high_flow_callback;
	(void)async_low_flow_callback;
	
	
	wchan->ops->set_high_flow_callback(wchan, async_high_flow_callback, &stopsending);
	wchan->ops->set_low_flow_callback(wchan, async_low_flow_callback, &stopsending);
	  
	wchan->low_flow_mark = 2;
	wchan->high_flow_mark = 20;
	
	while (rdcount < repcount) {
		int	rc;
		
		while (wrcount < repcount && blockedcount < 10
		       && wchan->ch_status != IPC_DISCONNECT 
		       ){
			
			if (!stopsending){
				++wrcount;
				if (wrcount > repcount) {
					break;
				}
				wmsg = wchan->ops->new_ipcmsg(wchan, NULL, data_size, NULL);
				echomsgbody(wmsg->msg_body, data_size, wrcount, &wmsg->msg_len);
				if ((rc = wchan->ops->send(wchan, wmsg)) != IPC_OK){
					
					cl_log(LOG_INFO, "channel sstatus in echo server is %d",
					       wchan->ch_status);
					if (wchan->ch_status != IPC_CONNECT) {
						cl_log(LOG_ERR
						       ,	"asyn_echoserver: send failed"
						       " %d rc iter %d"
						       ,	rc, wrcount);
						++errcount;
						continue;
					}else {/*send failed because of channel busy
						* roll back
						*/
						--wrcount;
					}				
				}
				
				if (wchan->ops->is_sending_blocked(wchan)) {
					/* fprintf(stderr, "b"); */
					++blockedcount;
				}else{
					blockedcount = 0;
				}
			}
			
			
			errcount += checkinput(wchan, w, &rdcount, repcount);
			if (wrcount < repcount
			    &&	wchan->ch_status == IPC_DISCONNECT) {
				++errcount;
				break;
			}
		}
		
/*  		cl_log(LOG_INFO, "async_echoserver: wrcount =%d rdcount=%d B", wrcount, rdcount); */

		wchan->ops->waitout(wchan);
		errcount += checkinput(wchan, w, &rdcount, repcount);
		if (wrcount >= repcount && rdcount < repcount) {
			while ((rc = wchan->ops->waitin(wchan)) == IPC_INTR);
			
			if (rc != IPC_OK) {
				cl_log(LOG_ERR
				       ,	"asyn_echoserver: waitin()"
				       " failed %d rc rdcount %d errno=%d"
				,	rc, rdcount, errno);
				cl_perror("waitin");
				exit(1);
			}
		}
		if (wchan->ch_status == IPC_DISCONNECT
		    &&	rdcount < repcount) {
			cl_log(LOG_ERR,
			       "asyn_echoserver: EOF in iter %d (wrcount=%d)",
			       rdcount, wrcount);
			EOFcheck(wchan);
			++errcount;
			break;
		}

		blockedcount = 0;

	}

	cl_log(LOG_INFO, "asyn_echoserver: %d errors", errcount);
#if 0
	cl_log(LOG_INFO, "%d destroying channel 0x%lx", getpid(), (unsigned long)wchan);
#endif
	wchan->ops->destroy(wchan); wchan = NULL;
	return errcount;
}

static int
asyn_echoclient(IPC_Channel* chan, int repcount)
{
	int		rdcount = 0;
	int		wrcount = 0;
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
		/* fprintf(stderr, "i"); */
		while (chan->ops->is_message_pending(chan)
		&&	rdcount < repcount) {
			/*fprintf(stderr, "r"); */

			if ((rc = chan->ops->recv(chan, &rmsg)) != IPC_OK) {
				if (!IPC_ISRCONN(chan)) {
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
			/*fprintf(stderr, "c"); */
			++rdcount;

			
			do {
				rc = chan->ops->send(chan, rmsg);
				
			}while (rc != IPC_OK && chan->ch_status == IPC_CONNECT);

			if (chan->ch_status !=  IPC_CONNECT){
				++errcount;
				cl_perror("send");
				cl_log(LOG_ERR
				       ,	"Async echoclient: send failed"
				       " rc %d, iter %d", rc, rdcount);
				cl_log(LOG_INFO, "Message being sent: %s"
				       ,		(char*)rmsg->msg_body);
				if (!IPC_ISRCONN(chan)) {
					cl_log(LOG_ERR
					       ,	"Async echoclient: EOF(2)"
					       " iter %d", rdcount+1);
					EOFcheck(chan);
					return errcount;
				}
				continue;
				
			}

			
			++wrcount;
			/*fprintf(stderr, "x"); */
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

		/*
		  fprintf(stderr, "P");
		  cl_log(LOG_INFO, "poll[%d, 0x%x]"
		  ,	pf[0].fd, pf[0].events);
		  cl_log(LOG_DEBUG, "poll[%d, 0x%x]..."
		  ,	pf[0].fd, pf[0].events);
		  fprintf(stderr, "%%");
		  cl_log(LOG_DEBUG, "CallingPollFunc()");
		*/
		rc = PollFunc(pf, nfd, -1);

		/* Bad poll? */
		if (rc <= 0) {
			cl_perror("Async echoclient: bad poll rc."
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
			EOFcheck(chan);
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
			/*fprintf(stderr, "R");*/
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
	cl_log(LOG_INFO, "Async echoclient: %d errors, %d reads, %d writes",
	       errcount, rdcount, wrcount);
#if 0
	cl_log(LOG_INFO, "%d destroying channel 0x%lx",getpid(), (unsigned long)chan);
#endif

	
	chan->ops->waitout(chan);

	chan->ops->destroy(chan); chan = NULL;
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
	
	++i->wcount;
	
	wmsg = i->chan->ops->new_ipcmsg(i->chan, NULL, data_size, NULL);
	echomsgbody(wmsg->msg_body, data_size, i->wcount, &wmsg->msg_len);
	
	/*cl_log(LOG_INFO, "s_send_msg: sending out %d", i->wcount);*/
	
	if ((rc = i->chan->ops->send(i->chan, wmsg)) != IPC_OK) {
		cl_log(LOG_ERR
		,	"s_send_msg: send failed"
		" %d rc iter %d"
		,	rc, i->wcount);
		cl_log(LOG_ERR
		,	"s_send_msg: channel status: %d qlen: %ld"
		,	i->chan->ch_status
		,	(long)i->chan->send_queue->current_qlen);
		++i->errcount;
		if (i->chan->ch_status != IPC_CONNECT) {
			cl_log(LOG_ERR,	"s_send_msg: Exiting.");
			return FALSE;
		}
		if (i->errcount >= MAXERRORS) {
			g_main_quit(loop);
			return FALSE;
		}
	}
	return !i->sendingsuspended?i->wcount < i->max: FALSE;
}




static void
mainloop_low_flow_callback(IPC_Channel* ch, void* userdata)
{
	
	struct iterinfo* i = (struct iterinfo*) userdata;
	
	if (userdata == NULL){
		cl_log(LOG_ERR, "userdata is NULL");
		return;
	}
	
	if (i->sendingsuspended){
		i->sendingsuspended = FALSE;
		g_idle_add(s_send_msg, i);
	}
	
	return;
	
}

static void
mainloop_high_flow_callback(IPC_Channel* ch, void* userdata)
{
	struct iterinfo* i = (struct iterinfo*) userdata;
	
	if (userdata == NULL){
		cl_log(LOG_ERR, "userdata is NULL");
		return;
	}
	
	i->sendingsuspended = TRUE;
	
}


static gboolean
s_rcv_msg(IPC_Channel* chan, gpointer data)
{
	struct iterinfo*i = data;

	i->errcount += checkinput(chan, "s_rcv_msg", &i->rcount, i->max);
	
	if (chan->ch_status == IPC_DISCONNECT
	||	i->rcount >= i->max || i->errcount > MAXERRORS) {
		if (i->rcount < i->max) {
			++i->errcount;
			cl_log(LOG_INFO, "Early exit from s_rcv_msg");
		}
		g_main_quit(loop);
		return FALSE;
	}

	return TRUE;
}

static gboolean
checkmsg(IPC_Message* rmsg, const char * who, int rcount)
{
	char		*str;
	size_t		len;
	
	if (!(str = malloc(data_size))) {
		cl_log(LOG_ERR, "Out of memory");
		exit(1);
	}

	echomsgbody(str, data_size, rcount, &len);

	if (rmsg->msg_len != len) {
		cl_log(LOG_ERR
		,	"checkmsg[%s]: length mismatch"
		" [expected %u, got %lu] iteration %d"
		,	who, (unsigned)len
		,	(unsigned long)rmsg->msg_len
		,	rcount);
		cl_log(LOG_ERR
		,	"checkmsg[%s]: expecting [%s]"
		,	who, str);
		cl_log(LOG_ERR
		,	"checkmsg[%s]: got [%s] instead"
		,	who, (const char *)rmsg->msg_body);
		return FALSE;
	}
	if (strncmp(rmsg->msg_body, str, len) != 0) {
		cl_log(LOG_ERR
		,	"checkmsg[%s]: data mismatch"
		". input iteration %d"
		,	who, rcount);
		cl_log(LOG_ERR
		,	"checkmsg[%s]: expecting [%s]"
		,	who, str);
		cl_log(LOG_ERR
		,	"checkmsg[%s]: got [%s] instead"
		,	who, (const char *)rmsg->msg_body);
		return FALSE;
#if 0
	}else if (strcmp(who, "s_rcv_msg") == 0) {
#if 0

	||	strcmp(who, "s_echo_msg") == 0) {
#endif
		cl_log(LOG_ERR
		,	"checkmsg[%s]: data Good"
		"! input iteration %d"
		,	who, rcount);
#endif
	}

	free(str);

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
			goto retout;
		}
		i->rcount++;
		if (!checkmsg(rmsg, "s_echo_msg", i->rcount)) {
			++i->errcount;
		}

		
		
		/*cl_log(LOG_INFO, "s_echo_msg: rcount= %d, wcount =%d", i->rcount, i->wcount);*/
		
		
		do {
			rc = chan->ops->send(chan, rmsg);
			
		}while (rc != IPC_OK && chan->ch_status == IPC_CONNECT);
		
		if (chan->ch_status !=  IPC_CONNECT){
			cl_log(LOG_ERR,
			       "s_echo_msg: send failed %d rc iter %d qlen %ld",
			       rc, i->rcount, (long)chan->send_queue->current_qlen);
			cl_perror("send");
			i->errcount ++;
			
		}
		
		i->wcount+=1;
		/*cl_log(LOG_INFO, "s_echo_msg: end of this ite");*/
	}
 retout:
	/*fprintf(stderr, "%%");*/
	if (i->rcount >= i->max || chan->ch_status == IPC_DISCONNECT
	    ||	i->errcount > MAXERRORS) {
		chan->ops->waitout(chan);
		g_main_quit(loop);
		return FALSE;
	}
	return TRUE;
}

static void
init_iterinfo(struct iterinfo * i, IPC_Channel* chan, int max)
{
	memset(i, 0, sizeof(*i));
	i->chan = chan;
	i->max = max;
	i->sendingsuspended = FALSE;
}

static int
mainloop_server(IPC_Channel* chan, int repcount)
{
	struct iterinfo info;
	guint		sendmsgsrc;

	

	loop = g_main_new(FALSE);
	init_iterinfo(&info, chan, repcount);

	chan->ops->set_high_flow_callback(chan, mainloop_high_flow_callback, &info);
	chan->ops->set_low_flow_callback(chan, mainloop_low_flow_callback, &info);
	chan->high_flow_mark = 20;
	chan->low_flow_mark = 2;

	sendmsgsrc = g_idle_add(s_send_msg, &info);
	G_main_add_IPC_Channel(G_PRIORITY_DEFAULT, chan
	,	FALSE, s_rcv_msg, &info, NULL);
	cl_log(LOG_INFO, "Mainloop echo server: %d reps pid %d.", repcount, (int)getpid());
	g_main_run(loop);
	g_main_destroy(loop);
	g_source_remove(sendmsgsrc);
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
	cl_log(LOG_INFO, "Mainloop echo client: %d errors, %d read %d written"
	,	info.errcount, info.rcount, info.wcount);
	return info.errcount;
}
