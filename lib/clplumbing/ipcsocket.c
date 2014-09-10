/*
 * ipcsocket unix domain socket implementation of IPC abstraction.
 *
 * Copyright (c) 2002 Xiaoxiang Liu <xiliu@ncsa.uiuc.edu>
 *
 * Stream support (c) 2004,2006 David Lee <t.d.lee@durham.ac.uk>
 *	Note: many of the variable/function names "*socket*" should be
 *	interpreted as having a more generic "ipc-channel-type" meaning.
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

#include <lha_internal.h>

#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/realtime.h>
#include <clplumbing/cl_poll.h>

#include <ha_msg.h>
/* avoid including cib.h - used in gshi's "late message" code to avoid
 *   printing insanely large messages
 */
#define F_CIB_CALLDATA  "cib_calldata"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/uio.h>
#ifdef HAVE_SYS_FILIO_H
#	include <sys/filio.h>
#endif
#ifdef HAVE_SYS_SYSLIMITS_H
#	include <sys/syslimits.h>
#endif
#ifdef HAVE_SYS_CRED_H
#	include <sys/cred.h>
#endif
#ifdef HAVE_SYS_UCRED_H
#	include <sys/ucred.h>
#endif

/* For 'getpeerucred()' (Solaris 10 upwards) */
#ifdef HAVE_UCRED_H
#	include <ucred.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

/*
 * Normally use "socket" code.  But on some OSes alternatives may be
 * preferred (or necessary).
 */
#define HB_IPC_SOCKET	1
#define HB_IPC_STREAM	2
/* #define HB_IPC_ANOTHER	3 */

#ifndef HB_IPC_METHOD
# if defined(SO_PEERCRED) || defined(HAVE_GETPEEREID) \
	|| defined(SCM_CREDS) || defined(HAVE_GETPEERUCRED)
#  define HB_IPC_METHOD	HB_IPC_SOCKET
# elif defined(HAVE_STROPTS_H)
#  define HB_IPC_METHOD	HB_IPC_STREAM
# else
#  error.  Surely we have sockets or streams...
# endif
#endif

#if HB_IPC_METHOD == HB_IPC_SOCKET
# include <sys/poll.h>
# include <netinet/in.h>
# include <sys/un.h>
#elif HB_IPC_METHOD == HB_IPC_STREAM
# include <stropts.h>
#else
# error "IPC type invalid"
#endif

#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#ifndef UNIX_PATH_MAX
#	define UNIX_PATH_MAX 108
#endif

#if HB_IPC_METHOD == HB_IPC_SOCKET

# define MAX_LISTEN_NUM 128

# ifndef MSG_NOSIGNAL
#  define		MSG_NOSIGNAL	0
# endif

# ifndef AF_LOCAL
#  define         AF_LOCAL AF_UNIX
# endif

#endif /* HB_IPC_METHOD */

/***********************************************************************
 *
 * Determine the IPC authentication scheme...  More machine dependent than
 * we'd like, but don't know any better way...
 *
 ***********************************************************************/
#ifdef SO_PEERCRED
#	define	USE_SO_PEERCRED
#elif HAVE_GETPEEREID
#	define USE_GETPEEREID
#elif defined(SCM_CREDS)
#	define	USE_SCM_CREDS
#elif HAVE_GETPEERUCRED		/* e.g. Solaris 10 upwards */
#	define USE_GETPEERUCRED
#elif HB_IPC_METHOD == HB_IPC_STREAM
#	define USE_STREAM_CREDS
#else
#	define	USE_DUMMY_CREDS
/* This will make it compile, but attempts to authenticate
 * will fail.  This is a stopgap measure ;-)
 */
#endif

#if HB_IPC_METHOD == HB_IPC_SOCKET

# ifdef USE_BINDSTAT_CREDS
# ifndef SUN_LEN
#    define SUN_LEN(ptr) ((size_t) (offsetof (sockaddr_un, sun_path) + strlen ((ptr)->sun_path))
# endif
# endif

#endif /* HB_IPC_METHOD */

/* wait connection private data. */
struct SOCKET_WAIT_CONN_PRIVATE{
  /* the path name wich the connection will be built on. */
  char path_name[UNIX_PATH_MAX];
#if HB_IPC_METHOD == HB_IPC_SOCKET
  /* the domain socket. */
  int s;
#elif HB_IPC_METHOD == HB_IPC_STREAM
  /* the streams pipe */
  int pipefds[2];
#endif
};

/* channel private data. */
struct SOCKET_CH_PRIVATE{
  /* the path name wich the connection will be built on. */
  char path_name[UNIX_PATH_MAX];
  /* the domain socket. */
  int s;
  /* the size of expecting data for below buffered message buf_msg */
  int remaining_data;

#if HB_IPC_METHOD == HB_IPC_SOCKET
  /* The address of our peer - used by USE_BINDSTAT_CREDS version of
   *   socket_verify_auth()
   */
  struct sockaddr_un *peer_addr;
#elif HB_IPC_METHOD == HB_IPC_STREAM
  uid_t farside_uid;
  gid_t farside_gid;
#endif

  /* the buf used to save unfinished message */
  struct IPC_MESSAGE *buf_msg;
};

struct IPC_Stats {
	long	nsent;
	long	noutqueued;
	long	send_count;
	long	nreceived;
	long	ninqueued;
	long	recv_count;
	int	last_recv_errno;
	int	last_recv_rc;
	int	last_send_errno;
	int	last_send_rc;
};

static struct IPC_Stats SocketIPCStats = {0, 0, 0, 0};
extern int	debug_level;

/* unix domain socket implementations of IPC functions. */

static int socket_resume_io(struct IPC_CHANNEL *ch);

static struct IPC_MESSAGE* socket_message_new(struct IPC_CHANNEL*ch
,	int msg_len);

struct IPC_WAIT_CONNECTION *socket_wait_conn_new(GHashTable* ch_attrs);

/* *** FIXME: This is also declared in 'ocf_ipc.c'. */
struct IPC_CHANNEL* socket_client_channel_new(GHashTable *attrs);

static struct IPC_CHANNEL* socket_server_channel_new(int sockfd);

static struct IPC_CHANNEL * channel_new(int sockfd, int conntype, const char *pathname);
static int client_channel_new_auth(int sockfd);
static int verify_creds(struct IPC_AUTH *auth_info, uid_t uid, gid_t gid);

typedef void (*DelProc)(IPC_Message*);

static struct IPC_MESSAGE * ipcmsg_new(struct IPC_CHANNEL* ch,
  const void* data, int len, void* private, DelProc d);

static pid_t socket_get_farside_pid(int sockfd);

extern int (*ipc_pollfunc_ptr)(struct pollfd *, nfds_t, int);

static int socket_resume_io_read(struct IPC_CHANNEL *ch, int*, gboolean read1anyway);

static struct IPC_OPS socket_ops;
static gboolean ipc_time_debug_flag = TRUE;

void
set_ipc_time_debug_flag(gboolean flag)
{
	ipc_time_debug_flag = flag;
}

#ifdef IPC_TIME_DEBUG

extern struct ha_msg* wirefmt2msg(const char* s, size_t length, int flag);
void cl_log_message (int log_level, const struct ha_msg *m);
int timediff(longclock_t t1, longclock_t t2);
void   ha_msg_del(struct ha_msg* msg);
void	ipc_time_debug(IPC_Channel* ch, IPC_Message* ipcmsg, int whichpos);

#define SET_ENQUEUE_TIME(x,t)	memcpy(&((struct SOCKET_MSG_HEAD*)x->msg_buf)->enqueue_time, &t, sizeof(longclock_t))
#define SET_SEND_TIME(x,t)	memcpy(&((struct SOCKET_MSG_HEAD*)x->msg_buf)->send_time, &t, sizeof(longclock_t))
#define SET_RECV_TIME(x,t)	memcpy(&((struct SOCKET_MSG_HEAD*)x->msg_buf)->recv_time, &t, sizeof(longclock_t))
#define SET_DEQUEUE_TIME(x,t)	memcpy(&((struct SOCKET_MSG_HEAD*)x->msg_buf)->dequeue_time, &t, sizeof(longclock_t))

static
longclock_t
get_enqueue_time(IPC_Message *ipcmsg)
{
	longclock_t t;

	memcpy(&t,
	  &(((struct SOCKET_MSG_HEAD *)ipcmsg->msg_buf)->enqueue_time),
	  sizeof(longclock_t));

	return t;
}

int
timediff(longclock_t t1, longclock_t t2)
{
	longclock_t	remain;

	remain = sub_longclock(t1, t2);

	return longclockto_ms(remain);
}

void
ipc_time_debug(IPC_Channel* ch, IPC_Message* ipcmsg, int whichpos)
{
	int msdiff = 0;
	longclock_t lnow =  time_longclock();
	char positions[4][16]={
		"enqueue",
		"send",
		"recv",
		"dequeue"};

	if (ipc_time_debug_flag == FALSE) {
		return ;
	}

	if (ipcmsg->msg_body == NULL
	    || ipcmsg->msg_buf == NULL) {
		cl_log(LOG_ERR, "msg_body =%p, msg_bu=%p",
		       ipcmsg->msg_body, ipcmsg->msg_buf);
		abort();
		return;
	}

	switch(whichpos) {
		case MSGPOS_ENQUEUE:
			SET_ENQUEUE_TIME(ipcmsg, lnow);
			break;
		case MSGPOS_SEND:
			SET_SEND_TIME(ipcmsg, lnow);
			goto checktime;
		case MSGPOS_RECV:
			SET_RECV_TIME(ipcmsg, lnow);
			goto checktime;
		case MSGPOS_DEQUEUE:
			SET_DEQUEUE_TIME(ipcmsg, lnow);

	checktime:
			msdiff = timediff(lnow, get_enqueue_time(ipcmsg));
			if (msdiff > MAXIPCTIME) {
				struct ha_msg* hamsg = NULL;
				cl_log(LOG_WARNING,
				       " message delayed from enqueue to %s %d ms "
				       "(enqueue-time=%lu, peer pid=%d) ",
				       positions[whichpos],
				       msdiff,
				       longclockto_ms(get_enqueue_time(ipcmsg)),
				       ch->farside_pid);

				(void)hamsg;
#if 0
				hamsg = wirefmt2msg(ipcmsg->msg_body, ipcmsg->msg_len, 0);
				if (hamsg != NULL) {
					struct ha_msg *crm_data = NULL;
					crm_data = cl_get_struct(
						hamsg, F_CRM_DATA);

					if(crm_data == NULL) {
						crm_data = cl_get_struct(
							hamsg, F_CIB_CALLDATA);
					}
					if(crm_data != NULL) {
						cl_msg_remove_value(
							hamsg, crm_data);
					}

					cl_log_message(LOG_DEBUG, hamsg);
					ha_msg_del(hamsg);
				} else {
					if (!ipcmsg) {
						cl_log(LOG_ERR,
						"IPC msg 0x%lx is unallocated"
						,	(gulong)ipcmsg);
						return;
					}
					if (!ipcmsg->msg_body) {
						cl_log(LOG_ERR,
						"IPC msg body 0x%lx is unallocated"
						,	(gulong)ipcmsg->msg_body);
						return;
					}
				}
#endif

			}
			break;
		default:
			cl_log(LOG_ERR, "wrong position value in IPC:%d", whichpos);
			return;
	}
}
#endif

void dump_ipc_info(const IPC_Channel* chan);

#undef AUDIT_CHANNELS

#ifndef AUDIT_CHANNELS
#	define	CHANAUDIT(ch)	/*NOTHING */
#else
#	define CHANAUDIT(ch)	socket_chan_audit(ch)
#	define MAXPID	65535

static void
socket_chan_audit(const struct IPC_CHANNEL* ch)
{
	int	badch = FALSE;

  	struct SOCKET_CH_PRIVATE *chp;
	struct stat		b;

	if ((chp = ch->ch_private) == NULL) {
		cl_log(LOG_CRIT, "Bad ch_private");
		badch = TRUE;
	}
	if (ch->ops != &socket_ops) {
		cl_log(LOG_CRIT, "Bad socket_ops");
		badch = TRUE;
	}
	if (ch->ch_status == IPC_DISCONNECT) {
		return;
	}
	if (!IPC_ISRCONN(ch)) {
		cl_log(LOG_CRIT, "Bad ch_status [%d]", ch->ch_status);
		badch = TRUE;
	}
	if (ch->farside_pid < 0 || ch->farside_pid > MAXPID) {
		cl_log(LOG_CRIT, "Bad farside_pid");
		badch = TRUE;
	}
	if (fstat(chp->s, &b) < 0) {
		badch = TRUE;
	} else if ((b.st_mode & S_IFMT) != S_IFSOCK) {
		cl_log(LOG_CRIT, "channel @ 0x%lx: not a socket"
		,	(unsigned long)ch);
		badch = TRUE;
	}
	if (chp->remaining_data < 0) {
		cl_log(LOG_CRIT, "Negative remaining_data");
		badch = TRUE;
	}
	if (chp->remaining_data < 0 || chp->remaining_data > MAXMSG) {
		cl_log(LOG_CRIT, "Excessive/bad remaining_data");
		badch = TRUE;
	}
	if (chp->remaining_data && chp->buf_msg == NULL) {
		cl_log(LOG_CRIT
		,	"inconsistent remaining_data [%ld]/buf_msg[0x%lx]"
		,	(long)chp->remaining_data, (unsigned long)chp->buf_msg);
		badch = TRUE;
	}
	if (chp->remaining_data == 0 && chp->buf_msg != NULL) {
		cl_log(LOG_CRIT
		,	"inconsistent remaining_data [%ld]/buf_msg[0x%lx] (2)"
		,	(long)chp->remaining_data, (unsigned long)chp->buf_msg);
		badch = TRUE;
	}
	if (ch->send_queue == NULL || ch->recv_queue == NULL) {
		cl_log(LOG_CRIT, "bad send/recv queue");
		badch = TRUE;
	}
	if (ch->recv_queue->current_qlen < 0
	||	ch->recv_queue->current_qlen > ch->recv_queue->max_qlen) {
		cl_log(LOG_CRIT, "bad recv queue");
		badch = TRUE;
	}
	if (ch->send_queue->current_qlen < 0
	||	ch->send_queue->current_qlen > ch->send_queue->max_qlen) {
		cl_log(LOG_CRIT, "bad send_queue");
		badch = TRUE;
	}
	if (badch) {
		cl_log(LOG_CRIT, "Bad channel @ 0x%lx", (unsigned long)ch);
		dump_ipc_info(ch);
		abort();
	}
}
#endif

#ifdef CHEAT_CHECKS
long	SeqNums[32];

static long
cheat_get_sequence(IPC_Message* msg)
{
	const char header [] = "String-";
	size_t header_len = sizeof(header)-1;
	char *	body;

	if (msg == NULL || msg->msg_len < sizeof(header)
	||	msg->msg_len > sizeof(header) + 10
	||	strncmp(msg->msg_body, header, header_len) != 0) {
		return -1L;
	}
	body = msg->msg_body;
	return atol(body+header_len);
}
static char SavedReadBody[32];
static char SavedReceivedBody[32];
static char SavedQueuedBody[32];
static char SavedSentBody[32];
#ifndef MIN
#	define MIN(a,b)	(a < b ? a : b)
#endif

static void
save_body(struct IPC_MESSAGE *msg, char * savearea, size_t length)
{
	int mlen = strnlen(msg->msg_body, MIN(length, msg->msg_len));
	memcpy(savearea, msg->msg_body, mlen);
	savearea[mlen] = EOS;
}

static void
audit_readmsgq_msg(gpointer msg, gpointer user_data)
{
	long	cheatseq = cheat_get_sequence(msg);

	if (cheatseq < SeqNums[1] || cheatseq > SeqNums[2]) {
		cl_log(LOG_ERR
		,	"Read Q Message %ld not in range [%ld:%ld]"
		,	cheatseq, SeqNums[1], SeqNums[2]);
	}
}

static void
saveandcheck(struct IPC_CHANNEL * ch, struct IPC_MESSAGE* msg, char * savearea
,	size_t savesize, long* lastseq, const char * text)
{
	long	cheatseq = cheat_get_sequence(msg);

	save_body(msg, savearea, savesize);
	if (*lastseq != 0 ) {
		if (cheatseq != *lastseq +1) {
			int	j;
			cl_log(LOG_ERR
			,	"%s packets out of sequence! %ld versus %ld [pid %d]"
			,	text, cheatseq, *lastseq, (int)getpid());
			dump_ipc_info(ch);
			for (j=0; j < 4; ++j) {
				cl_log(LOG_DEBUG
				,	"SeqNums[%d] = %ld"
				,	j, SeqNums[j]);
			}
			cl_log(LOG_ERR
			,	"SocketIPCStats.nsent = %ld"
			,	SocketIPCStats.nsent);
			cl_log(LOG_ERR
			,	"SocketIPCStats.noutqueued = %ld"
			,	SocketIPCStats.noutqueued);
			cl_log(LOG_ERR
			,	"SocketIPCStats.nreceived = %ld"
			,	SocketIPCStats.nreceived);
			cl_log(LOG_ERR
			,	"SocketIPCStats.ninqueued = %ld"
			,	SocketIPCStats.ninqueued);
		}

	}
	g_list_foreach(ch->recv_queue->queue, audit_readmsgq_msg, NULL);
	if (cheatseq > 0) {
		*lastseq = cheatseq;
	}
}

#	define	CHECKFOO(which, ch, msg, area, text)	{			\
		saveandcheck(ch,msg,area,sizeof(area),SeqNums+which,text);	\
	}
#else
#	define	CHECKFOO(which, ch, msg, area, text)	/* Nothing */
#endif

static void
dump_msg(struct IPC_MESSAGE *msg, const char * label)
{
#ifdef CHEAT_CHECKS
	cl_log(LOG_DEBUG, "%s packet (length %d) [%s] %ld pid %d"
	,	label,	(int)msg->msg_len, (char*)msg->msg_body
	,	cheat_get_sequence(msg), (int)getpid());
#else
	cl_log(LOG_DEBUG, "%s length %d [%s] pid %d"
	,	label,	(int)msg->msg_len, (char*)msg->msg_body
	,	(int)getpid());
#endif
}

static void
dump_msgq_msg(gpointer data, gpointer user_data)
{
	dump_msg(data, user_data);
}

void
dump_ipc_info(const IPC_Channel* chan)
{
	char squeue[] = "Send queue";
	char rqueue[] = "Receive queue";
#ifdef CHEAT_CHECKS
	cl_log(LOG_DEBUG, "Saved Last Body read[%s]", SavedReadBody);
	cl_log(LOG_DEBUG, "Saved Last Body received[%s]", SavedReceivedBody);
	cl_log(LOG_DEBUG, "Saved Last Body Queued[%s]", SavedQueuedBody);
	cl_log(LOG_DEBUG, "Saved Last Body Sent[%s]", SavedSentBody);
#endif
	g_list_foreach(chan->send_queue->queue, dump_msgq_msg, squeue);
	g_list_foreach(chan->recv_queue->queue, dump_msgq_msg, rqueue);
	CHANAUDIT(chan);
}

/* destroy socket wait channel */
static void
socket_destroy_wait_conn(struct IPC_WAIT_CONNECTION * wait_conn)
{
	struct SOCKET_WAIT_CONN_PRIVATE * wc = wait_conn->ch_private;

	if (wc != NULL) {
#if HB_IPC_METHOD == HB_IPC_SOCKET
		if (wc->s >= 0) {
			if (debug_level > 1) {
				cl_log(LOG_DEBUG
				,	"%s: closing socket %d"
				,	__FUNCTION__, wc->s);
			}
			close(wc->s);
			cl_poll_ignore(wc->s);
			unlink(wc->path_name);
			wc->s = -1;
		}
#elif HB_IPC_METHOD == HB_IPC_STREAM
		cl_poll_ignore(wc->pipefds[0]);
		if (wc->pipefds[0] >= 0) {
			if (debug_level > 1) {
				cl_log(LOG_DEBUG
				,	"%s: closing pipe[0] %d"
				,	__FUNCTION__, wc->pipefds[0]);
			}
			wc->pipefds[0] = -1;
		}
		if (wc->pipefds[1] >= 0) {
			if (debug_level > 1) {
				cl_log(LOG_DEBUG
				,	"%s: closing pipe[1] %d"
				,	__FUNCTION__, wc->pipefds[1]);
			}
			wc->pipefds[0] = -1;
		}
		unlink(wc->path_name);
#endif
		g_free(wc);
	}
	g_free((void*) wait_conn);
}

/* return a fd which can be listened on for new connections. */
static int
socket_wait_selectfd(struct IPC_WAIT_CONNECTION *wait_conn)
{
	struct SOCKET_WAIT_CONN_PRIVATE * wc = wait_conn->ch_private;

#if HB_IPC_METHOD == HB_IPC_SOCKET
	return (wc == NULL ? -1 : wc->s);
#elif HB_IPC_METHOD == HB_IPC_STREAM
	return (wc == NULL ? -1 : wc->pipefds[0]);
#endif
}

/* socket accept connection. */
static struct IPC_CHANNEL*
socket_accept_connection(struct IPC_WAIT_CONNECTION * wait_conn
,	struct IPC_AUTH *auth_info)
{
	struct IPC_CHANNEL *			ch = NULL;
	int					s;
	int					new_sock;
	struct SOCKET_WAIT_CONN_PRIVATE*	conn_private;
	struct SOCKET_CH_PRIVATE *		ch_private ;
	int auth_result = IPC_FAIL;
	int					saveerrno=errno;
	gboolean was_error = FALSE;
#if HB_IPC_METHOD == HB_IPC_SOCKET
	/* make peer_addr a pointer so it can be used by the
	 *   USE_BINDSTAT_CREDS implementation of socket_verify_auth()
	 */
	struct sockaddr_un *			peer_addr = NULL;
	socklen_t				sin_size;
#elif HB_IPC_METHOD == HB_IPC_STREAM
	struct strrecvfd strrecvfd;
#endif

	/* get select fd */

	s = wait_conn->ops->get_select_fd(wait_conn);
	if (s < 0) {
		cl_log(LOG_ERR, "get_select_fd: invalid fd");
		return NULL;
	}

	/* Get client connection. */
#if HB_IPC_METHOD == HB_IPC_SOCKET
	peer_addr = g_new(struct sockaddr_un, 1);
	*peer_addr->sun_path = '\0';
	sin_size = sizeof(struct sockaddr_un);
	new_sock = accept(s, (struct sockaddr *)peer_addr, &sin_size);
#elif HB_IPC_METHOD == HB_IPC_STREAM
	if (ioctl(s, I_RECVFD, &strrecvfd) == -1) {
		new_sock = -1;
	}
	else {
		new_sock = strrecvfd.fd;
	}
#endif
	saveerrno=errno;
	if (new_sock == -1) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			cl_perror("socket_accept_connection: accept(sock=%d)"
			,	s);
		}
		was_error = TRUE;

	} else {
		if ((ch = socket_server_channel_new(new_sock)) == NULL) {
			cl_log(LOG_ERR
			,	"socket_accept_connection:"
			        " Can't create new channel");
			was_error = TRUE;
		} else {
			conn_private=(struct SOCKET_WAIT_CONN_PRIVATE*)
			(	wait_conn->ch_private);
			ch_private = (struct SOCKET_CH_PRIVATE *)(ch->ch_private);
			strncpy(ch_private->path_name,conn_private->path_name
			,		sizeof(conn_private->path_name));

#if HB_IPC_METHOD == HB_IPC_SOCKET
			ch_private->peer_addr = peer_addr;
#elif HB_IPC_METHOD == HB_IPC_STREAM
			ch_private->farside_uid = strrecvfd.uid;
			ch_private->farside_gid = strrecvfd.gid;
#endif
		}
	}

	/* Verify the client authorization information. */
	if(was_error == FALSE) {
		auth_result = ch->ops->verify_auth(ch, auth_info);
		if (auth_result == IPC_OK) {
			ch->ch_status = IPC_CONNECT;
			ch->farside_pid = socket_get_farside_pid(new_sock);
			return ch;
		}
		saveerrno=errno;
	}

#if HB_IPC_METHOD == HB_IPC_SOCKET
	g_free(peer_addr);
	peer_addr = NULL;
#endif
	errno=saveerrno;
	return NULL;
}

/*
 * Called by socket_destroy(). Disconnect the connection
 * and set ch_status to IPC_DISCONNECT.
 *
 * parameters :
 *     ch (IN) the pointer to the channel.
 *
 * return values :
 *     IPC_OK   the connection is disconnected successfully.
 *      IPC_FAIL     operation fails.
*/

static int
socket_disconnect(struct IPC_CHANNEL* ch)
{
	struct SOCKET_CH_PRIVATE* conn_info;

	conn_info = (struct SOCKET_CH_PRIVATE*) ch->ch_private;
	if (debug_level > 1) {
		cl_log(LOG_DEBUG
		,	"%s(sock=%d, ch=0x%lx){"
		,	__FUNCTION__
		,	conn_info->s, (unsigned long)ch);
	}
#if 0
	if (ch->ch_status != IPC_DISCONNECT) {
  		cl_log(LOG_INFO, "forced disconnect for fd %d", conn_info->s);
	}
#endif
	if (ch->ch_status == IPC_CONNECT) {
		socket_resume_io(ch);
	}

	if (conn_info->s >= 0) {
		if (debug_level > 1) {
			cl_log(LOG_DEBUG
			,	"%s: closing socket %d"
			,	__FUNCTION__, conn_info->s);
		}
		close(conn_info->s);
		cl_poll_ignore(conn_info->s);
		conn_info->s = -1;
	}
	ch->ch_status = IPC_DISCONNECT;
	if (debug_level > 1) {
		cl_log(LOG_DEBUG, "}/*%s(sock=%d, ch=0x%lx)*/"
		,	__FUNCTION__, conn_info->s, (unsigned long)ch);
	}
	return IPC_OK;
}

/*
 * destroy a ipc queue and clean all memory space assigned to this queue.
 * parameters:
 *      q  (IN) the pointer to the queue which should be destroied.
 *
 *	FIXME:  This function does not free up messages that might
 *	be in the queue.
 */

static void
socket_destroy_queue(struct IPC_QUEUE * q)
{
  g_list_free(q->queue);

  g_free((void *) q);
}

static void
socket_destroy_channel(struct IPC_CHANNEL * ch)
{
	--ch->refcount;
	if (ch->refcount > 0) {
		return;
	}
	if (ch->ch_status == IPC_CONNECT) {
		socket_resume_io(ch);
	}
	if (debug_level > 1) {
		cl_log(LOG_DEBUG, "socket_destroy(ch=0x%lx){"
		,	(unsigned long)ch);
	}
	socket_disconnect(ch);
	socket_destroy_queue(ch->send_queue);
	socket_destroy_queue(ch->recv_queue);

	if (ch->pool) {
		ipc_bufpool_unref(ch->pool);
	}

	if (ch->ch_private != NULL) {
#if HB_IPC_METHOD == HB_IPC_SOCKET
		struct SOCKET_CH_PRIVATE *priv = (struct SOCKET_CH_PRIVATE *)
			ch->ch_private;
		if(priv->peer_addr != NULL) {
			if (*priv->peer_addr->sun_path) {
				unlink(priv->peer_addr->sun_path);
			}
			g_free((void*)(priv->peer_addr));
		}
#endif
    		g_free((void*)(ch->ch_private));
	}
	memset(ch, 0xff, sizeof(*ch));
	g_free((void*)ch);
	if (debug_level > 1) {
		cl_log(LOG_DEBUG, "}/*socket_destroy(ch=0x%lx)*/"
		,	(unsigned long)ch);
	}
}

static int
socket_check_disc_pending(struct IPC_CHANNEL* ch)
{
	int		rc;
	struct pollfd	sockpoll;

	if (ch->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_ERR, "check_disc_pending() already disconnected");
		return IPC_BROKEN;
	}
	if (ch->recv_queue->current_qlen > 0) {
		return IPC_OK;
	}
	sockpoll.fd = ch->ops->get_recv_select_fd(ch);
	sockpoll.events = POLLIN;

	rc = ipc_pollfunc_ptr(&sockpoll, 1, 0);

 	if (rc < 0) {
		cl_log(LOG_INFO
		,	"socket_check_disc_pending() bad poll call");
		ch->ch_status = IPC_DISCONNECT;
 		return IPC_BROKEN;
	}

	if (sockpoll.revents & POLLHUP) {
		if (sockpoll.revents & POLLIN) {
			ch->ch_status = IPC_DISC_PENDING;
		} else {
#if 1
			cl_log(LOG_INFO, "HUP without input");
#endif
			ch->ch_status = IPC_DISCONNECT;
			return IPC_BROKEN;
		}
	}
	if (sockpoll.revents & POLLIN) {
		int dummy;
		socket_resume_io_read(ch, &dummy, FALSE);
	}
	return IPC_OK;
}

static int
socket_initiate_connection(struct IPC_CHANNEL * ch)
{
	struct SOCKET_CH_PRIVATE* conn_info;
#if HB_IPC_METHOD == HB_IPC_SOCKET
	struct sockaddr_un peer_addr; /* connector's address information */
#elif HB_IPC_METHOD == HB_IPC_STREAM
#endif

	conn_info = (struct SOCKET_CH_PRIVATE*) ch->ch_private;

#if HB_IPC_METHOD == HB_IPC_SOCKET
	/* Prepare the socket */
	memset(&peer_addr, 0, sizeof(peer_addr));
	peer_addr.sun_family = AF_LOCAL;    /* host byte order */

	if (strlen(conn_info->path_name) >= sizeof(peer_addr.sun_path)) {
		return IPC_FAIL;
	}
	strncpy(peer_addr.sun_path, conn_info->path_name, sizeof(peer_addr.sun_path));

	/* Send connection request */
	if (connect(conn_info->s, (struct sockaddr *)&peer_addr
	, 	sizeof(struct sockaddr_un)) == -1) {
		return IPC_FAIL;
	}
#elif HB_IPC_METHOD == HB_IPC_STREAM

#endif

	ch->ch_status = IPC_CONNECT;
	ch->farside_pid = socket_get_farside_pid(conn_info->s);
	return IPC_OK;
}

static void
socket_set_high_flow_callback(IPC_Channel* ch,
			      flow_callback_t callback,
			      void* userdata) {
	ch->high_flow_callback = callback;
	ch->high_flow_userdata = userdata;
}

static void
socket_set_low_flow_callback(IPC_Channel* ch,
			     flow_callback_t callback,
			     void* userdata) {
	ch->low_flow_callback = callback;
	ch->low_flow_userdata = userdata;
}

static void
socket_check_flow_control(struct IPC_CHANNEL* ch,
			  int orig_qlen,
			  int curr_qlen)
{
	if (!IPC_ISRCONN(ch)) {
		return;
	}

	if (curr_qlen >= ch->high_flow_mark
	    && ch->high_flow_callback) {
			ch->high_flow_callback(ch, ch->high_flow_userdata);
	}

	if (curr_qlen <= ch->low_flow_mark
	    && orig_qlen > ch->low_flow_mark
	    && ch->low_flow_callback) {
		ch->low_flow_callback(ch, ch->low_flow_userdata);
	}
}

static int
socket_send(struct IPC_CHANNEL * ch, struct IPC_MESSAGE* msg)
{
	int orig_qlen;
	int diff;
	struct IPC_MESSAGE* newmsg;

	if (msg->msg_len > MAXMSG) {
		cl_log(LOG_ERR, "%s: sorry, cannot send messages "
			"bigger than %d (requested %lu)",
			__FUNCTION__, MAXMSG, (unsigned long)msg->msg_len);
		return IPC_FAIL;
	}
	if (msg->msg_len < 0) {
		cl_log(LOG_ERR, "socket_send: "
		       "invalid message");
		return IPC_FAIL;
	}

	if (ch->ch_status != IPC_CONNECT) {
		return IPC_FAIL;
	}

	ch->ops->resume_io(ch);

	if (ch->send_queue->maxqlen_cnt &&
		time(NULL) - ch->send_queue->last_maxqlen_warn >= 60) {
	    cl_log(LOG_ERR, "%u messages dropped on a non-blocking channel (send queue maximum length %d)",
		   ch->send_queue->maxqlen_cnt, (int)ch->send_queue->max_qlen);
	    ch->send_queue->maxqlen_cnt = 0;
	}
	if ( !ch->should_send_block &&
	    ch->send_queue->current_qlen >= ch->send_queue->max_qlen) {
		if (!ch->send_queue->maxqlen_cnt) {
			ch->send_queue->last_maxqlen_warn = time(NULL);
		}
		ch->send_queue->maxqlen_cnt++;

		if (ch->should_block_fail) {
			return IPC_FAIL;
		} else {
			return IPC_OK;
		}
	}

	while (ch->send_queue->current_qlen >= ch->send_queue->max_qlen) {
		if (ch->ch_status != IPC_CONNECT) {
		 	cl_log(LOG_WARNING, "socket_send:"
			" message queue exceeded and IPC not connected");
			return IPC_FAIL;
		}
		cl_shortsleep();
		ch->ops->resume_io(ch);
	}

	/* add the message into the send queue */
	CHECKFOO(0,ch, msg, SavedQueuedBody, "queued message");
	SocketIPCStats.noutqueued++;

	diff = 0;
	if (msg->msg_buf ) {
		diff = (char*)msg->msg_body - (char*)msg->msg_buf;
	}
	if ( diff < (int)sizeof(struct SOCKET_MSG_HEAD) ) {
		/* either we don't have msg->msg_buf set
		 * or we don't have enough bytes for socket head
		 * we delete this message and creates
		 * a new one and delete the old one
		 */

		newmsg= socket_message_new(ch, msg->msg_len);
		if (newmsg == NULL) {
			cl_log(LOG_ERR, "socket_resume_io_write: "
			       "allocating memory for new ipc msg failed");
			return IPC_FAIL;
		}

		memcpy(newmsg->msg_body, msg->msg_body, msg->msg_len);

		if(msg->msg_done) {
			msg->msg_done(msg);
		};
		msg = newmsg;
	}
#ifdef IPC_TIME_DEBUG
	ipc_time_debug(ch,msg, MSGPOS_ENQUEUE);
#endif
	ch->send_queue->queue = g_list_append(ch->send_queue->queue,
					      msg);
	orig_qlen = ch->send_queue->current_qlen++;

	socket_check_flow_control(ch, orig_qlen, orig_qlen +1 );

	/* resume io */
	ch->ops->resume_io(ch);
	return IPC_OK;
}

static int
socket_recv(struct IPC_CHANNEL * ch, struct IPC_MESSAGE** message)
{
	GList *element;

	int		nbytes;
	int		result;

	socket_resume_io(ch);
	result = socket_resume_io_read(ch, &nbytes, TRUE);

	*message = NULL;

	if (ch->recv_queue->current_qlen == 0) {
		return result != IPC_OK ? result : IPC_FAIL;
		/*return IPC_OK;*/
	}
	element = g_list_first(ch->recv_queue->queue);

	if (element == NULL) {
		/* Internal accounting error, but correctable */
		cl_log(LOG_ERR
		, "recv failure: qlen (%ld) > 0, but no message found."
		,	(long)ch->recv_queue->current_qlen);
		ch->recv_queue->current_qlen = 0;
		return IPC_FAIL;
	}
	*message = (struct IPC_MESSAGE *) (element->data);
#ifdef IPC_TIME_DEBUG
	ipc_time_debug(ch, *message, MSGPOS_DEQUEUE);
#endif

	CHECKFOO(1,ch, *message, SavedReadBody, "read message");
	SocketIPCStats.nreceived++;
	ch->recv_queue->queue =	g_list_remove(ch->recv_queue->queue
	,	element->data);
	ch->recv_queue->current_qlen--;
	return IPC_OK;
}

static int
socket_check_poll(struct IPC_CHANNEL * ch
,		struct pollfd * sockpoll)
{
	if (ch->ch_status == IPC_DISCONNECT) {
		return IPC_OK;
	}
	if (sockpoll->revents & POLLHUP) {
		/* If input present, or this is an output-only poll... */
		if (sockpoll->revents & POLLIN
		|| (sockpoll-> events & POLLIN) == 0 ) {
			ch->ch_status = IPC_DISC_PENDING;
			return IPC_OK;
		}
#if 1
		cl_log(LOG_INFO, "socket_check_poll(): HUP without input");
#endif
		ch->ch_status = IPC_DISCONNECT;
		return IPC_BROKEN;

	} else if (sockpoll->revents & (POLLNVAL|POLLERR)) {
		/* Have we already closed the socket? */
		if (fcntl(sockpoll->fd, F_GETFL) < 0) {
			cl_perror("socket_check_poll(pid %d): bad fd [%d]"
			,	(int) getpid(), sockpoll->fd);
			ch->ch_status = IPC_DISCONNECT;
			return IPC_OK;
		}
		cl_log(LOG_ERR
		,	"revents failure: fd %d, flags 0x%x"
		,	sockpoll->fd, sockpoll->revents);
		errno = EINVAL;
		return IPC_FAIL;
	}
	return IPC_OK;
}

static int
socket_waitfor(struct IPC_CHANNEL * ch
,	gboolean (*finished)(struct IPC_CHANNEL * ch))
{
	struct pollfd sockpoll;

	CHANAUDIT(ch);
	if (finished(ch)) {
		return IPC_OK;
	}

 	if (ch->ch_status == IPC_DISCONNECT) {
 		return IPC_BROKEN;
	}
	sockpoll.fd = ch->ops->get_recv_select_fd(ch);

	while (!finished(ch) &&	IPC_ISRCONN(ch)) {
		int	rc;

		sockpoll.events = POLLIN;

		/* Cannot call resume_io after the call to finished()
		 * and before the call to poll because we might
		 * change the state of the thing finished() is
		 * waiting for.
		 * This means that the poll call below would be
		 * not only pointless, but might
		 * make us hang forever waiting for this
		 * event which has already happened
		 */
		if (ch->send_queue->current_qlen > 0) {
			sockpoll.events |= POLLOUT;
		}

		rc = ipc_pollfunc_ptr(&sockpoll, 1, -1);

		if (rc < 0) {
			return (errno == EINTR ? IPC_INTR : IPC_FAIL);
		}

		rc = socket_check_poll(ch, &sockpoll);
		if (sockpoll.revents & POLLIN) {
			socket_resume_io(ch);
		}
		if (rc != IPC_OK) {
			CHANAUDIT(ch);
			return rc;
		}
	}

	CHANAUDIT(ch);
	return IPC_OK;
}

static int
socket_waitin(struct IPC_CHANNEL * ch)
{
	return socket_waitfor(ch, ch->ops->is_message_pending);
}
static gboolean
socket_is_output_flushed(struct IPC_CHANNEL * ch)
{
	return ! ch->ops->is_sending_blocked(ch);
}

static int
socket_waitout(struct IPC_CHANNEL * ch)
{
	int	rc;
	CHANAUDIT(ch);
	rc = socket_waitfor(ch, socket_is_output_flushed);

	if (rc != IPC_OK) {
		cl_log(LOG_ERR
		,	"socket_waitout failure: rc = %d", rc);
	} else if (ch->ops->is_sending_blocked(ch)) {
		cl_log(LOG_ERR, "socket_waitout output still blocked");
	}
	CHANAUDIT(ch);
	return rc;
}

static gboolean
socket_is_message_pending(struct IPC_CHANNEL * ch)
{
	int nbytes;

	socket_resume_io_read(ch, &nbytes, TRUE);
	ch->ops->resume_io(ch);
	if (ch->recv_queue->current_qlen > 0) {
		return TRUE;
	}

	return !IPC_ISRCONN(ch);
}

static gboolean
socket_is_output_pending(struct IPC_CHANNEL * ch)
{
	socket_resume_io(ch);
	return 	ch->ch_status == IPC_CONNECT
	&&	 ch->send_queue->current_qlen > 0;
}

static gboolean
socket_is_sendq_full(struct IPC_CHANNEL * ch)
{
	ch->ops->resume_io(ch);
	return(ch->send_queue->current_qlen == ch->send_queue->max_qlen);
}

static gboolean
socket_is_recvq_full(struct IPC_CHANNEL * ch)
{
	ch->ops->resume_io(ch);
	return(ch->recv_queue->current_qlen == ch->recv_queue->max_qlen);
}

static int
socket_get_conntype(struct IPC_CHANNEL* ch)
{
	return ch->conntype;
}

static int
socket_assert_auth(struct IPC_CHANNEL *ch, GHashTable *auth)
{
	cl_log(LOG_ERR
	, "the assert_auth function for domain socket is not implemented");
	return IPC_FAIL;
}

static int
socket_resume_io_read(struct IPC_CHANNEL *ch, int* nbytes, gboolean read1anyway)
{
	struct SOCKET_CH_PRIVATE*	conn_info;
	int				retcode = IPC_OK;
	struct pollfd			sockpoll;
	int				debug_loopcount = 0;
	int				debug_bytecount = 0;
	size_t				maxqlen = ch->recv_queue->max_qlen;
	struct ipc_bufpool*		pool = ch->pool;
	int				nmsgs = 0;
	int				spaceneeded;
	*nbytes = 0;

	CHANAUDIT(ch);
	conn_info = (struct SOCKET_CH_PRIVATE *) ch->ch_private;

	if (ch->ch_status == IPC_DISCONNECT) {
		return IPC_BROKEN;
	}

	if (pool == NULL) {
		ch->pool = pool = ipc_bufpool_new(0);
		if (pool == NULL) {
			cl_log(LOG_ERR, "socket_resume_io_read: "
			       "memory allocation for ipc pool failed");
			return IPC_FAIL;
		}
	}

	if (ipc_bufpool_full(pool, ch, &spaceneeded)) {
		struct ipc_bufpool*	newpool;

		newpool = ipc_bufpool_new(spaceneeded);
		if (newpool == NULL) {
			cl_log(LOG_ERR, "socket_resume_io_read: "
			       "memory allocation for a new ipc pool failed");
			return IPC_FAIL;
		}

		ipc_bufpool_partial_copy(newpool, pool);
		ipc_bufpool_unref(pool);
		ch->pool = pool = newpool;
	}
	if (maxqlen <= 0 && read1anyway) {
		maxqlen = 1;
	}
  	if (ch->recv_queue->current_qlen < maxqlen && retcode == IPC_OK) {
		void *				msg_begin;
		int				msg_len;
		int				len;
#if HB_IPC_METHOD == HB_IPC_STREAM
		struct strbuf d;
		int flags, rc;
#endif

		CHANAUDIT(ch);
		++debug_loopcount;

		len = ipc_bufpool_spaceleft(pool);
		msg_begin = pool->currpos;

		CHANAUDIT(ch);

		/* Now try to receive some data */

#if HB_IPC_METHOD == HB_IPC_SOCKET
		msg_len = recv(conn_info->s, msg_begin, len, MSG_DONTWAIT);
#elif HB_IPC_METHOD == HB_IPC_STREAM
		d.maxlen = len;
		d.len = 0;
		d.buf = msg_begin;
		flags = 0;
		rc = getmsg(conn_info->s, NULL, &d, &flags);
		msg_len = (rc < 0) ? rc : d.len;
#endif
		SocketIPCStats.last_recv_rc = msg_len;
		SocketIPCStats.last_recv_errno = errno;
		++SocketIPCStats.recv_count;

		/* Did we get an error? */
		if (msg_len < 0) {
			switch (errno) {
			case EAGAIN:
				if (ch->ch_status==IPC_DISC_PENDING) {
					ch->ch_status =IPC_DISCONNECT;
					retcode = IPC_BROKEN;
				}
				break;

			case ECONNREFUSED:
			case ECONNRESET:
				ch->ch_status = IPC_DISC_PENDING;
				retcode= socket_check_disc_pending(ch);
				break;

			default:
				cl_perror("socket_resume_io_read"
					  ": unknown recv error, peerpid=%d",
					  ch->farside_pid);
				ch->ch_status = IPC_DISCONNECT;
				retcode = IPC_FAIL;
				break;
			}

		} else if (msg_len == 0) {
			ch->ch_status = IPC_DISC_PENDING;
			if(ch->recv_queue->current_qlen <= 0) {
				ch->ch_status = IPC_DISCONNECT;
				retcode = IPC_FAIL;
			}
		} else {
			/* We read something! */
			/* Note that all previous cases break out of the loop */
			debug_bytecount += msg_len;
			*nbytes = msg_len;
			nmsgs = ipc_bufpool_update(pool, ch, msg_len, ch->recv_queue) ;

			if (nmsgs < 0) {
				/* we didn't like the other side */
				cl_log(LOG_ERR, "socket_resume_io_read: "
					   "disconnecting the other side");
				ch->ch_status = IPC_DISCONNECT;
				retcode = IPC_FAIL;
			} else {
				SocketIPCStats.ninqueued += nmsgs;
			}
		}
	}

	/* Check for errors uncaught by recv() */
	/* NOTE: It doesn't seem right we have to do this every time */
	/* FIXME?? */

	memset(&sockpoll,0, sizeof(struct pollfd));
	if ((retcode == IPC_OK)
	&&	(sockpoll.fd = conn_info->s) >= 0) {
		/* Just check for errors, not for data */
		sockpoll.events = 0;
		ipc_pollfunc_ptr(&sockpoll, 1, 0);
		retcode = socket_check_poll(ch, &sockpoll);
	}

	CHANAUDIT(ch);
	if (retcode != IPC_OK) {
		return retcode;
	}

	return IPC_ISRCONN(ch) ? IPC_OK : IPC_BROKEN;
}

static int
socket_resume_io_write(struct IPC_CHANNEL *ch, int* nmsg)
{
	int				retcode = IPC_OK;
	struct SOCKET_CH_PRIVATE*	conn_info;

	CHANAUDIT(ch);
	*nmsg = 0;
	conn_info = (struct SOCKET_CH_PRIVATE *) ch->ch_private;

	while (ch->ch_status == IPC_CONNECT
	&&		retcode == IPC_OK
	&&		ch->send_queue->current_qlen > 0) {

		GList *				element;
		struct IPC_MESSAGE *		msg;
		struct SOCKET_MSG_HEAD		head;
                struct IPC_MESSAGE* 		oldmsg = NULL;
		int				sendrc = 0;
                struct IPC_MESSAGE* 		newmsg;
		char*				p;
		unsigned int			bytes_remaining;
		int				diff;

		CHANAUDIT(ch);
		element = g_list_first(ch->send_queue->queue);
		if (element == NULL) {
			/* OOPS!  - correct consistency problem */
			ch->send_queue->current_qlen = 0;
			break;
		}
		msg = (struct IPC_MESSAGE *) (element->data);

		diff = 0;
		if (msg->msg_buf ) {
			diff = (char*)msg->msg_body - (char*)msg->msg_buf;
		}
		if ( diff < (int)sizeof(struct SOCKET_MSG_HEAD) ) {
			/* either we don't have msg->msg_buf set
			 * or we don't have enough bytes for socket head
			 * we delete this message and creates
			 * a new one and delete the old one
			 */

			newmsg= socket_message_new(ch, msg->msg_len);
			if (newmsg == NULL) {
				cl_log(LOG_ERR, "socket_resume_io_write: "
					"allocating memory for new ipc msg failed");
                		return IPC_FAIL;
			}

                	memcpy(newmsg->msg_body, msg->msg_body, msg->msg_len);
                	oldmsg = msg;
			msg = newmsg;
		}

                head.msg_len = msg->msg_len;
		head.magic = HEADMAGIC;
		memcpy(msg->msg_buf, &head, sizeof(struct SOCKET_MSG_HEAD));

		if (ch->bytes_remaining == 0) {
			/*we start to send a new message*/
#ifdef IPC_TIME_DEBUG
			ipc_time_debug(ch, msg, MSGPOS_SEND);
#endif
			bytes_remaining = msg->msg_len + ch->msgpad;
			p = msg->msg_buf;
		} else {
			bytes_remaining = ch->bytes_remaining;
			p = ((char*)msg->msg_buf) + msg->msg_len + ch->msgpad
				- bytes_remaining;

		}

		sendrc = 0;

                do {
#if HB_IPC_METHOD == HB_IPC_STREAM
			struct strbuf d;
			int msglen, putmsgrc;
#endif

                        CHANAUDIT(ch);

#if HB_IPC_METHOD == HB_IPC_SOCKET
			sendrc = send(conn_info->s, p
			,       bytes_remaining, (MSG_DONTWAIT|MSG_NOSIGNAL));
#elif HB_IPC_METHOD == HB_IPC_STREAM
			d.maxlen = 0;
			d.len = msglen = bytes_remaining;
			d.buf = p;
			putmsgrc = putmsg(conn_info->s, NULL, &d, 0);
			sendrc = putmsgrc == 0 ? msglen : -1;
#endif
                        SocketIPCStats.last_send_rc = sendrc;
                        SocketIPCStats.last_send_errno = errno;
                        ++SocketIPCStats.send_count;

			if (sendrc <= 0) {
				break;
			} else {
				p = p + sendrc;
				bytes_remaining -= sendrc;
			}

                } while(bytes_remaining > 0 );

		ch->bytes_remaining = bytes_remaining;

		if (sendrc < 0) {
			switch (errno) {
			case EAGAIN:
				retcode = IPC_OK;
				break;
			case EPIPE:
				ch->ch_status = IPC_DISC_PENDING;
				socket_check_disc_pending(ch);
				retcode = IPC_BROKEN;
				break;
			default:
				cl_perror("socket_resume_io_write"
					  ": send2 bad errno");
				ch->ch_status = IPC_DISCONNECT;
				retcode = IPC_FAIL;
				break;
			}
			break;
		} else {
			int orig_qlen;

			CHECKFOO(3,ch, msg, SavedSentBody, "sent message")

			if (oldmsg) {
		                if (msg->msg_done != NULL) {
                                	msg->msg_done(msg);
                        	}
				msg=oldmsg;
			}

			if(ch->bytes_remaining ==0) {
				ch->send_queue->queue = g_list_remove(ch->send_queue->queue,	msg);
				if (msg->msg_done != NULL) {
					msg->msg_done(msg);
				}

				SocketIPCStats.nsent++;
				orig_qlen = ch->send_queue->current_qlen--;
				socket_check_flow_control(ch, orig_qlen, orig_qlen -1 );
				(*nmsg)++;
			}
		}
	}
	CHANAUDIT(ch);
	if (retcode != IPC_OK) {
		return retcode;
	}
	return IPC_ISRCONN(ch) ? IPC_OK : IPC_BROKEN;
}

static int
socket_resume_io(struct IPC_CHANNEL *ch)
{
	int		rc1 = IPC_OK;
	int		rc2 = IPC_OK;
	int		nwmsg = 1;
	int		nbytes_r = 1;
	gboolean	OKonce = FALSE;

	CHANAUDIT(ch);
	if (!IPC_ISRCONN(ch)) {
		return IPC_BROKEN;
	}

	do {
		if (nbytes_r > 0) {
			rc1 = socket_resume_io_read(ch, &nbytes_r, FALSE);
		}
		if (nwmsg > 0) {
			nwmsg = 0;
			rc2 = socket_resume_io_write(ch, &nwmsg);
		}
		if (rc1 == IPC_OK || rc2 == IPC_OK) {
			OKonce = TRUE;
		}
	} while ((nbytes_r > 0  || nwmsg > 0) && IPC_ISRCONN(ch));

	if (IPC_ISRCONN(ch)) {
		if (rc1 != IPC_OK) {
			cl_log(LOG_ERR
			       ,	"socket_resume_io_read() failure");
		}
		if (rc2 != IPC_OK && IPC_CONNECT == ch->ch_status) {
			cl_log(LOG_ERR
			,	"socket_resume_io_write() failure");
		}
	} else {
		return (OKonce ? IPC_OK : IPC_BROKEN);
	}

	return (rc1 != IPC_OK ? rc1 : rc2);
}

static int
socket_get_recv_fd(struct IPC_CHANNEL *ch)
{
	struct SOCKET_CH_PRIVATE* chp = ch ->ch_private;

	return (chp == NULL ? -1 : chp->s);
}

static int
socket_get_send_fd(struct IPC_CHANNEL *ch)
{
	return socket_get_recv_fd(ch);
}

static void
socket_adjust_buf(struct IPC_CHANNEL *ch, int optname, unsigned q_len)
{
	const char *direction = optname == SO_SNDBUF ? "snd" : "rcv";
	int fd = socket_get_send_fd(ch);
	unsigned byte;

	/* Arbitrary scaling.
	 * DEFAULT_MAX_QLEN is 64, default socket buf is often 64k to 128k,
	 * at least on those linux I checked.
	 * Keep that ratio, and allow for some overhead. */
	if (q_len == 0)
		/* client does not want anything,
		 * reduce system buffers as well */
		byte = 4096;
	else if (q_len < 512)
		byte = (32 + q_len) * 1024;
	else
		byte = q_len * 1024;

	if (0 == setsockopt(fd, SOL_SOCKET, optname, &byte, sizeof(byte))) {
		if (debug_level > 1) {
			cl_log(LOG_DEBUG, "adjusted %sbuf size to %u",
					direction, byte);
		}
	} else {
		/* If this fails, you may need to adjust net.core.rmem_max,
		 * ...wmem_max, or equivalent */
		cl_log(LOG_WARNING, "adjust %sbuf size to %u failed: %s",
			direction, byte, strerror(errno));
	}
}

static int
socket_set_send_qlen (struct IPC_CHANNEL* ch, int q_len)
{
  /* This seems more like an assertion failure than a normal error */
  if (ch->send_queue == NULL) {
    return IPC_FAIL;
  }
  socket_adjust_buf(ch, SO_SNDBUF, q_len);
  ch->send_queue->max_qlen = q_len;
  return IPC_OK;
}

static int
socket_set_recv_qlen (struct IPC_CHANNEL* ch, int q_len)
{
  /* This seems more like an assertion failure than a normal error */
  if (ch->recv_queue == NULL) {
    return IPC_FAIL;
  }
  socket_adjust_buf(ch, SO_RCVBUF, q_len);
  ch->recv_queue->max_qlen = q_len;
  return IPC_OK;
}

static int ipcmsg_count_allocated = 0;
static int ipcmsg_count_freed = 0;
void socket_ipcmsg_dump_stats(void);
void
socket_ipcmsg_dump_stats(void) {
	cl_log(LOG_INFO, "ipcsocket ipcmsg allocated=%d, freed=%d, diff=%d",
	       ipcmsg_count_allocated,
	       ipcmsg_count_freed,
	       ipcmsg_count_allocated - ipcmsg_count_freed);
}

static void
socket_del_ipcmsg(IPC_Message* m)
{
	if (m == NULL) {
		cl_log(LOG_ERR, "socket_del_ipcmsg:"
		       "msg is NULL");
		return;
	}

	if (m->msg_body) {
		memset(m->msg_body, 0, m->msg_len);
	}
	if (m->msg_buf) {
		g_free(m->msg_buf);
	}

	memset(m, 0, sizeof(*m));
	g_free(m);

	ipcmsg_count_freed ++;
}

static IPC_Message*
socket_new_ipcmsg(IPC_Channel* ch, const void* data, int len, void* private)
{
	IPC_Message*	hdr;

	if (ch == NULL || len < 0) {
		cl_log(LOG_ERR, "socket_new_ipcmsg:"
		       " invalid parameter");
		return NULL;
	}

	if (ch->msgpad > MAX_MSGPAD) {
		cl_log(LOG_ERR, "socket_new_ipcmsg: too many pads "
		       "something is wrong");
		return NULL;
	}

	hdr = ipcmsg_new(ch, data, len, private, socket_del_ipcmsg);

	if (hdr) ipcmsg_count_allocated ++;

	return hdr;
}

static
struct IPC_MESSAGE *
ipcmsg_new(struct IPC_CHANNEL * ch, const void* data, int len, void* private,
	DelProc delproc)
{
	struct IPC_MESSAGE * hdr;
	char*	copy = NULL;
	char*	buf;
	char*	body;

	if ((hdr = g_new(struct IPC_MESSAGE, 1))  == NULL) {
		return NULL;
	}
	memset(hdr, 0, sizeof(*hdr));

	if (len > 0) {
		if ((copy = (char*)g_malloc(ch->msgpad + len)) == NULL) {
			g_free(hdr);
			return NULL;
		}
		if (data) {
			memcpy(copy + ch->msgpad, data, len);
		}
		buf = copy;
		body = copy + ch->msgpad;;
	} else {
		len = 0;
		buf = body = NULL;
	}
	hdr->msg_len = len;
	hdr->msg_buf = buf;
	hdr->msg_body = body;
	hdr->msg_ch = ch;
	hdr->msg_done = delproc;
	hdr->msg_private = private;

	return hdr;
}

static int
socket_get_chan_status(IPC_Channel* ch)
{
	socket_resume_io(ch);
	return ch->ch_status;
}

/* socket object of the function table */
static struct IPC_WAIT_OPS socket_wait_ops = {
  socket_destroy_wait_conn,
  socket_wait_selectfd,
  socket_accept_connection,
};

/*
 * create a new ipc queue whose length = 0 and inner queue = NULL.
 * return the pointer to a new ipc queue or NULL is the queue can't be created.
 */

static struct IPC_QUEUE*
socket_queue_new(void)
{
  struct IPC_QUEUE *temp_queue;

  /* temp queue with length = 0 and inner queue = NULL. */
  temp_queue =  g_new(struct IPC_QUEUE, 1);
  temp_queue->current_qlen = 0;
  temp_queue->max_qlen = DEFAULT_MAX_QLEN;
  temp_queue->queue = NULL;
  temp_queue->last_maxqlen_warn = 0;
  temp_queue->maxqlen_cnt = 0;
  return temp_queue;
}

/*
 * socket_wait_conn_new:
 * Called by ipc_wait_conn_constructor to get a new socket
 * waiting connection.
 * (better explanation of this role might be nice)
 *
 * Parameters :
 *     ch_attrs (IN) the attributes used to create this connection.
 *
 * Return :
 *	the pointer to the new waiting connection or NULL if the connection
 *	can't be created.
 *
 * NOTE :
 *   for domain socket implementation, the only attribute needed is path name.
 *	so the user should
 *   create the hash table like this:
 *     GHashTable * attrs;
 *     attrs = g_hash_table_new(g_str_hash, g_str_equal);
 *     g_hash_table_insert(attrs, PATH_ATTR, path_name);
 *     here PATH_ATTR is defined as "path".
 *
 * NOTE :
 *   The streams implementation uses "Streams Programming Guide", Solaris 8,
 *   as its guide (sample code near end of "Configuration" chapter 11).
 */
struct IPC_WAIT_CONNECTION *
socket_wait_conn_new(GHashTable *ch_attrs)
{
  struct IPC_WAIT_CONNECTION * temp_ch;
  char *path_name;
  char *mode_attr;
  int s, flags;
  struct SOCKET_WAIT_CONN_PRIVATE *wait_private;
  mode_t s_mode;
#if HB_IPC_METHOD == HB_IPC_SOCKET
  struct sockaddr_un my_addr;
#elif HB_IPC_METHOD == HB_IPC_STREAM
  int pipefds[2];
#endif

  path_name = (char *) g_hash_table_lookup(ch_attrs, IPC_PATH_ATTR);
  mode_attr = (char *) g_hash_table_lookup(ch_attrs, IPC_MODE_ATTR);

  if (mode_attr != NULL) {
    s_mode = (mode_t)strtoul((const char *)mode_attr, NULL, 8);
  } else {
    s_mode = 0777;
  }
  if (path_name == NULL) {
    return NULL;
  }

#if HB_IPC_METHOD == HB_IPC_SOCKET
  /* prepare the unix domain socket */
  if ((s = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
    cl_perror("socket_wait_conn_new: socket() failure");
    return NULL;
  }

  if (unlink(path_name) < 0 && errno != ENOENT) {
	  cl_perror("socket_wait_conn_new: unlink failure(%s)",
		    path_name);
  }
  memset(&my_addr, 0, sizeof(my_addr));
  my_addr.sun_family = AF_LOCAL;         /* host byte order */

  if (strlen(path_name) >= sizeof(my_addr.sun_path)) {
    close(s);
    return NULL;
  }

  strncpy(my_addr.sun_path, path_name, sizeof(my_addr.sun_path));

  if (bind(s, (struct sockaddr *)&my_addr, sizeof(my_addr)) == -1) {
    cl_perror("socket_wait_conn_new: trying to create in %s bind:"
    ,	path_name);
    close(s);
    return NULL;
  }
#elif HB_IPC_METHOD == HB_IPC_STREAM
  /* Set up the communication channel the clients will use to us (server) */
  if (pipe(pipefds) == -1) {
    cl_perror("pipe() failure");
    return NULL;
  }

  /* Let clients have unique connections to us */
  if (ioctl(pipefds[1], I_PUSH, "connld") == -1) {
    cl_perror("ioctl(%d, I_PUSH, \"connld\") failure", pipefds[1]);
    return NULL;
  }

  if (unlink(path_name) < 0 && errno != ENOENT) {
	  cl_perror("socket_wait_conn_new: unlink failure(%s)",
		    path_name);
  }

  if (mkfifo(path_name, s_mode) == -1) {
    cl_perror("socket_wait_conn_new: mkfifo(%s, ...) failure", path_name);
    return NULL;
  }

  if (fattach(pipefds[1], path_name) == -1) {
    cl_perror("socket_wait_conn_new: fattach(..., %s) failure", path_name);
    return NULL;
  }

  /* the pseudo-socket is the other part of the pipe */
  s = pipefds[0];
#endif

  /* Change the permission of the socket */
  if (chmod(path_name,s_mode) < 0) {
    cl_perror("socket_wait_conn_new: failure trying to chmod %s"
    ,	path_name);
    close(s);
    return NULL;
  }

#if HB_IPC_METHOD == HB_IPC_SOCKET
  /* listen to the socket */
  if (listen(s, MAX_LISTEN_NUM) == -1) {
    cl_perror("socket_wait_conn_new: listen(MAX_LISTEN_NUM)");
    close(s);
    return NULL;
  }
#elif HB_IPC_METHOD == HB_IPC_STREAM

#endif

  flags = fcntl(s, F_GETFL);
  if (flags == -1) {
    cl_perror("socket_wait_conn_new: cannot read file descriptor flags");
    close(s);
    return NULL;
  }
  flags |= O_NONBLOCK;
  if (fcntl(s, F_SETFL, flags) < 0) {
    cl_perror("socket_wait_conn_new: cannot set O_NONBLOCK");
    close(s);
    return NULL;
  }

  wait_private =  g_new(struct SOCKET_WAIT_CONN_PRIVATE, 1);
#if HB_IPC_METHOD == HB_IPC_SOCKET
  wait_private->s = s;
#elif HB_IPC_METHOD == HB_IPC_STREAM
  wait_private->pipefds[0] = pipefds[0];
  wait_private->pipefds[1] = pipefds[1];
#endif
  strncpy(wait_private->path_name, path_name, sizeof(wait_private->path_name));
  temp_ch = g_new(struct IPC_WAIT_CONNECTION, 1);
  temp_ch->ch_private = (void *) wait_private;
  temp_ch->ch_status = IPC_WAIT;
  temp_ch->ops = (struct IPC_WAIT_OPS *)&socket_wait_ops;

  return temp_ch;
}

/*
 * will be called by ipc_channel_constructor to create a new socket channel.
 * parameters :
 *      attrs (IN) the hash table of the attributes used to create this channel.
 *
 * return:
 *      the pointer to the new waiting channel or NULL if the channel can't be created.
*/

struct IPC_CHANNEL *
socket_client_channel_new(GHashTable *ch_attrs) {
  char *path_name;
  int sockfd;

  /*
   * I don't really understand why the client and the server use different
   * parameter names...
   *
   * It's a really bad idea to store both integers and strings
   * in the same table.
   *
   * Maybe we need an internal function with a different set of parameters?
   */

  /*
   * if we want to seperate them. I suggest
   * <client side>
   * user call ipc_channel_constructor(ch_type,attrs) to create a new channel.
   * ipc_channel_constructor() call socket_channel_new(GHashTable*)to
   * create a new socket channel.
   * <server side>
   * wait_conn->accept_connection() will call another function to create a
   * new channel.  This function will take socketfd as the parameter to
   * create a socket channel.
   */

  path_name = (char *) g_hash_table_lookup(ch_attrs, IPC_PATH_ATTR);
  if (path_name == NULL) {
	return NULL;
  }

#if HB_IPC_METHOD == HB_IPC_SOCKET
    /* prepare the socket */
    if ((sockfd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
      cl_perror("socket_client_channel_new: socket");
      return NULL;
    }
#elif HB_IPC_METHOD == HB_IPC_STREAM
    sockfd = open(path_name, O_RDWR|O_NONBLOCK);
    if (sockfd == -1) {
      cl_perror("socket_client_channel_new: open(%s, ...) failure", path_name);
      return NULL;
    }
#endif

	if (client_channel_new_auth(sockfd) < 0) {
		close(sockfd);
		return NULL;
	}
  return channel_new(sockfd, IPC_CLIENT, path_name);
}

static
int client_channel_new_auth(int sockfd) {
#ifdef USE_BINDSTAT_CREDS
  char rand_id[16];
  char uuid_str_tmp[40];
  struct sockaddr_un sock_addr;

  /* Prepare the socket */
  memset(&sock_addr, 0, sizeof(sock_addr));
  sock_addr.sun_family = AF_UNIX;

  /* make sure socket paths never clash */
  uuid_generate(rand_id);
  uuid_unparse(rand_id, uuid_str_tmp);

  snprintf(sock_addr.sun_path, sizeof(sock_addr.sun_path),
	   "%s/%s", HA_VARLIBHBDIR, uuid_str_tmp);

  unlink(sock_addr.sun_path);
  if(bind(sockfd, (struct sockaddr*)&sock_addr, SUN_LEN(&sock_addr)) < 0) {
	  perror("Client bind() failure");
	  return 0;
  }
#endif

  return 0;
}

static
struct IPC_CHANNEL *
socket_server_channel_new(int sockfd) {
	return channel_new(sockfd, IPC_SERVER, "?");
}

static
struct IPC_CHANNEL *
channel_new(int sockfd, int conntype, const char *path_name) {
  struct IPC_CHANNEL * temp_ch;
  struct SOCKET_CH_PRIVATE* conn_info;
  int flags;

  if (path_name == NULL || strlen(path_name) >= sizeof(conn_info->path_name)) {
	return NULL;
  }

  temp_ch = g_new(struct IPC_CHANNEL, 1);
  if (temp_ch == NULL) {
	  cl_log(LOG_ERR, "channel_new: allocating memory for channel failed");
	  return NULL;
  }
  memset(temp_ch, 0, sizeof(struct IPC_CHANNEL));

  conn_info = g_new(struct SOCKET_CH_PRIVATE, 1);

  flags = fcntl(sockfd, F_GETFL);
  if (flags == -1) {
	  cl_perror("channel_new: cannot read file descriptor flags");
	  g_free(conn_info); conn_info = NULL;
	  g_free(temp_ch);
	  if (conntype == IPC_CLIENT) close(sockfd);
	  return NULL;
  }
  flags |= O_NONBLOCK;
  if (fcntl(sockfd, F_SETFL, flags) < 0) {
	  cl_perror("channel_new: cannot set O_NONBLOCK");
	  g_free(conn_info); conn_info = NULL;
	  g_free(temp_ch);
	  if (conntype == IPC_CLIENT) close(sockfd);
	  return NULL;
  }

  conn_info->s = sockfd;
  conn_info->remaining_data = 0;
  conn_info->buf_msg = NULL;
#if HB_IPC_METHOD == HB_IPC_SOCKET
  conn_info->peer_addr = NULL;
#endif
  strncpy(conn_info->path_name, path_name, sizeof(conn_info->path_name));

#ifdef DEBUG
  cl_log(LOG_INFO, "Initializing socket %d to DISCONNECT", sockfd);
#endif
  temp_ch->ch_status = IPC_DISCONNECT;
  temp_ch->ch_private = (void*) conn_info;
  temp_ch->ops = (struct IPC_OPS *)&socket_ops;
  temp_ch->msgpad = sizeof(struct SOCKET_MSG_HEAD);
  temp_ch->bytes_remaining = 0;
  temp_ch->should_send_block = FALSE;
  temp_ch->should_block_fail = TRUE;
  temp_ch->send_queue = socket_queue_new();
  temp_ch->recv_queue = socket_queue_new();
  temp_ch->pool = NULL;
  temp_ch->high_flow_mark = temp_ch->send_queue->max_qlen;
  temp_ch->low_flow_mark = -1;
  temp_ch->conntype = conntype;
  temp_ch->refcount = 0;
  temp_ch->farside_uid = -1;
  temp_ch->farside_gid = -1;

  return temp_ch;
}

/*
 * Create a new pair of pre-connected IPC channels similar to
 * the result of pipe(2), or socketpair(2).
 */

int
ipc_channel_pair(IPC_Channel* channels[2])
{
	int	sockets[2];
	int	rc;
	int	j;
	const char *pname;

#if HB_IPC_METHOD == HB_IPC_SOCKET
	pname = "[socketpair]";

	if ((rc = socketpair(AF_LOCAL, SOCK_STREAM, 0, sockets)) < 0) {
		return IPC_FAIL;
	}
#elif HB_IPC_METHOD == HB_IPC_STREAM
	pname = "[pipe]";

	if ((rc = pipe(sockets)) < 0) {
		return IPC_FAIL;
	}
	rc = 0;
	for (j=0; j < 2; ++j) {
		if (fcntl(sockets[j], F_SETFL, O_NONBLOCK) < 0) {
			cl_perror("ipc_channel_pair: cannot set O_NONBLOCK");
			rc = -1;
		}
	}
	if (rc < 0) {
		close(sockets[0]);
		close(sockets[1]);
		return IPC_FAIL;
	}
#endif

	if ((channels[0] = socket_server_channel_new(sockets[0])) == NULL) {
		close(sockets[0]);
		close(sockets[1]);
		return IPC_FAIL;
	}
	if ((channels[1] = socket_server_channel_new(sockets[1])) == NULL) {
		close(sockets[0]);
		close(sockets[1]);
		channels[0]->ops->destroy(channels[0]);
		return IPC_FAIL;
	}
	for (j=0; j < 2; ++j) {
  		struct SOCKET_CH_PRIVATE* p = channels[j]->ch_private;
		channels[j]->ch_status = IPC_CONNECT;
		channels[j]->conntype = IPC_PEER;
		/* Valid, but not terribly meaningful */
		channels[j]->farside_pid = getpid();
  		strncpy(p->path_name, pname, sizeof(p->path_name));
	}

	return IPC_OK;
}

/* brief free the memory space allocated to msg and destroy msg. */

static void
socket_free_message(struct IPC_MESSAGE * msg) {
#if 0
	memset(msg->msg_body, 0xff, msg->msg_len);
#endif
       if (msg->msg_buf) {
               g_free(msg->msg_buf);
       } else {
               g_free(msg->msg_body);
       }
#if 0
	memset(msg, 0xff, sizeof(*msg));
#endif
	g_free((void *)msg);
}

/*
 * create a new ipc message whose msg_body's length is msg_len.
 *
 * parameters :
 *       msg_len (IN) the length of this message body in this message.
 *
 * return :
 *       the pointer to the new message or NULL if the message can't be created.
 */

static struct IPC_MESSAGE*
socket_message_new(struct IPC_CHANNEL *ch, int msg_len)
{
	return ipcmsg_new(ch, NULL, msg_len, NULL, socket_free_message);
}

/***********************************************************************
 *
 * IPC authentication schemes...  More machine dependent than
 * we'd like, but don't know any better way...
 *
 ***********************************************************************/

static int
verify_creds(struct IPC_AUTH *auth_info, uid_t uid, gid_t gid)
{
	int ret = IPC_FAIL;

	if (!auth_info || (!auth_info->uid && !auth_info->gid)) {
		return IPC_OK;
	}
	if (	auth_info->uid
	&&	(g_hash_table_lookup(auth_info->uid
		,	GUINT_TO_POINTER((guint)uid)) != NULL)) {
		ret = IPC_OK;
	} else if (auth_info->gid
	&&	(g_hash_table_lookup(auth_info->gid
		,	GUINT_TO_POINTER((guint)gid)) != NULL)) {
		ret = IPC_OK;
  	}
	return ret;
}

/***********************************************************************
 * SO_PEERCRED VERSION... (Linux)
 ***********************************************************************/

#ifdef USE_SO_PEERCRED
/* verify the authentication information. */
static int
socket_verify_auth(struct IPC_CHANNEL* ch, struct IPC_AUTH * auth_info)
{
	struct SOCKET_CH_PRIVATE *	conn_info;
	int				ret = IPC_FAIL;
	struct ucred			cred;
	socklen_t			n = sizeof(cred);

	if (ch == NULL || ch->ch_private == NULL) {
		return IPC_FAIL;
	}
	if (auth_info == NULL
	||	(auth_info->uid == NULL && auth_info->gid == NULL)) {
		ret = IPC_OK;    /* no restriction for authentication */
	  }

	/* Get the credential information for our peer */
	conn_info = (struct SOCKET_CH_PRIVATE *) ch->ch_private;
	if (getsockopt(conn_info->s, SOL_SOCKET, SO_PEERCRED, &cred, &n) != 0
	||	(size_t)n != sizeof(cred)) {
		return ret;
	}

	ch->farside_uid = cred.uid;
	ch->farside_gid = cred.gid;
	if (ret == IPC_OK) {
		return ret;
	}
#if 0
	cl_log(LOG_DEBUG, "SO_PEERCRED returned [%d, (%ld:%ld)]"
	,	cred.pid, (long)cred.uid, (long)cred.uid);
	cl_log(LOG_DEBUG, "Verifying authentication: cred.uid=%d cred.gid=%d"
	,	cred.uid, cred.gid);
	cl_log(LOG_DEBUG, "Verifying authentication: uidptr=0x%lx gidptr=0x%lx"
	,	(unsigned long)auth_info->uid
	,	(unsigned long)auth_info->gid);
#endif
	/* verify the credential information. */
	return verify_creds(auth_info, cred.uid, cred.gid);
}

/* get farside pid for our peer process */

static
pid_t
socket_get_farside_pid(int sockfd)
{
  socklen_t n;
  struct ucred *cred;
  pid_t f_pid;

  /* Get the credential information from peer */
  n = sizeof(struct ucred);
  cred = g_new(struct ucred, 1);
  if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, cred, &n) != 0) {
    g_free(cred);
    return -1;
  }

  f_pid = cred->pid;
  g_free(cred);
  return f_pid;
}
#endif /* SO_PEERCRED version */

#ifdef USE_GETPEEREID
/*
 * This is implemented in OpenBSD and FreeBSD.
 *
 * It's not a half-bad interface...
 *
 * This should probably be our standard way of doing it, and put it
 * as a replacement library.  That would simplify things...
 */

static int
socket_verify_auth(struct IPC_CHANNEL* ch, struct IPC_AUTH * auth_info)
{
	struct SOCKET_CH_PRIVATE *conn_info;
	uid_t	euid;
	gid_t	egid;
	int	ret = IPC_FAIL;

	if (auth_info == NULL
	||	(auth_info->uid == NULL && auth_info->gid == NULL)) {
		ret = IPC_OK;    /* no restriction for authentication */
	}
	conn_info = (struct SOCKET_CH_PRIVATE *) ch->ch_private;

	if (getpeereid(conn_info->s, &euid, &egid) < 0) {
		cl_perror("getpeereid() failure");
		return ret;
	}

	ch->farside_uid = euid;
	ch->farside_gid = egid;

	/* verify the credential information. */
	return verify_creds(auth_info, euid, egid);
}

static
pid_t
socket_get_farside_pid(int sock)
{
	return -1;
}
#endif /* USE_GETPEEREID */

/***********************************************************************
 * SCM_CREDS VERSION... (*BSD systems)
 ***********************************************************************/
#ifdef USE_SCM_CREDS
/* FIXME!  Need to implement SCM_CREDS mechanism for BSD-based systems
 * This isn't an emergency, but should be done in the future...
 * Hint: * Postgresql does both types of authentication...
 * see src/backend/libpq/auth.c
 * Not clear its SO_PEERCRED implementation works though ;-)
 */

/* Done.... Haven't tested yet. */
static int
socket_verify_auth(struct IPC_CHANNEL* ch, struct IPC_AUTH * auth_info)
{
  struct msghdr msg;
  /* Credentials structure */

#define	EXTRASPACE	0

#ifdef HAVE_STRUCT_CMSGCRED
	/* FreeBSD */
  typedef struct cmsgcred Cred;
#	define crRuid	cmcred_uid
#	define crEuid	cmcred_euid
#	define crRgid	cmcred_gid
#	define crEgid	cmcred_groups[0]	/* Best guess */
#	define crpid	cmcred_pid
#	define crngrp	cmcred_ngroups
#	define crgrps	cmcred_groups

#elif HAVE_STRUCT_FCRED
	/* Stevens' book */
  typedef struct fcred Cred;
#	define crRuid	fc_uid
#	define crRgid	fc_rgid
#	define crEgid	fc_gid
#	define crngrp	fc_ngroups
#	define crgrps	fc_groups

#elif HAVE_STRUCT_SOCKCRED
	/* NetBSD */
  typedef struct sockcred Cred;
#	define crRuid	sc_uid
#	define crEuid	sc_euid
#	define crRgid	sc_gid
#	define crEgid	sc_egid
#	define crngrp	sc_ngroups
#	define crgrps	sc_groups
#	undef EXTRASPACE
#	define EXTRASPACE	SOCKCREDSIZE(ngroups)

#elif HAVE_STRUCT_CRED
  typedef struct cred Cred;
#define cruid c_uid

#elif HAVE_STRUCT_UCRED
 typedef struct ucred Cred;

 /* reuse this define for the moment */
#  if HAVE_STRUCT_UCRED_DARWIN
#	define crEuid	cr_uid
#	define crEgid	cr_groups[0]		/* Best guess */
#	define crgrps	cr_groups
#	define crngrp	cr_ngroups
#  else
#	define crEuid	c_uid
#	define crEgid	c_gid
#  endif
#else
#	error "No credential type found!"
#endif

  struct SOCKET_CH_PRIVATE *conn_info;
  int ret = IPC_FAIL;
  char         buf;

  /* Compute size without padding */
  #define CMSGSIZE	(sizeof(struct cmsghdr)+(sizeof(Cred))+EXTRASPACE)

  union {
  	char		mem[CMSGSIZE];
	struct cmsghdr	hdr;
	Cred		credu;
  }cmsgmem;
  Cred	   cred;

  /* Point to start of first structure */
  struct cmsghdr *cmsg = &cmsgmem.hdr;

  if (auth_info == NULL
  ||	(auth_info->uid == NULL && auth_info->gid == NULL)) {
    ret = IPC_OK;    /* no restriction for authentication */
  }
  conn_info = (struct SOCKET_CH_PRIVATE *) ch->ch_private;

  memset(&msg, 0, sizeof(msg));
  msg.msg_iov =  g_new(struct iovec, 1);
  msg.msg_iovlen = 1;
  msg.msg_control = (char *) cmsg;
  msg.msg_controllen = CMSGSIZE;
  memset(cmsg, 0, sizeof(cmsgmem));

  /*
   * The one character which is received here is not meaningful; its
   * purpose is only to make sure that recvmsg() blocks long enough for
   * the other side to send its credentials.
   */
  msg.msg_iov->iov_base = &buf;
  msg.msg_iov->iov_len = 1;

  if (recvmsg(conn_info->s, &msg, 0) < 0
      || cmsg->cmsg_len < CMSGSIZE
      || cmsg->cmsg_type != SCM_CREDS) {
      cl_perror("can't get credential information from peer");
      return ret;
    }

  /* Avoid alignment issues - just copy it! */
  memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));

  ch->farside_uid = cred.crEuid;
  ch->farside_gid = cred.crEgid;
  if (ret == IPC_OK) {
      return ret;
  }

  /* verify the credential information. */
  return verify_creds(auth_info, cred.crEuid, cred.crEgid);
}

/*
 * FIXME!  Need to implement SCM_CREDS mechanism for BSD-based systems
 * this is similar to the SCM_CREDS mechanism for verify_auth() function.
 * here we just want to get the pid of the other side from the credential
 * information.
 */

static
pid_t
socket_get_farside_pid(int sock)
{
	/* FIXME! */
	return -1;
}
#endif /* SCM_CREDS version */

/***********************************************************************
 * Bind/Stat VERSION... (Supported on OSX/Darwin and 4.3+BSD at least...)
 *
 * This is for use on systems such as OSX-Darwin where
 *   none of the other options is available.
 *
 * This implementation has been adapted from "Advanced Programming
 *   in the Unix Environment", Section 15.5.2, by W. Richard Stevens.
 *
 */
#ifdef USE_BINDSTAT_CREDS

static int
socket_verify_auth(struct IPC_CHANNEL* ch, struct IPC_AUTH * auth_info)
{
	int len = 0;
	int ret = IPC_FAIL;
	struct stat stat_buf;
	struct sockaddr_un *peer_addr = NULL;
	struct SOCKET_CH_PRIVATE *ch_private = NULL;

	if(ch != NULL) {
		ch_private = (struct SOCKET_CH_PRIVATE *)(ch->ch_private);
		if(ch_private != NULL) {
			peer_addr = ch_private->peer_addr;
		}
	}

	if(ch == NULL) {
		cl_log(LOG_ERR, "No channel to authenticate");
		return IPC_FAIL;

	} else if (auth_info == NULL
	    ||	(auth_info->uid == NULL && auth_info->gid == NULL)) {
		ret = IPC_OK;    /* no restriction for authentication */

	}

	if(ch_private == NULL) {
		cl_log(LOG_ERR, "No channel private data available");
		return ret;

	} else if(peer_addr == NULL) {
		cl_log(LOG_ERR, "No peer information available");
		return ret;
	}

	len = SUN_LEN(peer_addr);

	if(len < 1) {
		cl_log(LOG_ERR, "No peer information available");
		return ret;
	}
	peer_addr->sun_path[len] = 0;
	stat(peer_addr->sun_path, &stat_buf);

	ch->farside_uid = stat_buf.st_uid;
	ch->farside_gid = stat_buf.st_gid;
	if (ret == IPC_OK) {
		return ret;
	}

	if ((auth_info->uid == NULL || g_hash_table_size(auth_info->uid) == 0)
	    && auth_info->gid != NULL
	    && g_hash_table_size(auth_info->gid) != 0) {
		cl_log(LOG_WARNING,
		       "GID-Only IPC security is not supported"
		       " on this platform.");
		return IPC_BROKEN;
	}

	/* verify the credential information. */
	return verify_creds(auth_info, stat_buf.st_uid, stat_buf.st_gid);
}

static pid_t
socket_get_farside_pid(int sock)
{
	return -1;
}
#endif /* Bind/stat version */

/***********************************************************************
 * USE_STREAM_CREDS VERSION... (e.g. Solaris pre-10)
 ***********************************************************************/
#ifdef USE_STREAM_CREDS
static int
socket_verify_auth(struct IPC_CHANNEL* ch, struct IPC_AUTH * auth_info)
{
	struct SOCKET_CH_PRIVATE *conn_info;

	if (ch == NULL || ch->ch_private == NULL) {
		return IPC_FAIL;
	}

	conn_info = (struct SOCKET_CH_PRIVATE *) ch->ch_private;

	ch->farside_uid = conn_info->farside_uid;
	ch->farside_gid = conn_info->farside_gid;

	/* verify the credential information. */
	return verify_creds(auth_info,
		conn_info->farside_uid, conn_info->farside_gid);
}

static
pid_t
socket_get_farside_pid(int sock)
{
	return -1;
}
#endif

/***********************************************************************
 * GETPEERUCRED VERSION... (e.g. Solaris 10 upwards)
 ***********************************************************************/

#ifdef USE_GETPEERUCRED
/* verify the authentication information. */
static int
socket_verify_auth(struct IPC_CHANNEL* ch, struct IPC_AUTH * auth_info)
{
	struct SOCKET_CH_PRIVATE *conn_info;
	ucred_t *ucred = NULL;
	int rc = IPC_FAIL;

	if (ch == NULL || ch->ch_private == NULL) {
		return IPC_FAIL;
	}

	conn_info = (struct SOCKET_CH_PRIVATE *) ch->ch_private;

	if (auth_info == NULL
	  || (auth_info->uid == NULL && auth_info->gid == NULL)) {
		rc = IPC_OK;	/* no restriction for authentication */
	}

	if (getpeerucred(conn_info->s, &ucred) < 0) {
		cl_perror("getpeereid() failure");
		return rc;
	}

	ch->farside_uid = ucred_geteuid(ucred);
	ch->farside_gid = ucred_getegid(ucred);
	if (rc == IPC_OK) {
		return rc;
	}

	/* verify the credential information. */
	rc = verify_creds(auth_info,
		ucred_geteuid(ucred), ucred_getegid(ucred));
	ucred_free(ucred);
	return rc;
}

static
pid_t
socket_get_farside_pid(int sockfd)
{
	ucred_t *ucred = NULL;
	pid_t pid;

	if (getpeerucred(sockfd, &ucred) < 0) {
		cl_perror("getpeereid() failure");
		return IPC_FAIL;
	}

	pid = ucred_getpid(ucred);

	ucred_free(ucred);

	return pid;
}
#endif

/***********************************************************************
 * DUMMY VERSION... (other systems...)
 *
 * Other options that seem to be out there include
 * SCM_CREDENTIALS and LOCAL_CREDS
 * There are some kludgy things you can do with SCM_RIGHTS
 * to pass an fd which could only be opened by the user id to
 * validate the user id, but I don't know of a similar kludge which
 * would work for group ids.  And, even the uid one will fail
 * if normal users are allowed to give away (chown) files.
 *
 * Unfortunately, this set of authentication routines have become
 * very important to this API and its users (like heartbeat).
 *
 ***********************************************************************/

#ifdef USE_DUMMY_CREDS
static int
socket_verify_auth(struct IPC_CHANNEL* ch, struct IPC_AUTH * auth_info)
{
	return IPC_FAIL;
}

static
pid_t
socket_get_farside_pid(int sock)
{
	return -1;
}
#endif /* Dummy version */

/* socket object of the function table */
static struct IPC_OPS socket_ops = {
	socket_destroy_channel,
	socket_initiate_connection,
	socket_verify_auth,
	socket_assert_auth,
	socket_send,
	socket_recv,
	socket_waitin,
	socket_waitout,
	socket_is_message_pending,
	socket_is_output_pending,
	socket_resume_io,
	socket_get_send_fd,
	socket_get_recv_fd,
	socket_set_send_qlen,
	socket_set_recv_qlen,
	socket_set_high_flow_callback,
	socket_set_low_flow_callback,
	socket_new_ipcmsg,
	socket_get_chan_status,
	socket_is_sendq_full,
	socket_is_recvq_full,
	socket_get_conntype,
	socket_disconnect,
};
