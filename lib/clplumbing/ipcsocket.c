/*
 * ipcsocket unix domain socket implementation of IPC abstraction.
 *
 * Copyright (c) 2002 Xiaoxiang Liu <xiliu@ncsa.uiuc.edu>
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

#include <portability.h>

#include <clplumbing/ipc.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/realtime.h>
#include <clplumbing/cl_poll.h>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
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
#include <sys/socket.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#ifndef UNIX_PATH_MAX
#	define UNIX_PATH_MAX 108
#endif
#define MAX_LISTEN_NUM 10

#ifndef MSG_NOSIGNAL
#define		MSG_NOSIGNAL	0
#endif

#ifndef AF_LOCAL
#define         AF_LOCAL AF_UNIX
#endif


/* wait connection private data. */
struct SOCKET_WAIT_CONN_PRIVATE{
  /* the path name wich the connection will be built on. */
  char path_name[UNIX_PATH_MAX];
  /* the domain socket. */
  int s;
};

/* channel private data. */
struct SOCKET_CH_PRIVATE{
  /* the path name wich the connection will be built on. */
  char path_name[UNIX_PATH_MAX];
  /* the domain socket. */
  int s;
  /* the size of expecting data for below buffered message buf_msg */
  int remaining_data;
  /* the buf used to save unfinished message */
  struct IPC_MESSAGE *buf_msg;
};

struct SOCKET_MSG_HEAD{
  int msg_len;
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

struct IPC_Stats	SocketIPCStats = {0,0,0,0};

/* unix domain socket implementations of IPC functions. */

static void socket_destroy_wait_conn(struct IPC_WAIT_CONNECTION * wait_conn);

static int socket_wait_selectfd(struct IPC_WAIT_CONNECTION *wait_conn);


static struct IPC_CHANNEL * socket_accept_connection(struct IPC_WAIT_CONNECTION * wait_conn, struct IPC_AUTH *auth_info);

static void socket_destroy_channel(struct IPC_CHANNEL * ch);

static int socket_initiate_connection(struct IPC_CHANNEL * ch);

static int socket_send(struct IPC_CHANNEL * ch, struct IPC_MESSAGE* message);

static int socket_recv(struct IPC_CHANNEL * ch, struct IPC_MESSAGE** message);

static int socket_resume_io(struct IPC_CHANNEL *ch);

static gboolean socket_is_message_pending(struct IPC_CHANNEL *ch);

static gboolean socket_is_output_pending(struct IPC_CHANNEL *ch);

static int socket_assert_auth(struct IPC_CHANNEL *ch, GHashTable *auth);

static int socket_verify_auth(struct IPC_CHANNEL*ch, struct IPC_AUTH*auth_info);

/* for domain socket, reve_fd = send_fd. */

static int socket_get_recv_fd(struct IPC_CHANNEL *ch);

static int socket_get_send_fd(struct IPC_CHANNEL *ch);

static int socket_set_send_qlen (struct IPC_CHANNEL* ch, int q_len);

static int socket_set_recv_qlen (struct IPC_CHANNEL* ch, int q_len);


/* helper functions. */

static int socket_disconnect(struct IPC_CHANNEL* ch);

static struct IPC_QUEUE* socket_queue_new(void);

static void socket_destroy_queue(struct IPC_QUEUE * q);

static struct IPC_MESSAGE* socket_message_new(struct IPC_CHANNEL*ch
,	int msg_len);

void socket_free_message(struct IPC_MESSAGE * msg);

struct IPC_WAIT_CONNECTION *socket_wait_conn_new(GHashTable* ch_attrs);

struct IPC_CHANNEL* socket_client_channel_new(GHashTable *attrs);

struct IPC_CHANNEL* socket_server_channel_new(int sockfd);

pid_t socket_get_farside_pid(int sockfd);

extern int (*ipc_pollfunc_ptr)(struct pollfd *, nfds_t, int);
static int socket_waitin(struct IPC_CHANNEL * ch);

static int socket_waitout(struct IPC_CHANNEL * ch);

static int socket_resume_io_read(struct IPC_CHANNEL *ch, gboolean* started);

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
};



#define	MAXDATASIZE	65535

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
	}else if ((b.st_mode & S_IFMT) != S_IFSOCK) {
		cl_log(LOG_CRIT, "channel @ 0x%lx: not a socket"
		,	(unsigned long)ch);
		badch = TRUE;
	}
	if (chp->remaining_data < 0) {
		cl_log(LOG_CRIT, "Negative remaining_data");
		badch = TRUE;
	}
	if (chp->remaining_data < 0 || chp->remaining_data > MAXDATASIZE) {
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
		close(wc->s);
		cl_poll_ignore(wc->s);
		unlink(wc->path_name);
		g_free(wc);
	}
	g_free((void*) wait_conn);
}

/* return a fd which can be listened on for new connections. */
static int 
socket_wait_selectfd(struct IPC_WAIT_CONNECTION *wait_conn)
{
	struct SOCKET_WAIT_CONN_PRIVATE * wc = wait_conn->ch_private;

	return (wc == NULL ? -1 : wc->s);

}

/* socket accept connection. */
static struct IPC_CHANNEL* 
socket_accept_connection(struct IPC_WAIT_CONNECTION * wait_conn
,	struct IPC_AUTH *auth_info)
{
	struct sockaddr_un			peer_addr;
	struct IPC_CHANNEL *			ch;
	int					sin_size;
	int					s;
	int					new_sock;
	struct SOCKET_WAIT_CONN_PRIVATE*	conn_private;
	struct SOCKET_CH_PRIVATE *		ch_private ;

	/* get select fd */

	s = wait_conn->ops->get_select_fd(wait_conn); 
	if (s < 0) {
		cl_log(LOG_ERR, "get_select_fd: invalid fd");
		return NULL;
	}

	/* Get client connection. */
	sin_size = sizeof(struct sockaddr_un);
	if ((new_sock = accept(s, (struct sockaddr *)&peer_addr, &sin_size)) == -1){
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			cl_perror("socket_accept_connection: accept");
		}
		return NULL;
	}else{
		if ((ch = socket_server_channel_new(new_sock)) == NULL) {
			cl_log(LOG_ERR
			,	"socket_accept_connection: Can't create new channel");
			return NULL;
		}else{
			conn_private=(struct SOCKET_WAIT_CONN_PRIVATE*)
			(	wait_conn->ch_private);
			ch_private = (struct SOCKET_CH_PRIVATE *)(ch->ch_private);
			strncpy(ch_private->path_name,conn_private->path_name
			,		sizeof(conn_private->path_name));
		}
	}

	/* Verify the client authorization information. */

	if (ch->ops->verify_auth(ch, auth_info) == IPC_OK) {
		ch->ch_status = IPC_CONNECT;
		ch->farside_pid = socket_get_farside_pid(new_sock);
		return ch;
	}
  
	return NULL;

}


static void
socket_destroy_channel(struct IPC_CHANNEL * ch)
{
	socket_disconnect(ch);
	socket_destroy_queue(ch->send_queue);
	socket_destroy_queue(ch->recv_queue);
	if (ch->ch_private != NULL) {
    		g_free((void*)(ch->ch_private));
	}
	memset(ch, 0xff, sizeof(*ch));
	g_free((void*)ch);
}

/* 
 * Called by socket_destory(). Disconnect the connection 
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
#if 0
	if (ch->ch_status != IPC_DISCONNECT) {
  		cl_log(LOG_INFO, "forced disconnect for fd %d", conn_info->s);
	}
#endif
	close(conn_info->s);
	cl_poll_ignore(conn_info->s);
	conn_info->s = -1;
	ch->ch_status = IPC_DISCONNECT;
	return IPC_OK;
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
		}else{
#if 0
			cl_log(LOG_INFO, "HUP without input");
#endif
			ch->ch_status = IPC_DISCONNECT;
			return IPC_BROKEN;
		}
	}
	if (sockpoll.revents & POLLIN) {
		int dummy;
		socket_resume_io_read(ch, &dummy);
	}
	return IPC_OK;

}


static int 
socket_initiate_connection(struct IPC_CHANNEL * ch)
{
	struct SOCKET_CH_PRIVATE* conn_info;  
	struct sockaddr_un peer_addr; /* connector's address information */
  
	conn_info = (struct SOCKET_CH_PRIVATE*) ch->ch_private;
  
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
		cl_perror("initiate_connection: connect failure");
		return IPC_FAIL;
	}

	ch->ch_status = IPC_CONNECT;
	ch->farside_pid = socket_get_farside_pid(conn_info->s);
	return IPC_OK;
}


static int 
socket_send(struct IPC_CHANNEL * ch, struct IPC_MESSAGE* msg)
{

	if (msg->msg_len < 0 || msg->msg_len > MAXDATASIZE) {
		return IPC_FAIL;
	}
  
	if (ch->ch_status == IPC_CONNECT
	&&	ch->send_queue->current_qlen < ch->send_queue->max_qlen) {
		/* add the message into the send queue */
		CHECKFOO(0,ch, msg, SavedQueuedBody, "queued message");
		SocketIPCStats.noutqueued++;
		ch->send_queue->queue = g_list_append(ch->send_queue->queue
		,	msg);
		ch->send_queue->current_qlen++;
		/* resume io */
		ch->ops->resume_io(ch);
		return IPC_OK;
	}
  
	return IPC_FAIL;
  
}

static int 
socket_recv(struct IPC_CHANNEL * ch, struct IPC_MESSAGE** message)
{
	GList *element;

	int	result = ch->ops->resume_io(ch);

	*message = NULL;

	if (ch->recv_queue->current_qlen == 0) {
		return result != IPC_OK ? result : IPC_FAIL;
	}
	element = g_list_first(ch->recv_queue->queue);

	if (element == NULL) {
		/* Internal accounting error, but correctable */
		cl_log(LOG_ERR
		, "recv failure: qlen (%d) > 0, but no message found."
		,	ch->recv_queue->current_qlen);
		ch->recv_queue->current_qlen = 0;
		return IPC_FAIL;
	}
	*message = (struct IPC_MESSAGE *) (element->data);

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
#if 0
		cl_log(LOG_INFO, "socket_check_poll(): HUP without input");
#endif
		ch->ch_status = IPC_DISCONNECT;
		return IPC_BROKEN;

	}else if (sockpoll->revents & (POLLNVAL|POLLERR)) {
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
	}else if (ch->ops->is_sending_blocked(ch)) {
		cl_log(LOG_ERR, "socket_waitout output still blocked");
	}
	CHANAUDIT(ch);
	return rc;
}


static gboolean
socket_is_message_pending(struct IPC_CHANNEL * ch)
{

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


static int 
socket_assert_auth(struct IPC_CHANNEL *ch, GHashTable *auth)
{
	cl_log(LOG_ERR
	, "the assert_auth function for domain socket is not implemented");
	return IPC_FAIL;
}



static int
socket_resume_io_read(struct IPC_CHANNEL *ch, gboolean* started)
{
	struct SOCKET_CH_PRIVATE*	conn_info;
	int				retcode = IPC_OK;
	struct pollfd			sockpoll;
	int				debug_loopcount = 0;
	int				debug_bytecount = 0;

	CHANAUDIT(ch);
	conn_info = (struct SOCKET_CH_PRIVATE *) ch->ch_private;
	*started = FALSE;

 
  	while (ch->recv_queue->current_qlen < ch->recv_queue->max_qlen
	&&	retcode == IPC_OK) {

		gboolean			new_msg;
		void *				msg_begin;
		int				msg_len;
		struct SOCKET_MSG_HEAD		head;
		int				len;


		CHANAUDIT(ch);
		++debug_loopcount;
		new_msg = (conn_info->remaining_data == 0);

		if (new_msg) {
			len = sizeof(struct SOCKET_MSG_HEAD);
			msg_begin = &head;
		}else{
			struct IPC_MESSAGE * msg = conn_info->buf_msg;
			len = conn_info->remaining_data;
			msg_begin = ((char*)msg->msg_body)
			+	(msg->msg_len - len);
		}

		if (len <= 0 || len > MAXDATASIZE) {
			cl_log(LOG_ERR
			,	"socket_resume_io_read()"
			": bad packet length [%d]", len);
			ch->ch_status = IPC_DISCONNECT;
			retcode = IPC_BROKEN;
			break;
		}
		CHANAUDIT(ch);

		/* Now try to receive some data */

		msg_len = recv(conn_info->s, msg_begin, len, MSG_DONTWAIT);
		SocketIPCStats.last_recv_rc = msg_len;
		SocketIPCStats.last_recv_errno = errno;
		++SocketIPCStats.recv_count;
#ifdef DEBUG
		cl_perror("recv() => %d, errno = %d loopcount = %d, %s"
		,	msg_len, errno, debug_loopcount
		,	(new_msg ? "msg head": "msg body"));
#endif

		CHANAUDIT(ch);

		/* Did we get an error? */
		if (msg_len < 0) {
			/* What kind of error did we get? */
			switch (errno) {
				case EAGAIN:
					if (ch->ch_status==IPC_DISC_PENDING){
						ch->ch_status =IPC_DISCONNECT;
						retcode = IPC_BROKEN;
					}
					break;
						
				case ECONNREFUSED:
				case ECONNRESET:
					retcode
					= socket_check_disc_pending(ch);
					break;

				default:
					cl_perror("socket_resume_io_read"
					": unknown recv error");
					ch->ch_status = IPC_DISCONNECT;
					retcode = IPC_FAIL;
					break;
			}
			break; /* out of loop */
    		}
		if (msg_len == 0) {
			if (ch->ch_status == IPC_DISC_PENDING
			&&	ch->recv_queue->current_qlen <= 0) {
				ch->ch_status = IPC_DISCONNECT;
				retcode = IPC_FAIL;
			}
			break;
		}
		/* How about that!  We read something! */
		/* Note that all previous cases break out of the loop */
		debug_bytecount += msg_len;
		*started=TRUE;

#if 0
		cl_log(LOG_DEBUG, "Got %d byte message", msg_len);
		cl_log(LOG_DEBUG, "Contents: %s", (char*)msg_begin);
#endif
		/* Is this data for the start of a new message? */
		if (new_msg){
			/* We assume we read 'len' bytes */
			if (head.msg_len <= 0
			||	head.msg_len > MAXDATASIZE) {
				cl_log(LOG_CRIT
				,	"socket_resume_io_read()"
				": Invalid msg len [%d]"
				,	head.msg_len);
				ch->ch_status = IPC_DISCONNECT;
				retcode = IPC_FAIL;
				break;
			}
			conn_info->buf_msg
			= socket_message_new(ch, head.msg_len);
			conn_info->remaining_data = head.msg_len;
			/* Next time we'll read the message body */
			continue;
		}


		/* No, not the start of a new message. Therefore we */
		/* must have received (more) data from an old message */

		conn_info->remaining_data = conn_info->remaining_data
		-	msg_len;

		if (conn_info->remaining_data < 0){
			cl_log(LOG_CRIT
			,	"received more data than expected");
			conn_info->remaining_data = 0;
			retcode = IPC_FAIL;

		}else if (conn_info->remaining_data == 0){
#if 0
			cl_log(LOG_DEBUG, "channel: 0x%lx"
			,	(unsigned long)ch);
			cl_log(LOG_DEBUG, "New recv_queue = 0x%lx"
			,	(unsigned long)ch->recv_queue);
			cl_log(LOG_DEBUG, "buf_msg: len = %ld, body =  0x%lx"
			,	(unsigned long)conn_info->buf_msg->msg_len
			,	(unsigned long)conn_info->buf_msg->msg_body);
			cl_log(LOG_DEBUG, "buf_msg: contents: %s"
			,	(char *)conn_info->buf_msg->msg_body);
#endif
			/* Got the last of the message! */

			/* Append gotten message to receive queue */
			CHECKFOO(2,ch, conn_info->buf_msg, SavedReceivedBody
			,	"received message");
			ch->recv_queue->queue =	g_list_append
			(	ch->recv_queue->queue, conn_info->buf_msg);
			ch->recv_queue->current_qlen++;
			SocketIPCStats.ninqueued++;
			conn_info->buf_msg = NULL;
		}
	}

	/* Check for errors uncaught by recv() */
	/* NOTE: It doesn't seem right we have to do this every time */
	/* FIXME?? */
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
socket_resume_io_write(struct IPC_CHANNEL *ch, gboolean* started)
{
	int				retcode = IPC_OK;
	struct SOCKET_CH_PRIVATE*	conn_info;


	CHANAUDIT(ch);
	conn_info = (struct SOCKET_CH_PRIVATE *) ch->ch_private;
	*started = FALSE;
  
 
	while (ch->ch_status == IPC_CONNECT
	&&		retcode == IPC_OK
	&&		ch->send_queue->current_qlen > 0) {

		GList *				element;
		struct IPC_MESSAGE *		msg;
		struct SOCKET_MSG_HEAD		head;
		int				sendrc = 0;

		CHANAUDIT(ch);
		element = g_list_first(ch->send_queue->queue);
		if (element == NULL) {
			/* OOPS!  - correct consistency problem */
			ch->send_queue->current_qlen = 0;
			break;
		}
		msg = (struct IPC_MESSAGE *) (element->data);
		head.msg_len = msg->msg_len;

		/* Send message header */
		sendrc = send(conn_info->s, (char *)&head
		,	sizeof(struct SOCKET_MSG_HEAD)
		,	(MSG_DONTWAIT|MSG_NOSIGNAL));
		SocketIPCStats.last_send_rc = sendrc;
		SocketIPCStats.last_send_errno = errno;
		++SocketIPCStats.send_count;
#ifdef DEBUG
		cl_log(LOG_DEBUG, "Sent %d byte message header"
		,	sizeof(struct SOCKET_MSG_HEAD));
#endif


		if (sendrc < 0) {
			switch (errno) {
				case EAGAIN:
#ifdef DEBUG
					cl_log(LOG_DEBUG,
						"socket send returned EAGAIN");
#endif
					/* FIXME! KLUDGE! */
					/* We could fix this if we kept better
					 * state info so we could retry this
					 * operation later and not be confused.
					 * This is the right thing to do!
					 */
					cl_shortsleep();
					continue;
				case EPIPE:
					socket_check_disc_pending(ch);
					retcode = IPC_BROKEN;
					break;
				default:
					cl_perror("socket_resume_io_write: send1 bad errno");
					ch->ch_status = IPC_DISCONNECT;
					retcode = IPC_FAIL;
					break;
			}
			break;
    		}
		*started=TRUE;


		do {
			CHANAUDIT(ch);
			sendrc = send(conn_info->s, msg->msg_body
			,	msg->msg_len, (MSG_DONTWAIT|MSG_NOSIGNAL));
			SocketIPCStats.last_send_rc = sendrc;
			SocketIPCStats.last_send_errno = errno;
			++SocketIPCStats.send_count;
#ifdef DEBUG
			cl_log(LOG_DEBUG, "send(%d bytes)  => %d errno=%d"
			,	msg->msg_len, sendrc, errno);
#endif

			/* if send failed with EAGAIN, delay and try again */
			/* FIXME! KLUDGE! */
			/* We could fix this if we kept better
			 * state info so we could retry this
			 * operation later and not be confused.
			 * This is the right thing to do!
			 */
		} while(sendrc < 0
		&&	(errno == EAGAIN ? (cl_shortsleep(), TRUE) : FALSE));

		if (sendrc > 0 && sendrc != (int)msg->msg_len) {
			cl_perror("Sent %d byte message body: rc = %d"
			,	(int)msg->msg_len, sendrc);
		}

#ifdef DEBUG
		cl_log(LOG_DEBUG, "Sent %d byte message body"
		,	msg->msg_len);
		cl_log(LOG_DEBUG, "Contents sent: %s",(char*)msg->msg_body);
#endif

		if (sendrc < 0) {
			switch (errno) {
				case EPIPE:
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
		}else{
			CHECKFOO(3,ch, msg, SavedSentBody, "sent message")
			ch->send_queue->queue = g_list_remove(
					ch->send_queue->queue,	msg);
			if (msg->msg_done != NULL) {
				msg->msg_done(msg);
			}
			SocketIPCStats.nsent++;
			ch->send_queue->current_qlen--;
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
	int		rc1, rc2;
	gboolean	rstarted;
	gboolean	wstarted;
	gboolean	OKonce = FALSE;
#ifdef DEBUG
	int		count = 0;
#endif

	CHANAUDIT(ch);
	if (!IPC_ISRCONN(ch)) {
		return IPC_BROKEN;
	}

	do {
		rc1 = socket_resume_io_read(ch, &rstarted);
		CHANAUDIT(ch);
		if (ch->ch_status == IPC_DISC_PENDING) {
			rc2 = IPC_OK;
			wstarted = FALSE;
		}else{
			rc2 = socket_resume_io_write(ch, &wstarted);
		}
		CHANAUDIT(ch);
		if (rc1 == IPC_OK || rc2 == IPC_OK) {
			OKonce = TRUE;
		}
#ifdef DEBUG
		++count;
		if (rc1 == IPC_OK && rc2 == IPC_OK && (rstarted||wstarted)) {
			cl_log(LOG_DEBUG
			,	"continuing: rstarted = %d wstarted = %d count: %d"
			,	rstarted, wstarted, count);
		}
#endif
	} while ((rstarted||wstarted) && IPC_ISRCONN(ch));

	if (IPC_ISRCONN(ch)) {
		if (rc1 != IPC_OK) {
			cl_log(LOG_ERR
			,	"socket_resume_io_read() failure");
		}
		if (rc2 != IPC_OK) {
			cl_log(LOG_ERR
			,	"socket_resume_io_write() failure");
		}
	}else{
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

static int
socket_set_send_qlen (struct IPC_CHANNEL* ch, int q_len)
{
  /* This seems more like an assertion failure than a normal error */
  if (ch->send_queue == NULL) {
    return IPC_FAIL;
  }
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
  
  ch->recv_queue->max_qlen = q_len;
  return IPC_OK;
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
  return temp_queue;
}


/* 
 * destory a ipc queue and clean all memory space assigned to this queue.
 * parameters:
 *      q  (IN) the pointer to the queue which should be destroied.
 *
 *	FIXME:  This function does not free up messages that might
 *	be in the queue.
 */ 

void
socket_destroy_queue(struct IPC_QUEUE * q)
{
  g_list_free(q->queue);

  g_free((void *) q);
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
 */
struct IPC_WAIT_CONNECTION *
socket_wait_conn_new(GHashTable *ch_attrs)
{
  struct IPC_WAIT_CONNECTION * temp_ch;
  char *path_name;
  char *mode_attr;
  struct sockaddr_un my_addr;
  int s;
  struct SOCKET_WAIT_CONN_PRIVATE *wait_private;
  mode_t s_mode;
  
  path_name = (char *) g_hash_table_lookup(ch_attrs, IPC_PATH_ATTR);
  mode_attr = (char *) g_hash_table_lookup(ch_attrs, IPC_MODE_ATTR);

  if (mode_attr != NULL) {
    s_mode = (mode_t)strtoul((const char *)mode_attr, NULL, 8);
  }else{
    s_mode = 0777;
  }
  if (path_name == NULL) {
    return NULL;
  }

  /* prepare the unix domain socket */
  if ((s = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
    cl_perror("socket_wait_conn_new: socket() failure");
    return NULL;
  }

  if (unlink(path_name) < 0 && errno != ENOENT) {
    cl_perror("socket_wait_conn_new: unlink failure");
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

  /* Change the permission of the socket */
  if (chmod(path_name,s_mode) < 0){
    cl_perror("socket_wait_conn_new: failure trying to chmod %s"
    ,	path_name);
    close(s);
    return NULL;
  }

  /* listen to the socket */
  if (listen(s, MAX_LISTEN_NUM) == -1) {
    cl_perror("socket_wait_conn_new: listen(MAX_LISTEN_NUM)");
    close(s);
    return NULL;
  }
  if (fcntl(s, F_SETFL, O_NONBLOCK) < 0) {
    cl_perror("socket_wait_conn_new: cannot set O_NONBLOCK");
    close(s);
    return NULL;
  }
  
  wait_private =  g_new(struct SOCKET_WAIT_CONN_PRIVATE, 1);
  wait_private->s = s;
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
  struct IPC_CHANNEL * temp_ch;
  struct SOCKET_CH_PRIVATE* conn_info;
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
  if (path_name != NULL) { 
    if (strlen(path_name) >= sizeof(conn_info->path_name)) {
      	return NULL;
    }
    /* prepare the socket */
    if ((sockfd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
      cl_perror("socket_client_channel_new: socket");
      return NULL;
    }
  }else{
    return NULL;
  }

  temp_ch = g_new(struct IPC_CHANNEL, 1);
  conn_info = g_new(struct SOCKET_CH_PRIVATE, 1);


  conn_info->s = sockfd;
  conn_info->remaining_data = 0;
  conn_info->buf_msg = NULL;
  
  strncpy(conn_info->path_name, path_name, sizeof(conn_info->path_name));
  temp_ch->ch_status = IPC_DISCONNECT;
#ifdef DEBUG
  cl_log(LOG_INFO, "Initializing client socket %d to DISCONNECT", sockfd);
#endif
  temp_ch->ch_private = (void*) conn_info;
  temp_ch->ops = (struct IPC_OPS *)&socket_ops;
  temp_ch->send_queue = socket_queue_new();
  temp_ch->recv_queue = socket_queue_new();
   
  return temp_ch;
  
}

struct IPC_CHANNEL * 
socket_server_channel_new(int sockfd){
  struct IPC_CHANNEL * temp_ch;
  struct SOCKET_CH_PRIVATE* conn_info;
  
  
  temp_ch = g_new(struct IPC_CHANNEL, 1);
  conn_info = g_new(struct SOCKET_CH_PRIVATE, 1);


  conn_info->s = sockfd;
  conn_info->remaining_data = 0;
  conn_info->buf_msg = NULL;
  strcpy(conn_info->path_name, "?");

#ifdef DEBUG
  cl_log(LOG_INFO, "Initializing server socket %d to DISCONNECT", sockfd);
#endif
  temp_ch->ch_status = IPC_DISCONNECT;
  temp_ch->ch_private = (void*) conn_info;
  temp_ch->ops = (struct IPC_OPS *)&socket_ops;
  temp_ch->send_queue = socket_queue_new();
  temp_ch->recv_queue = socket_queue_new();
   
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

	if ((rc = socketpair(AF_LOCAL, SOCK_STREAM, 0, sockets)) < 0) {
		return IPC_FAIL;
	}
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
		/* Valid, but not terribly meaningful */
		channels[j]->farside_pid = getpid();
  		strncpy(p->path_name, "[socketpair]", sizeof(p->path_name));
	}

	return IPC_OK;
	
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
  struct IPC_MESSAGE * temp_msg;

  temp_msg = g_new(struct IPC_MESSAGE, 1);
  temp_msg->msg_body = g_malloc(msg_len);
  temp_msg->msg_len = msg_len;
  temp_msg->msg_private = NULL;
  temp_msg->msg_ch = ch;
  temp_msg->msg_done = socket_free_message;

  return temp_msg;
}


/* brief free the memory space allocated to msg and destroy msg. */

void
socket_free_message(struct IPC_MESSAGE * msg) {

#if 0
	memset(msg->msg_body, 0xff, msg->msg_len);
#endif
	g_free(msg->msg_body);
#if 0
	memset(msg, 0xff, sizeof(*msg));
#endif
	g_free((void *)msg);
}



/***********************************************************************
 *
 * IPC authentication schemes...  More machine dependent than
 * we'd like, but don't know any better way...
 *
 ***********************************************************************/


#ifdef SO_PEERCRED
#	define	USE_SO_PEERCRED
#elif defined(SCM_CREDS)
#	define	USE_SCM_CREDS
#else
#	define	USE_DUMMY_CREDS
	/* This will make it compile, but attempts to authenticate
	 * will fail.  This is a stopgap measure ;-)
	 */
#endif

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
		return IPC_OK;    /* no restriction for authentication */
	  }

	/* Get the credential information for our peer */
	conn_info = (struct SOCKET_CH_PRIVATE *) ch->ch_private;
	if (getsockopt(conn_info->s, SOL_SOCKET, SO_PEERCRED, &cred, &n) != 0
	||	(size_t)n != sizeof(cred)) {
		return IPC_FAIL;
	}
#if 1
	cl_log(LOG_DEBUG, "SO_PEERCRED returned [%d, (%ld:%ld)]"
	,	cred.pid, (long)cred.uid, (long)cred.uid);
	cl_log(LOG_DEBUG, "Verifying authentication: cred.uid=%d cred.gid=%d"
	,	cred.uid, cred.gid);
	cl_log(LOG_DEBUG, "Verifying authentication: uidptr=0x%lx gidptr=0x%lx"
	,	(unsigned long)auth_info->uid
	,	(unsigned long)auth_info->gid);
#endif

  
	/* verify the credential information. */
	if (	auth_info->uid
	&&	(g_hash_table_lookup(auth_info->uid
		,	GUINT_TO_POINTER((guint)cred.uid)) != NULL)) {
		ret = IPC_OK;
	}else if (auth_info->gid
	&&	(g_hash_table_lookup(auth_info->gid
		,	GUINT_TO_POINTER((guint)cred.gid)) != NULL)) {
		ret = IPC_OK;
  	}
	return ret;
}

/* get farside pid for our peer process */

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
#ifdef HAVE_STRUCT_CMSGCRED
  typedef struct cmsgcred Cred;
#define cruid cmcred_uid

#elif HAVE_STRUCT_FCRED
  typedef struct fcred Cred;
#define cruid fc_uid

#elif HAVE_STRUCT_SOCKCRED
  typedef struct sockcred Cred;
#define cruid sc_uid

#elif _HAVE_CRED_H
  typedef struct cred Cred;
#define cruid c_uid
#else
 typedef struct ucred Cred;
#define cruid c_uid
#endif

  Cred	   *cred;
  struct SOCKET_CH_PRIVATE *conn_info;
  int ret = IPC_OK;
  char         buf;
  
  /* Compute size without padding */
  char		cmsgmem[ALIGN(sizeof(struct cmsghdr)) + ALIGN(sizeof(Cred))];	/* for NetBSD */

  /* Point to start of first structure */
  struct cmsghdr *cmsg = (struct cmsghdr *) cmsgmem;
  

  if (auth_info == NULL
  ||	(auth_info->uid == NULL && auth_info->gid == NULL)) {
    return IPC_OK;    /* no restriction for authentication */
  }
  conn_info = (struct SOCKET_CH_PRIVATE *) ch->ch_private;

  memset(&msg, 0, sizeof(msg));
  msg.msg_iov =  g_new(struct iovec, 1);
  msg.msg_iovlen = 1;
  msg.msg_control = (char *) cmsg;
  msg.msg_controllen = sizeof(cmsgmem);
  memset(cmsg, 0, sizeof(cmsgmem));

  /*
   * The one character which is received here is not meaningful; its
   * purpose is only to make sure that recvmsg() blocks long enough for
   * the other side to send its credentials.
   */
  msg.msg_iov->iov_base = &buf;
  msg.msg_iov->iov_len = 1;
  
  if (recvmsg(conn_info->s, &msg, 0) < 0 
      || cmsg->cmsg_len < sizeof(cmsgmem) 
      || cmsg->cmsg_type != SCM_CREDS) {
      cl_perror("can't get credential information from peer");
      return IPC_FAIL;
    }

  cred = (Cred *) CMSG_DATA(cmsg);

  /* This is weird... Shouldn't cr_uid be cruid instead? FIXME??*/
  /* Either that, or we shouldn't be defining it above... */
  /* Also, what about the group id field name? */
  /* FIXME! */

  if (	auth_info->uid
  &&	g_hash_table_lookup(auth_info->uid, &(cred->cr_uid)) == NULL) {
		ret = IPC_FAIL;
  }
  if (	auth_info->gid
  &&	g_hash_table_lookup(auth_info->gid, &(cred->cr_groups)) == NULL) {
		ret = IPC_FAIL;
  }

  return ret;
}

/* FIXME!  Need to implement SCM_CREDS mechanism for BSD-based systems
 * this is similar to the SCM_CREDS mechanism for verify_auth() function.
 * here we just want to get the pid of the other side from the credential 
 * information.
 */

pid_t
socket_get_farside_pid(int sock)
{
	/* FIXME! */
	return -1;
}
#endif /* SCM_CREDS version */


/***********************************************************************
 * DUMMY VERSION... (other systems...)
 ***********************************************************************/

#ifdef USE_DUMMY_CREDS
static int 
socket_verify_auth(struct IPC_CHANNEL* ch, struct IPC_AUTH * auth_info)
{
	return IPC_FAIL;
}

pid_t
socket_get_farside_pid(int sock){
	return -1;
}
#endif /* Dummy version */
