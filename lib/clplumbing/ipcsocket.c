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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
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
#define UNIX_PATH_MAX 108
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

static gboolean socket_is_sending_blocked(struct IPC_CHANNEL *ch);

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

static int (*ourpollfunc)(struct pollfd *, nfds_t, int) = poll;

/* destroy socket wait channel */ 
static void 
socket_destroy_wait_conn(struct IPC_WAIT_CONNECTION * wait_conn)
{
  struct SOCKET_WAIT_CONN_PRIVATE * wc = wait_conn->ch_private;

  if (wc != NULL) {
    close(wc->s);
    unlink(wc->path_name);
    free(wc);
  }
  free((void*) wait_conn);
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
  struct sockaddr_un peer_addr;
  struct IPC_CHANNEL *ch;
  int sin_size;
  int s, new_sock;
  struct SOCKET_WAIT_CONN_PRIVATE *conn_private;
  struct SOCKET_CH_PRIVATE *ch_private ;
  
  /* get select fd */
  s = wait_conn->ops->get_select_fd(wait_conn); 
  if (s < 0) {
    cl_log(LOG_ERR, "get_select_fd: invalid fd");
    return NULL;
  }

  /* get client connection. */
  sin_size = sizeof(struct sockaddr_un);
  if ((new_sock = accept(s, (struct sockaddr *)&peer_addr, &sin_size)) == -1) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
        cl_perror("socket_accept_connection: accept");
    }
    return NULL;
  }else{
    if ((ch = socket_server_channel_new(new_sock)) == NULL) {
      cl_log(LOG_ERR, "socket_accept_connection: Can't create new channel");
      return NULL;
    }else{
      conn_private = (struct SOCKET_WAIT_CONN_PRIVATE *)(wait_conn->ch_private);
      ch_private = (struct SOCKET_CH_PRIVATE *)(ch->ch_private);
      strncpy(ch_private->path_name,conn_private->path_name
      ,		sizeof(conn_private->path_name));
    }
  }
  /* verify the client authentication information. */
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
  if(ch->ch_private != NULL)
    free((void*)(ch->ch_private));
  
  free((void*) ch);
}

/* 
 * will called by the socket_destory. Disconnec the connection 
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
  close(conn_info->s);
  ch->ch_status = IPC_DISCONNECT;
  return IPC_OK;
}


static int 
socket_initiate_connection(struct IPC_CHANNEL * ch)
{
  struct SOCKET_CH_PRIVATE* conn_info;  
  struct sockaddr_un peer_addr; /* connector's address information */
  
  conn_info = (struct SOCKET_CH_PRIVATE*) ch->ch_private;
  
  /* prepare the socket */
  memset(&peer_addr, 0, sizeof(peer_addr));
  peer_addr.sun_family = AF_LOCAL;    /* host byte order */ 

  if (strlen(conn_info->path_name) >= sizeof(peer_addr.sun_path)) {
    return IPC_FAIL;
  }
  strncpy(peer_addr.sun_path, conn_info->path_name, sizeof(peer_addr.sun_path));
  /* send connection request */
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
socket_send(struct IPC_CHANNEL * ch, struct IPC_MESSAGE* message)
{
  
  
  if (ch->send_queue->current_qlen < ch->send_queue->max_qlen) {
    /* add the meesage into the send queue */
    ch->send_queue->queue = g_list_append(ch->send_queue->queue, message);
    ch->send_queue->current_qlen++;
    /* resume io */
    return ch->ops->resume_io(ch);
        
  }
  
  
  return IPC_FAIL;
  
}

static int 
socket_recv(struct IPC_CHANNEL * ch, struct IPC_MESSAGE** message)
{
  int result;
  struct pollfd sockpoll;
  
  result = ch->ops->resume_io(ch);
  
  if ((result == IPC_OK) && (ch->recv_queue->current_qlen != 0)) {
      GList *element = g_list_first(ch->recv_queue->queue);
      if (element != NULL) {
	*message = (struct IPC_MESSAGE *) (element->data);
	      
	ch->recv_queue->queue = g_list_remove(ch->recv_queue->queue
	,	element->data);
	ch->recv_queue->current_qlen--;
      
	return IPC_OK;
      }
  }

  if (ch->ch_status == IPC_DISCONNECT) {
	return IPC_BROKEN;
  }
  result = IPC_FAIL;
  *message = NULL;

  if ((sockpoll.fd = socket_get_recv_fd(ch)) >= 0) {
    	/* check if the server still exists */
  	sockpoll.events = POLLHUP;
	if ((ourpollfunc(&sockpoll, 1, 0)) && sockpoll.revents) {
  		ch->ch_status = IPC_DISCONNECT;
		return IPC_BROKEN;
	 }
  }
  errno = EAGAIN;
  return result;
}

static int
socket_waitin(struct IPC_CHANNEL * ch)
{
	struct pollfd sockpoll[2];

 	if (ch->ch_status == IPC_DISCONNECT) {
 		return IPC_BROKEN;
	}
	sockpoll[0].fd = ch->ops->get_recv_select_fd(ch);
	sockpoll[1].fd = ch->ops->get_send_select_fd(ch);
	sockpoll[1].events = POLLHUP|POLLNVAL|POLLERR|POLLOUT;

	do {
		int	rc;
		int	nfd = 1;

		sockpoll[0].events = POLLHUP|POLLNVAL|POLLERR|POLLIN;

		if (ch->ops->is_sending_blocked(ch)) {
			if (sockpoll[0].fd == sockpoll[1].fd) {
				sockpoll[0].events |= POLLOUT;
			}else{
				nfd=2;
			}
		}

		rc = ourpollfunc(sockpoll, nfd, -1);

		if (rc < 0) {
			return (errno == EINTR ? IPC_INTR : IPC_FAIL);
		}
		if (sockpoll[0].revents & POLLHUP) {
 			ch->ch_status = IPC_DISCONNECT;
 			return IPC_BROKEN;
		}
		if (sockpoll[0].revents & (POLLNVAL|POLLERR)) {
			cl_log(LOG_ERR
			,	"revents[0] failure: fd %d, flags 0x%x"
			,	sockpoll[0].fd, sockpoll[0].revents);
			errno = EINVAL;
 			return IPC_FAIL;
		}
		if (nfd == 2) {
			if (sockpoll[1].revents & POLLHUP) {
				ch->ch_status = IPC_DISCONNECT;
				return IPC_BROKEN;
			}
			if (sockpoll[1].revents & (POLLNVAL|POLLERR)) {
				cl_log(LOG_ERR
				,	"revents[1] failure: fd %d, flags 0x%x"
				,	sockpoll[1].fd, sockpoll[1].revents);
				errno = EINVAL;
				return IPC_FAIL;
			}
		}
		ch->ops->resume_io(ch);
	} while (!ch->ops->is_message_pending(ch));

	return IPC_OK;
}

static gboolean
socket_is_message_pending(struct IPC_CHANNEL * ch)
{
  struct SOCKET_CH_PRIVATE * conn_info = ch->ch_private;
  struct pollfd sockpoll;

  if (ch->recv_queue->current_qlen > 0 || conn_info->buf_msg != NULL) {
    return TRUE;
  }

  if((sockpoll.fd = socket_get_recv_fd(ch)) != -1) {
  	sockpoll.events = POLLIN|POLLHUP;
	if ((ourpollfunc(&sockpoll, 1, 0)) && sockpoll.revents) {
		if (sockpoll.revents & POLLHUP) {
 			ch->ch_status = IPC_DISCONNECT;
		}
		return TRUE;
	 }
  }
  return FALSE;
}

static gboolean
socket_is_sending_blocked(struct IPC_CHANNEL * ch)
{

  socket_resume_io(ch);

  return ch->send_queue->current_qlen > 0;
}


static int 
socket_assert_auth(struct IPC_CHANNEL *ch, GHashTable *auth)
{
  cl_log(LOG_ERR
  , "the assert_auth function for domain socket is not implemented");
  return IPC_FAIL;
}



static int
socket_resume_io(struct IPC_CHANNEL *ch)
{
  int len,msg_len;
  struct IPC_MESSAGE *msg;
  struct SOCKET_CH_PRIVATE* conn_info;
  GList *element;
  struct SOCKET_MSG_HEAD head;
  char *msg_begin = NULL;
  gboolean new_msg = FALSE;

  conn_info = (struct SOCKET_CH_PRIVATE *) ch->ch_private;
  
  while (ch->ch_status == IPC_CONNECT
  &&		ch->recv_queue->current_qlen < ch->recv_queue->max_qlen) {
    /* check how much data queued. */
    if(ioctl(conn_info->s, FIONREAD,&len) < 0){
      cl_perror("socket_resume_io: ioctl FIONREAD failed");
      return IPC_FAIL;
    }

    if(len <= 0) break;
    if(conn_info->remaining_data != 0){
	new_msg = FALSE;
	len = conn_info->remaining_data;
	msg = conn_info->buf_msg;
	msg_begin = (char *) msg->msg_body + (msg->msg_len - len); 
    }else{
	msg_begin = (char *)&head;
	new_msg = TRUE;
    }

    if(new_msg){
      msg_len = recv(conn_info->s, (char *)&head , sizeof(struct SOCKET_MSG_HEAD) ,MSG_DONTWAIT );
    }else{
      msg_len = recv(conn_info->s, msg_begin, len , MSG_DONTWAIT);
    }
    if (msg_len < 0){
      if(errno == EAGAIN) {
	break;
      }else if( errno == ECONNREFUSED){
	ch->ch_status = IPC_DISCONNECT;
	return IPC_BROKEN;
      }else{
	ch->ch_status = IPC_DISCONNECT;
	return IPC_FAIL;
      }
    }

    if (msg_len > 0) {
      if(new_msg){
	msg = socket_message_new(ch, head.msg_len + 1);
	msg->msg_done = socket_free_message;
	msg->msg_ch = ch;
	msg->msg_len = head.msg_len;
	conn_info->buf_msg = msg;
	conn_info->remaining_data = head.msg_len;
	msg = NULL;
      }else{
	if(msg_len == conn_info->remaining_data){
	  ch->recv_queue->queue
          =	g_list_append(ch->recv_queue->queue, conn_info->buf_msg);
#if 0
          cl_log(LOG_DEBUG, "channel: 0x%lx", (unsigned long)ch);
          cl_log(LOG_DEBUG, "New recv_queue = 0x%lx"
	  ,	(unsigned long)ch->recv_queue);
          cl_log(LOG_DEBUG, "buf_msg: len = %ld, body =  0x%lx"
	  ,	conn_info->buf_msg->msg_len
	  ,	(unsigned long)conn_info->buf_msg->msg_body);
#endif
	  ch->recv_queue->current_qlen++;
	  conn_info->buf_msg = NULL;
	  conn_info->remaining_data = 0;
	}else if(msg_len < conn_info->remaining_data){
	  conn_info->remaining_data = conn_info->remaining_data - msg_len;
	}else{
	  /* Wrong! */
	  cl_log(LOG_INFO, " received more data than expected");
	  return IPC_FAIL;
	}
      }
    }else{
      break;
    }
  }
  
 
  len = 0;
  while (ch->ch_status == IPC_CONNECT
  &&		len >=0 && ch->send_queue->current_qlen >0) {

    element = g_list_first(ch->send_queue->queue);
    if (element != NULL) {
      msg = (struct IPC_MESSAGE *) (element->data);
      head.msg_len = msg->msg_len;

      len=send(conn_info->s, (char *)&head
      ,			sizeof(struct SOCKET_MSG_HEAD)
      ,			(MSG_DONTWAIT|MSG_NOSIGNAL));

      if (len < 0){
	if(errno == EAGAIN) {
	  break;
	}else if (errno == EPIPE){
	  ch->ch_status = IPC_DISCONNECT;
	  return IPC_BROKEN;
	}else{
	  ch->ch_status = IPC_DISCONNECT;
	  return IPC_FAIL;	  
	}
      }

      if (ch->ch_status != IPC_CONNECT) {
		break;
      }

      len=send(conn_info->s, msg->msg_body, msg->msg_len
      ,			(MSG_DONTWAIT|MSG_NOSIGNAL));
      if (len < 0){
	if (errno == EAGAIN) {
	  break;
	}else if (errno == EPIPE){
	  ch->ch_status = IPC_DISCONNECT;
	  return IPC_BROKEN;
	}else{
	  ch->ch_status = IPC_DISCONNECT;
	  return IPC_FAIL;	  
	}
      }
    
      if (len > 0 ) {
	if (len < msg->msg_len){
	  /* 
	   * FIXME! for stream domain socket, if the message is too big, it 
	   * may cause part of the message cut instead of being sent out.
	   * We may need to implement the fragmentation for sending. 
	   * 
	   */
	  cl_log(LOG_ERR, "can't send all data out %d",len);
	}
	ch->send_queue->queue = g_list_remove(ch->send_queue->queue, msg);
	if (msg->msg_done != NULL) {
	  msg->msg_done(msg);
        }
	ch->send_queue->current_qlen--;
      }else{
	cl_perror("socket_resume_io: send");
	break;
      }
    }
  }

  return ch->ch_status == IPC_CONNECT ? IPC_OK : IPC_BROKEN;
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


/* socket object of the function table */
static struct IPC_OPS socket_ops = {
  socket_destroy_channel,
  socket_initiate_connection,
  socket_verify_auth,
  socket_assert_auth,
  socket_send,
  socket_recv,
  socket_waitin,
  socket_is_message_pending,
  socket_is_sending_blocked,
  socket_resume_io,
  socket_get_send_fd,
  socket_get_recv_fd,
  socket_set_send_qlen,
  socket_set_recv_qlen,
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
  temp_queue = (struct IPC_QUEUE *) malloc(sizeof(struct IPC_QUEUE));
  temp_queue->current_qlen = 0;
  temp_queue->max_qlen = DEFAULT_MAX_QLEN;
  temp_queue->queue = NULL;
  return temp_queue;
}


/* 
 * destory a ipc queue and clean all memory space assigned to this queue.
 * parameters:
 *      q  (IN) the pointer to the queue which should be destroied.
 */ 

void
socket_destroy_queue(struct IPC_QUEUE * q)
{
  g_list_free(q->queue);
  free((void *) q);
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
  struct sockaddr_un my_addr;
  int s;
  struct SOCKET_WAIT_CONN_PRIVATE *wait_private;
  
  path_name = (char *) g_hash_table_lookup(ch_attrs, PATH_ATTR);
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
    cl_perror("socket_wait_conn_new: trying to create in %s bind:", path_name);
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
  
  wait_private = (struct SOCKET_WAIT_CONN_PRIVATE* ) malloc(sizeof(struct SOCKET_WAIT_CONN_PRIVATE));
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

  if ((path_name = (char *) g_hash_table_lookup(ch_attrs, PATH_ATTR)) != NULL) { 
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

	if ((rc = socketpair(AF_LOCAL, SOCK_STREAM, 0, sockets)) < 0) {
		return IPC_FAIL;
	}
	if ((channels[0] = socket_server_channel_new(sockets[0])) == NULL) {
		return IPC_FAIL;
	}
	if ((channels[1] = socket_server_channel_new(sockets[1])) == NULL) {
		channels[0]->ops->destroy(channels[0]);
		return IPC_FAIL;
	}
	channels[0]->ch_status = IPC_CONNECT;
	channels[1]->ch_status = IPC_CONNECT;

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

  free(msg->msg_body);
  free((void *)msg);
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
  struct SOCKET_CH_PRIVATE *conn_info;
  socklen_t n;
  int ret = IPC_OK;
  struct ucred *cred;
  
  

  if (auth_info == NULL
  ||	(auth_info->uid == NULL && auth_info->gid == NULL)) {
    return IPC_OK;    /* no restriction for authentication */
  }

  /* get the credential information for peer */
  n = sizeof(struct ucred);
  conn_info = (struct SOCKET_CH_PRIVATE *) ch->ch_private;
  cred = g_new(struct ucred, 1); 
  if (getsockopt(conn_info->s, SOL_SOCKET, SO_PEERCRED, cred, &n) != 0) {
    free(cred);
    return IPC_FAIL;
  }
  
  /* verify the credential information. */
  if (	auth_info->uid
  &&	g_hash_table_lookup(auth_info->uid, &(cred->uid)) == NULL) {
		ret = IPC_FAIL;
  }
  if (	auth_info->gid
  &&	g_hash_table_lookup(auth_info->gid, &(cred->gid)) == NULL) {
		ret = IPC_FAIL;
  }
  free(cred);
  return ret;
}
/* get farside pid through*/

pid_t
socket_get_farside_pid(int sockfd )
{

  socklen_t n;
  struct ucred *cred;
  pid_t f_pid;
  
  /* Get the credential information from peer */
  n = sizeof(struct ucred);
  cred = g_new(struct ucred, 1); 
  if (getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, cred, &n) != 0) {
    free(cred);
    return -1;
  }
  
  f_pid = cred->pid;
  free(cred);
  return f_pid;
}
#endif /* SO_PEERCRED version */



/***********************************************************************
 * SCM_CREDS VERSION... (*BSD systems)
 ***********************************************************************/
#ifdef	USE_SCM_CREDS
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
  msg.msg_iov = (struct iovec *) malloc(sizeof(struct iovec));
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
