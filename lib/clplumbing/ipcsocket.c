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

#include <clplumbing/ipc.h>


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#ifdef BSD
#include <sys/syslimits.h>
#endif
#include <sys/param.h>
#include <sys/uio.h>
#ifdef BSD
#include <sys/ucred.h>
#endif
#include <sys/socket.h>
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

static int socket_verify_auth(struct IPC_CHANNEL* ch);

/* for domain socket, reve_fd = send_fd. */

static int socket_get_recv_fd(struct IPC_CHANNEL *ch);

static int socket_get_send_fd(struct IPC_CHANNEL *ch);

static int socket_set_send_qlen (struct IPC_CHANNEL* ch, int q_len);

static int socket_set_recv_qlen (struct IPC_CHANNEL* ch, int q_len);


/* helper functions. */

int socket_disconnect(struct IPC_CHANNEL* ch);

struct IPC_QUEUE* socket_queue_new(void);

void socket_destroy_queue(struct IPC_QUEUE * q);

struct IPC_MESSAGE* socket_message_new(struct IPC_CHANNEL *ch, int msg_len);

void socket_free_message(struct IPC_MESSAGE * msg);

struct IPC_WAIT_CONNECTION *socket_wait_conn_new(GHashTable* ch_attrs);

struct IPC_CHANNEL* socket_client_channel_new(GHashTable *attrs);

struct IPC_CHANNEL* socket_server_channel_new(int sockfd);

pid_t socket_get_farside_pid(int sockfd);

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
  if (s == -1) {
    printf("get_select_fd: invalid fd\n");
    return NULL;
  }

  /* get client connection. */
  sin_size = sizeof(struct sockaddr_un);
  if ((new_sock = accept(s, (struct sockaddr *)&peer_addr, &sin_size)) == -1) {
    perror("accept");
    return NULL;
  }else{
    if ((ch = socket_server_channel_new(new_sock)) == NULL) {
      printf("socket_accept_connection: Can't create new channel\n");
      return NULL;
    }else{
      conn_private = (struct SOCKET_WAIT_CONN_PRIVATE *)(wait_conn->ch_private);
      ch_private = (struct SOCKET_CH_PRIVATE *)(ch->ch_private);
      strncpy(ch_private->path_name,conn_private->path_name,sizeof(conn_private->path_name));
    }
  }
  /* verify the client authentication information. */
  ch->auth_info = auth_info;
  if (ch->ops->verify_auth(ch) == IPC_OK) {
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
  ipc_destroy_auth(ch->auth_info);
  
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

int
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
    fprintf(stderr,"the max path length is %d\n", sizeof(peer_addr.sun_path));
    return IPC_FAIL;
  }
  strncpy(peer_addr.sun_path, conn_info->path_name, sizeof(peer_addr.sun_path));
  /* send connection request */
  if (connect(conn_info->s, (struct sockaddr *)&peer_addr
  , 	sizeof(struct sockaddr_un)) == -1) {
    perror("connect");
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
  GList *element;  
  int result;
  
  result = ch->ops->resume_io(ch);
  
  if (result != IPC_OK) {
    *message = NULL;
    return result;
  }else{
    if (ch->recv_queue->current_qlen != 0) {
      element = g_list_first(ch->recv_queue->queue);
      if (element != NULL) {
	*message = (struct IPC_MESSAGE *) (element->data);
	      
	ch->recv_queue->queue = g_list_remove_link(ch->recv_queue->queue, element);
	ch->recv_queue->current_qlen--;
      
	return IPC_OK;
      }else {
	*message = NULL;
      }
    }
  }
  return IPC_FAIL;
  
}

static gboolean
socket_is_message_pending(struct IPC_CHANNEL * ch)
{
  
  int	rc;
  int	len;
  struct SOCKET_CH_PRIVATE * conn_info = ch->ch_private;

  if (ch->recv_queue->current_qlen > 0 || conn_info->buf_msg != NULL) {
    return TRUE;
  }

  rc=ioctl(conn_info->s, FIONREAD,&len);
  if (rc == 0 && len > 0) {
	return TRUE;
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
  printf("the assert_auth function for domain socket is not implemented\n");
  return IPC_FAIL;
}

/* verify the authentication information. */
#ifdef SO_PEERCRED
static int 
socket_verify_auth(struct IPC_CHANNEL* ch)
{
  struct SOCKET_CH_PRIVATE *conn_info;
  struct IPC_AUTH *auth_info;
  ssize_t n;
  int ret = IPC_OK;
  struct ucred *cred;
  
  
  auth_info = (struct IPC_AUTH *) ch->auth_info;

  if (auth_info == NULL) { /* no restriction for authentication */
    return IPC_OK;
  }
  
  if (auth_info->uid == NULL && auth_info->gid == NULL) {
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

#elif defined(SCM_CREDS) || defined(HAVE_STRUCT_CMSGCRED) || defined(HAVE_STRUCT_FCRED) || (defined(HAVE_STRUCT_SOCKCRED) && defined(LOCAL_CREDS))

/* FIXME!  Need to implement SCM_CREDS mechanism for BSD-based systems
 * This isn't an emergency, but should be done in the future...
 * Hint: * Postgresql does both types of authentication...
 * see src/backend/libpq/auth.c
 * Not clear its SO_PEERCRED implementation works though ;-) 
 */

/* Done.... Haven't tested yet. */
static int 
socket_verify_auth(struct IPC_CHANNEL* ch)
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

#else
  typedef struct ucred Cred;
#define cruid c_uid
#endif
  Cred	   *cred;
  struct SOCKET_CH_PRIVATE *conn_info;
  struct IPC_AUTH *auth_info;
  int ret = IPC_OK;
  char         buf;
  
  /* Compute size without padding */
  char		cmsgmem[ALIGN(sizeof(struct cmsghdr)) + ALIGN(sizeof(Cred))];	/* for NetBSD */

  /* Point to start of first structure */
  struct cmsghdr *cmsg = (struct cmsghdr *) cmsgmem;
  
  auth_info = (struct IPC_AUTH *) ch->auth_info;

  if (auth_info == NULL) { /* no restriction for authentication */
    return IPC_OK;
  }
  
  if (auth_info->uid == FALSE && auth_info->gid == FALSE) {
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
   * purposes is only to make sure that recvmsg() blocks long enough for
   * the other side to send its credentials.
   */
  msg.msg_iov->iov_base = &buf;
  msg.msg_iov->iov_len = 1;
  
  if (recvmsg(conn_info->s, &msg, 0) < 0 
      || cmsg->cmsg_len < sizeof(cmsgmem) 
      || cmsg->cmsg_type != SCM_CREDS)
    {
      fprintf(stderr,"can't get credential information from peer\n");
      return IPC_FAIL;
    }

  cred = (Cred *) CMSG_DATA(cmsg);
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

#else

#error "Need either SO_PEERCRED or SCM_CREDS authentication mechanisms!"

#endif

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
  
  while (ch->recv_queue->current_qlen < ch->recv_queue->max_qlen) {
    /* check how much data queued. */
    if(ioctl(conn_info->s, FIONREAD,&len) < 0){
      perror("ioctl");
      return IPC_FAIL;
    }

    if(len > 0){
      if(conn_info->remaining_data != 0){
	new_msg = FALSE;
	len = conn_info->remaining_data;
	msg = conn_info->buf_msg;
	msg_begin = (char *) msg->msg_body + (msg->msg_len - len); 
      }else{
	msg_begin = (char *)&head;
	new_msg = TRUE;
      }
    }else{
      break;
    }

    if(new_msg){
      msg_len = recv(conn_info->s, (char *)&head , sizeof(struct SOCKET_MSG_HEAD) , MSG_DONTWAIT);
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
	  ch->recv_queue->queue = g_list_append(ch->recv_queue->queue, conn_info->buf_msg);
	  ch->recv_queue->current_qlen++;
	  conn_info->buf_msg = NULL;
	  conn_info->remaining_data = 0;
	}else if(msg_len < conn_info->remaining_data){
	  conn_info->remaining_data = conn_info->remaining_data - msg_len;
	}else{
	  /* Wrong! */
	  printf(" received more data than expected\n");
	  return IPC_FAIL;
	}
      }
    }else{
      break;
    }
  }
  
 
  len = 0;
  while (len >=0 && ch->send_queue->current_qlen >0) {
    element = g_list_first(ch->send_queue->queue);
    if (element != NULL) {
      msg = (struct IPC_MESSAGE *) (element->data);
      head.msg_len = msg->msg_len;
      len=send(conn_info->s, (char *)&head, sizeof(struct SOCKET_MSG_HEAD), MSG_DONTWAIT);
      if (len < 0){
	if(errno == EAGAIN) {
	  break;
	}else if(errno == EPIPE){
	  ch->ch_status = IPC_DISCONNECT;
	  return IPC_BROKEN;
	}else{
	  ch->ch_status = IPC_DISCONNECT;
	  return IPC_FAIL;	  
	}
      }
      len=send(conn_info->s, msg->msg_body, msg->msg_len, MSG_DONTWAIT&MSG_OOB);
      if (len < 0){
	if(errno == EAGAIN) {
	  break;
	}else if(errno == EPIPE){
	  ch->ch_status = IPC_DISCONNECT;
	  return IPC_BROKEN;
	}else{
	  ch->ch_status = IPC_DISCONNECT;
	  return IPC_FAIL;	  
	}
      }
    
      if (len > 0 ) {
	ch->send_queue->queue = g_list_remove(ch->send_queue->queue, msg);
	if (msg->msg_done != NULL) {
	  msg->msg_done(msg);
        }
	ch->send_queue->current_qlen--;
      }else{
	perror("send");
	break;
      }
    }
  }

  return IPC_OK;
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

struct IPC_QUEUE*
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
    printf("GHash look up : Can't get the path_name from the hash table\n");
    return NULL;
  }

  /* prepare the unix domain socket */
  if ((s = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
    perror("socket_wait_conn_new: socket");
    return NULL;
  }
  
  if (unlink(path_name) < 0 && errno != ENOENT) {
    perror("socket_wait_conn_new: unlink");
  }
  memset(&my_addr, 0, sizeof(my_addr));
  my_addr.sun_family = AF_LOCAL;         /* host byte order */

  if (strlen(path_name) >= sizeof(my_addr.sun_path)) {
    return NULL;
  }
    
  strncpy(my_addr.sun_path, path_name, sizeof(my_addr.sun_path));
    
  if (bind(s, (struct sockaddr *)&my_addr, sizeof(my_addr)) == -1) {
    perror("bind");
    return NULL;
  }

  /* listen to the socket */
  if (listen(s, MAX_LISTEN_NUM) == -1) {
    perror("listen");
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
   * wait_conn->accept_connection() will call another function to create a new channel.
   * this function will take socketfd as the parameter to create a socket channel.
   */

  if ((path_name = (char *) g_hash_table_lookup(ch_attrs, PATH_ATTR)) != NULL) { 
    if (strlen(path_name) >= sizeof(conn_info->path_name)) {
      fprintf(stderr,"the max path length is %d\n"
      ,	sizeof(conn_info->path_name));
      	return NULL;
    }
    /* prepare the socket */
    if ((sockfd = socket(AF_LOCAL, SOCK_STREAM, 0)) == -1) {
      perror("socket");
      return NULL;
    }
  }else{
    printf("socket_client_channel_new: Can't get required information from hash table\n");
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
  temp_ch->auth_info = NULL;
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
  temp_ch->auth_info = NULL;
  temp_ch->ops = (struct IPC_OPS *)&socket_ops;
  temp_ch->send_queue = socket_queue_new();
  temp_ch->recv_queue = socket_queue_new();
   
  return temp_ch;
  
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


struct IPC_MESSAGE*
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

/* get farside pid through*/
#ifdef SO_PEERCRED
pid_t
socket_get_farside_pid(int sockfd )
{

  ssize_t n;
  struct ucred *cred;
  pid_t f_pid;
  
  /* get the credential information for peer */
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

#elif defined(SCM_CREDS) || defined(HAVE_STRUCT_CMSGCRED) || defined(HAVE_STRUCT_FCRED) || (defined(HAVE_STRUCT_SOCKCRED) && defined(LOCAL_CREDS))
  
/* FIXME!  Need to implement SCM_CREDS mechanism for BSD-based systems
 * this is similar to the SCM_CREDS mechanism for verify_auth() function.
 * here we just want to get the pid of the other side from the credential 
 * information.
 */

pid_t socket_get_farside_pid(int sock){
  return -1;
}

#endif
