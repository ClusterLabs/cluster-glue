/*
 * ipc.h IPC abstraction data structures.
 *
 * author  Xiaoxiang Liu <xiliu@ncsa.uiuc.edu>, Alan Robertson <alanr@unix.sh>
 *
 *
 * Copyright (c) 2002 International Business Machines
 * Copyright (c) 2002  Xiaoxiang Liu <xiliu@ncsa.uiuc.edu>
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

#ifndef _OCF_IPC_H_
#define _OCF_IPC_H_
#include <glib.h>
#include <portability.h>
#undef MIN
#undef MAX
#include <sys/types.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

/* constants */
#define DEFAULT_MAX_QLEN 20
#define MAX_MESSAGE_SIZE 4096

/* channel and connection status */
#define IPC_CONNECT 0
#define IPC_WAIT 1
#define IPC_DISCONNECT 2

/* general return values */
#define IPC_OK 0
#define IPC_FAIL 1
#define IPC_BROKEN 2

/* wait connection structure. */
struct OCF_IPC_WAIT_CONNECTION{
  /* wait connection status.*/
  int ch_status;
  /* wait connection private data. */
  void * ch_private;
  /* wait connection function table .*/
  struct OCF_IPC_WAIT_OPS *ops;
};

/* channel structure.*/
struct OCF_IPC_CHANNEL{
  /* identify the status of channel.*/
  int ch_status;
  /* far side pid */
  pid_t farside_pid;
  /* the information used for authentication */
  struct OCF_IPC_AUTH* auth_info;
  /* the channel private data. May contain the connection information*/
  void* ch_private;
  /*
   *  There two queues in channel. One is for sending and the other
   *  is for receiving. 
   *  Those two queues are channel's internal queues. They should not be 
   *  accessed by user directly.
   *
   */
  struct OCF_IPC_QUEUE* send_queue; 
  /* the queue used to contain receving messages.*/
  struct OCF_IPC_QUEUE* recv_queue; 
  /* the standard function table.*/
  struct OCF_IPC_OPS *ops;
};

struct OCF_IPC_QUEUE{
  int current_qlen;
  int max_qlen;
  GList* queue;
};
/* authentication information : set of gid and uid. */
struct OCF_IPC_AUTH {
  /* hash table for user id */
  GHashTable * uid;
  /* hash table for group id */
  GHashTable * gid;
};

/* Message structure. */
struct OCF_IPC_MESSAGE{
  unsigned long msg_len;
  void* msg_body;
  /* 
   * OCF_IPC_MESSAGE::msg_done 
   *   the callback function pointer which can be called after this 
   *   message is sent, received or processed.
   * Parameter:
   *   msg: the back pointer to the message which contains this function pointer.
   * 
  */
  void (* msg_done)(struct OCF_IPC_MESSAGE * msg);
  /* the message private data. Sometimes can also be used by above callback function. */
  void* msg_private;
  /* this will point back to the channel which contain the message. */
  struct OCF_IPC_CHANNEL * ch;
};

struct OCF_IPC_WAIT_OPS{
  /*
   * OCF_IPC_WAIT_OPS::destroy
   *   detroy the wait connection and free the memory space used by this wait connection.
   * 
   * parameters:
   *   wait_conn (IN):  the pointer to the wait connection.
   *
  */ 
  void (* destroy)(struct OCF_IPC_WAIT_CONNECTION *wait_conn);
  /*
   * OCF_IPC_WAIT_OPS::get_select_fd
   *   provide a fd which user can listen on for a new coming connection.
   * parameters: 
   *   wait_conn (IN) : the pointer to the wait connection which contains the select id.
   * return values:
   *   integer >= 0 :  the select_fd.
   *       -1       :  can't get the select fd.
   *
  */
  int (* get_select_fd)(struct OCF_IPC_WAIT_CONNECTION *wait_conn);
  /*
   * OCF_IPC_WAIT_OPS::accept_connection
   *   accept and create a new connection and verify the authentication.
   * parameters:
   *   wait_conn (IN) : the waiting connection which will accept create the new connection.
   *   auth_info (IN) : the authentication infromation which will be assigned to the new connection.
   * return values:
   *   the pointer to the new IPC channel; NULL if the creation or authentication fail.
   *
  */
  struct OCF_IPC_CHANNEL* (* accept_connection)(struct OCF_IPC_WAIT_CONNECTION * wait_conn, struct OCF_IPC_AUTH *auth_info);
};

/* channel function table. */
struct OCF_IPC_OPS{
  /*
   * OCF_IPC_OPS::destroy
   *   brief destory the channel object.
   * parameters:
   *   ch  (IN) : the pointer to the channel which will be destroied.
   *
  */
  void  (*destroy) (struct OCF_IPC_CHANNEL* ch);
  /*
   * OCF_IPC_OPS::initiate_connection
   *   used by service user side to set up a connection.
   * parameters:
   *   ch (IN) : the pointer to channel used to initiate the connection. 
   * return values:
   *   IPC_OK  : the channel set up the connection succesully.
   *   IPC_FAIL     : the connection initiation fails.
   *
  */
  int (* initiate_connection) (struct OCF_IPC_CHANNEL* ch);
  /*
   * OCF_IPC_OPS::verify_auth
   *   used by service provider to verify the authentication of peer.
   * parameters
   *   ch (IN) : the pointer to the channel.
   * return values:
   *   IPC_OK   : the peer is trust.
   *   IPC_FAIL : verifying authentication fails.
   *
  */
  int (* verify_auth) (struct OCF_IPC_CHANNEL* ch);
  /*
   * OCF_IPC_OPS::assert_auth
   *   service user asserts to be certain qualified service user.
   * parameters:
   *   ch    (IN):  the active channel.
   *   auth  (IN):  the hash table contain the asserting information.
   * return values:
   *   IPC_OK :  assert the authentication succefully.
   *   IPC_FAIL    : assertion fails.
  */
  int (* assert_auth) (struct OCF_IPC_CHANNEL* ch, GHashTable * auth);
  /*
   * OCF_IPC_OPS::send
   *   send the message through the sending connection.
   * parameters:
   *   ch  (IN) : the channel which contains the connection.
   *   msg (IN) : pointer to the sending message. User should allocate the message space.
   * return values:
   *   IPC_OK : the message was either sent out successfully or appended in the send_queue.
   *   IPC_FAIL    : the send operation fails.
   *   IPC_BROKEN  : the channel is broken.
   *
  */    
  int (* send) (struct OCF_IPC_CHANNEL* ch, struct OCF_IPC_MESSAGE* msg);
  /*
   * OCF_IPC_OPS::recv
   *   receive the message through receving queue.
   * parameters:
   *   ch  (IN) : the channel which contains the connection.
   *   msg (OUT): the OCF_IPC_MESSAGE** pointer which contains the pointer to the recevied message 
   *              or NULL if there is no message available.
   * return values:
   *   IPC_OK : reveive operation is finished successfully.
   *   IPC_FAIL    : operation fails.
   *   IPC_BROKEN  : the channel is broken.
   *
   * note: 
   *   return value IPC_OK doesn't mean the message is already 
   *   sent out to the peer. It may be pending in the send_queue. In order to 
   *   make sure the message it out, please specify the msg_done function in the
   *   message structure and once this function is called, the message is out.
   *
   *   is_sending_blocked() is another way to check if there is message 
   *   pending in the send_queue. 
  */
  int (* recv) (struct OCF_IPC_CHANNEL* ch, struct OCF_IPC_MESSAGE** msg);
  /*
   * OCF_IPC_OPS::is_message_pending
   *   check the recv_queue to see if there is any messages available. 
   * parameters:
   *   ch (IN) : the pointer to the channel.
   * return values:
   *   TRUE : there are messages pending in the rece_queue.
   *   FALSE: there is no message pending in the rece_queue.
   *
  */
  gboolean (* is_message_pending) (struct OCF_IPC_CHANNEL * ch);
  /*
   * OCF_IPC_OPS::is_sending_blocked
   *   check the send_queue to see if there is any messages blocked. 
   * parameters:
   *   ch (IN) : the pointer to the channel.
   * return values:
   *   TRUE : there are messages blocked in the send_queue.
   *   FALSE: there is no message blocked in the send_queue.
   *
  */  
  gboolean (* is_sending_blocked) (struct OCF_IPC_CHANNEL *ch);
  /*
   * OCF_IPC_OPS::resume_io
   *   brief resume all possible IO operations through the inner connection . 
   * parameters:
   *   the pointer to the channel.
   * return values:
   *   IPC_OK : resume all the possible I/O operation succefully.
   *   IPC_FAIL   : the operation fails.
   *   IPC_BROKEN : the channel is broken.
   *
  */
  int (* resume_io) (struct OCF_IPC_CHANNEL *ch);
  /*
   * OCF_IPC_OPS::get_send_select_fd 
   *   return a file descriptor which can be given to select. this fd is
   *   for sending.
   * parameters:
   *   ch (IN) : the pointer to the channel.
   * return values:
   *   interger >= 0 : the send fd for selection.
   *      -1         : there is no send fd.
   *
  */
  int   (* get_send_select_fd) (struct OCF_IPC_CHANNEL* ch);
  /*
   * OCF_IPC_OPS::get_recv_select_fd
   *   return a file descriptor which can be given to select. This fd
   *   is for receiving.
   * parameters:
   *   ch (IN) : the pointer to the channel.
   * return values:
   *   interger >= 0 : the recv fd for selection.
   *       -1        : there is no recv fd.
   *
  */
  int   (* get_recv_select_fd) (struct OCF_IPC_CHANNEL* ch);
  /*
   * OCF_IPC_OPS::set_send_qlen
   *   allow user to set the maximum send_queue length.
   * parameters
   *   ch    (IN) : the pointer to the channel.
   *   q_len (IN) : the max length for the send_queue.
   * return values:
   *   IPC_OK : set the send queue length successfully.
   *   IPC_FAIL    : there is no send queue.we are not supposed to get this return value.
   *                It means something bad happened.
   *
  */
  int  (* set_send_qlen) (struct OCF_IPC_CHANNEL* ch, int q_len);
  /*
   * OCF_IPC_OPS::set_recv_qlen
   *   allow user to set the maximum recv_queue length.
   * parameters:
   *   ch    (IN) : the pointer to the channel.
   *   q_len (IN) : the max length for the recv_queue.
   * return values:
   *   IPC_OK : set the recv queue length successfully.
   *   IPC_FAIL    : there is no recv queue.
   *
  */
  int  (* set_recv_qlen) (struct OCF_IPC_CHANNEL* ch, int q_len);
};

/* below functions are implemented in ocf_ipc.c */

/*
 * ipc_wait_conn_constructor:
 *    the common constructor for ipc waiting connection. 
 *    Use ch_type to identify the connection type. Usually it's only
 *    needed by server side.
 * parameters:
 *    ch_type   (IN) : the type of the waiting connection you want to create.
 *    ch_attrs  (IN) : the hash table which contains the attributes needed by this waiting connection.
 *                     For example, the only attribute needed by doamin socket is path name.
 * return values:
 *    the pointer to a new waiting connection or NULL if the connection can't be created.
 * note:
 *    current implementation only support unix domain socket 
 *    whose type is IPC_DOMAIN_SOCKET 
 *
*/
extern struct OCF_IPC_WAIT_CONNECTION * ipc_wait_conn_constructor(const char * ch_type
,	GHashTable* ch_attrs);

/*
 * ipc_channel_constructor:
 *   brief the common constructor for ipc channel. 
 *   Use ch_type to identify the channel type.
 *   Usually this function is only called by client side.
 * parameters:
 *   ch_type  (IN): the type of the channel you want to create.
 *   ch_attrs (IN): the hash table which contains the attributes needed by this channel.
 *                  For example, the only attribute needed by doamin socket is path name.
 * return values:
 *   the pointer to the new channel whose status is IPC_DISCONNECT or NULL if the channel can't be created.
 * note:
 *   current implementation only support unix domain socket 
 *   whose type is IPC_DOMAIN_SOCKET 
 *
*/
extern struct OCF_IPC_CHANNEL * ipc_channel_constructor(const char * ch_type
,	GHashTable* ch_attrs);

/*
 * ipc_set_auth:
 *   the wapper function used to convert array of uid and gid into a authetication structure.
 * parameters:
 *   a_uid    (IN): the array of a set of user ids.
 *   a_gid    (IN): the array of a set of group ids.
 *   num_uid  (IN): the number of user ids.
 *   num_gid  (IN): the number of group ids.
 * return values:
 *   the pointer to the authentication structure which contains the 
 *   set of uid and the set of gid. Or NULL if this sturcture can't be created.
 *
*/
extern struct OCF_IPC_AUTH * ipc_set_auth(uid_t * a_uid, gid_t * a_gid, int num_uid, int num_gid);			   

extern void ipc_destroy_auth(struct OCF_IPC_AUTH * auth);


#define	PATH_ATTR		"path"		/* pathname attribute */
#define	IPC_DOMAIN_SOCKET	"uds"		/* Unix domain socket */

#ifdef IPC_DOMAIN_SOCKET
#	define	IPC_ANYTYPE		IPC_DOMAIN_SOCKET
#else
#	error "No IPC types defined(!)"
#endif

#endif
