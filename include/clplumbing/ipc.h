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

//constants
#define DEFAULT_MAX_QLEN 20
#define MAX_MESSAGE_SIZE 4096

//Authentication status
#define AUTH_OK 0
#define AUTH_FAIL 1


//channel and connection status
#define CH_CONNECT 0
#define CH_WAIT 1
#define CH_DISCONNECT 2

//general return values
#define CH_SUCCESS 0
#define CH_FAIL 1
#define CH_BROKEN 2

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
  /* the information used for authentication */
  struct OCF_IPC_AUTH* auth_info;
  /* the channel private data. May contain the connection information*/
  void* ch_private;
  /*! below two queues are channel's internal queues. They should not be 
     accessed by user directly.*/
  /* the queue used to contain sending messages.*/
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
  /*! 
    \brief the callback function pointer which will be called after this message is sent, received or processed.
    \param msg \b (IN) the pointer points back to the message.
  */
  void (* msg_done)(struct OCF_IPC_MESSAGE * msg);
  /* the message private data. Sometimes can also be used by above callback function. */
  void* msg_private;
  /* this will point back to the channel which contain the message. */
  struct OCF_IPC_CHANNEL * ch;
};

struct OCF_IPC_WAIT_OPS{
  /*!
    \brief detroy the wait connection and free the memory space used by this wait connection.
    \param wait_conn \b (IN) the pointer to the wait connection.
  */ 
  void (* destroy)(struct OCF_IPC_WAIT_CONNECTION *wait_conn);
  /*! 
    \brief provide a fd which user can listen on for a new coming connection.
    \param wait_conn \b (IN) the pointer to the wait connection which contains the select id.
    \retval integer >= 0  the select_fd.
    \retval -1   can't get the select fd.
  */
  int (* get_select_fd)(struct OCF_IPC_WAIT_CONNECTION *wait_conn);
  /*! 
    \brief accept and create a new connection and verify the authentication.
    \param wait_conn \b (IN) the waiting connection which will accept create the new connection.
    \param auth_info \b (IN) the authentication infromation which will be assigned to the new connection.
    \retval the pointer to the new IPC channel; NULL if the creation or authentication fail.
  */
  struct OCF_IPC_CHANNEL* (* accept_connection)(struct OCF_IPC_WAIT_CONNECTION * wait_conn, struct OCF_IPC_AUTH *auth_info);
};

/* channel function table. */
struct OCF_IPC_OPS{
  /*!
    \brief destory the channel object.
    \param ch \b (IN) the pointer to the channel which will be destroied.
  */
  void  (*destroy) (struct OCF_IPC_CHANNEL* ch);
  /*! 
    \brief used by service user side to set up a connection.
    \param ch \b (IN) the pointer to channel used to initiate the connection. 
    \retval CH_SUCCESS the channel set up the connection succesully.
    \retval CH_FAIL the connection initiation fails.
  */
  int (* initiate_connection) (struct OCF_IPC_CHANNEL* ch);
  /*! 
    \brief used by service provider to verify the authentication of peer.
    \param ch \b (IN) the pointer to the channel.
    \retval AUTH_OK the peer is trust.
    \retval AUTH_FAIL verifying authentication fails.
  */
  int (* verify_auth) (struct OCF_IPC_CHANNEL* ch);
  /*! 
   \brief service user asserts to be certain qualified service user.
   \param ch \b (IN) the avtive channel.
   \param auth \b (IN) the hash table contain the asserting information.
   \retval CH_SUCCESS assert the authentication succefully.
   \retval CH_FAIL assertion fails.
  */
  int (* assert_auth) (struct OCF_IPC_CHANNEL* ch, GHashTable * auth);
  /*!
    \brief  send the message through the sending connection.
    \param ch \b (IN) the channel which contains the connection.
    \param msg \b (IN) pointer to the sending message. User should allocate the message space.
    \retval CH_SUCCESS the message was either sent out successfully or appended in the send_queue.
    \retval CH_FAIL the send operation fails.
    \retval CH_BROKEN the channel is broken.
  */    
  int (* send) (struct OCF_IPC_CHANNEL* ch, struct OCF_IPC_MESSAGE* msg);
  /*!
    \brief receive the message through receving queue.
    \param ch \b (IN) the channel which contains the connection.
    \param msg \b (OUT) the OCF_IPC_MESSAGE** which contain the pointer to the recevied message or NULL if there is no message available.
    \retval CH_SUCCESS reveive operation is finished successfully.
    \retval CH_FAIL operation fails.
    \retval CH_BROKEN the channel is broken.
    \note return value CH_SUCCESS doesn't mean the message is already sent out to the peer. It may be pending
     in the send_queue. In order to make sure the message it out, please specify the msg_done function in the
     message structure and once this function is called, the message is out.
  */
  int (* recv) (struct OCF_IPC_CHANNEL* ch, struct OCF_IPC_MESSAGE** msg);
  /*! 
    \brief check the recv_queue to see if there is any messages available. 
    \param ch \b (IN) the pointer to the channel. 
    \retval TRUE there are messages pending in the rece_queue.
    \return FALSE there is no message pending in the rece_queue.
  */
  gboolean (* is_message_pending) (struct OCF_IPC_CHANNEL * ch);
  
  /* check the send_queue to see if there is any message blocking. */
  gboolean (* is_sending_blocked) (struct OCF_IPC_CHANNEL *ch);
  /*! 
    \brief resume all possible IO operations through the inner connection . 
    \param the pointer to the channel.
    \retval CH_SUCCSS resume all the possible I/O operation succefully.
    \retval CH_FAIL the operation fails.
    \retval CH_BROEKN the channel is broken.
  */
  int (* resume_io) (struct OCF_IPC_CHANNEL *ch);
  /*! 
    \brief return a file descriptor which can be given to select.
    \param ch \b (IN) the pointer to the channel.
    \retval interger >= 0 : the send fd for selection.
    \retval -1 there is no send fd.
  */
  int   (* get_send_select_fd) (struct OCF_IPC_CHANNEL* ch);
  /*! 
    \brief return a file descriptor which can be given to select.
    \param ch \b (IN) the pointer to the channel.
    \retval interger >= 0 : the recv fd for selection.
    \retval -1 there is no recv fd.
  */
  int   (* get_recv_select_fd) (struct OCF_IPC_CHANNEL* ch);
  /*!
    \brief allow user to set the maximum send_queue length.
    \param ch \b (IN) the pointer to the channel.
    \param q_len \b (IN) the max length for the send_queue.
    \retval CH_SUCCESS set the send queue length successfully.
    \retval CH_FAIL there is no send queue.
  */
  int  (* set_send_qlen) (struct OCF_IPC_CHANNEL* ch, int q_len);
  /*!
    \brief allow user to set the maximum recv_queue length.
    \param ch \b (IN) the pointer to the channel.
    \param q_len \b (IN) the max length for the recv_queue.
    \retval CH_SUCCESS set the recv queue length successfully.
    \retval CH_FAIL there is no recv queue.
  */
  int  (* set_recv_qlen) (struct OCF_IPC_CHANNEL* ch, int q_len);
};

/* below functions are implemented in ocf_ipc.c */

/*! 
  \brief the common constructor for ipc waiting connection. Use ch_type to identify the connection type. 
  \param ch_type \b (IN) the type of the waiting connection you want to create.
  \param ch_attrs \b (IN) the hash table which contains the attributes needed by this waiting connection.
  \retval the pointer to a new waiting connection or NULL if the connection can't be created.
  \note current channel types only  contain "domain_socket".
*/
extern struct OCF_IPC_WAIT_CONNECTION * ipc_wait_conn_constructor(const char * ch_type
,	GHashTable* ch_attrs);

/*! 
  \brief the common constructor for ipc channel. Use ch_type to identify the channel type.
  \param ch_type \b (IN) the type of the channel you want to create.
  \param ch_attrs \b (IN) the hash table which contains the attributes needed by this channel.
  \retval the pointer to the new channel whose status is CH_DISCONNECT or NULL if the channel can't be created.
  \note current channel types only  contain "domain_socket".
*/
extern struct OCF_IPC_CHANNEL * ipc_channel_constructor(const char * ch_type
,	GHashTable* ch_attrs);

/*! 
  \brief the wapper function used to convert array of uid and gid into a authetication structure.
  \param a_uid \b (IN) the array of a set of user ids.
  \param a_gid \b (IN) the array of a set of group ids.
  \param num_uid \b (IN) the number of user ids.
  \param num_gid \b (IN) the number of group ids.
  \retval the pointer to the authentication structure which contain the set of uid and the set of gid.
  Or NULL if this sturcture can't be created.
*/
extern struct OCF_IPC_AUTH * ipc_set_auth(uid_t * a_uid, gid_t * a_gid, int num_uid, int num_gid);			   

extern void ipc_destroy_auth(struct OCF_IPC_AUTH * auth);


#define	PATH_ATTR		"path"		/* pathname attribute */
#define	SOCK_ATTR		"socket"	/* socket fd attribute */
#define	IPC_DOMAIN_SOCKET	"uds"		/* Unix domain socket */

#ifdef IPC_DOMAIN_SOCKET
#	define	IPC_ANYTYPE		IPC_DOMAIN_SOCKET
#else
#	error "No IPC types defined(!)"
#endif

#endif
