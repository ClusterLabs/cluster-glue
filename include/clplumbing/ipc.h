/*
 * ipc.h IPC abstraction data structures.
 *
 * author  Xiaoxiang Liu <xiliu@ncsa.uiuc.edu>,
 *	Alan Robertson <alanr@unix.sh>
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

#ifndef _IPC_H_
#define _IPC_H_
#include <glib.h>
#undef MIN
#undef MAX
#include <sys/types.h>
#include <sys/poll.h>

#ifdef IPC_TIME_DEBUG
#include <clplumbing/longclock.h>
#define MAXIPCTIME 3000

#endif

/* constants */
#define DEFAULT_MAX_QLEN 64
#define MAX_MSGPAD 128
/* channel and connection status */
#define IPC_CONNECT		1	/* Connected: can read, write */
#define IPC_WAIT		2	/* Waiting for connection */
#define IPC_DISCONNECT		3	/* Disconnected, can't read or write*/
#define IPC_DISC_PENDING	4	/* Disconnected, can't write but    */
					/* may be more data to read	    */

#define MAXFAILREASON		128

#define IPC_SERVER		1
#define IPC_CLIENT		2
#define IPC_PEER		3

#define IPC_ISRCONN(ch) ((ch)->ch_status == IPC_CONNECT		\
	||	(ch)->ch_status == IPC_DISC_PENDING)

#define IPC_ISWCONN(ch) ((ch)->ch_status == IPC_CONNECT)

/* general return values */
#define IPC_OK 0
#define IPC_FAIL 1
#define IPC_BROKEN 2
#define IPC_INTR 3
#define IPC_TIMEOUT 4

/*
 *	IPC:  Sockets-like Interprocess Communication Abstraction
 *
 *	We have two fundamental abstractions which we maintain.
 *	Everything else is in support of these two abstractions.
 *
 *	These two main abstractions are:
 *
 *	IPC_WaitConnection:
 *	A server-side abstraction for waiting for someone to connect.
 *
 *	IPC_Channel:
 *	An abstraction for an active communications channel.
 *
 *	All the operations on these two abstractions are carried out
 *	via function tables (channel->ops).  Below we refer to the
 *	function pointers in these tables as member functions.
 *
 *  On the server side, everything starts up with a call to
 *	ipc_wait_conn_constructor(), which returns an IPC_WaitConnection.
 *
 *	Once the server has the IPC_WaitConnection object in hand,
 *	it can give the result of the get_select_fd() member function
 *	to poll or select to inform you when someone tries to connect.
 *
 *	Once select tells you someone is trying to connect, you then
 *	use the accept_connection() member function to accept
 *	the connection.  accept_connection() returns an IPC_Channel.
 *
 *	With that, the server can talk to the client, and away they
 *	go ;-)
 *
 *  On the client side, everything starts up with a call to
 *	ipc_channel_constructor() which we use to talk to the server.
 *	The client is much easier ;-)
 */


typedef struct IPC_WAIT_CONNECTION	IPC_WaitConnection;
typedef struct IPC_CHANNEL		IPC_Channel;

typedef struct IPC_MESSAGE		IPC_Message;
typedef struct IPC_QUEUE		IPC_Queue;
typedef struct IPC_AUTH			IPC_Auth;

typedef struct IPC_OPS			IPC_Ops;
typedef struct IPC_WAIT_OPS		IPC_WaitOps;



/* wait connection structure. */
struct IPC_WAIT_CONNECTION{
	int		ch_status;	/* wait conn. status.*/
	void *		ch_private;	/* wait conn. private data. */
	IPC_WaitOps	*ops;		/* wait conn. function table .*/
};


typedef void(*flow_callback_t)(IPC_Channel*, void*);

/* channel structure.*/
struct IPC_CHANNEL{
	int		ch_status;	/* identify the status of channel.*/
	int		refcount;	/* reference count */
	pid_t		farside_pid;	/* far side pid */
	void*		ch_private;	/* channel private data. */
					/* (may contain conn. info.) */
	IPC_Ops*	ops;		/* IPC_Channel function table.*/

	/* number of bytes needed
	 * at the begginging of <ipcmessage>->msg_body
	 * it's for msg head needed to tranmit in wire	 
	 */
	unsigned int	msgpad;
	
	/* the number of bytes remainng to send for the first message in send queue
	   0 means nothing has been sent thus all bytes needs to be send
	   n != 0 means there are still n bytes needs to be sent
	*/
	unsigned int	bytes_remaining;


	/* is the send blocking or nonblocking*/
	gboolean	should_send_block;
	
	/* if send would block, should an error be returned or not */
	gboolean	should_block_fail;
	
/*  There are two queues in channel. One is for sending and the other
 *  is for receiving. 
 *  Those two queues are channel's internal queues. They should not be 
 *  accessed directly.
 */
	/* private: */
	IPC_Queue*	send_queue; 
	IPC_Queue*	recv_queue; 

	/* buffer pool for receive in this channel*/
	struct ipc_bufpool* pool;

	/* the follwing is for send flow control*/
	int		high_flow_mark;
	int		low_flow_mark;
	void*		high_flow_userdata;
	void*		low_flow_userdata;
	flow_callback_t	high_flow_callback;
	flow_callback_t	low_flow_callback;
	
	int		conntype;
	
	char		failreason[MAXFAILREASON];

	/* New members to support Multi-level ACLs for the CIB,
	 * available since libplumb.so.2.1.0, added at the
	 * end of the struct to maintain backwards ABI compatibility.
	 *
	 * If you don't like to care for library versions,
	 * create your IPC channels with
	 *  c = ipc_wait_conn_constructor(IPC_UDS_CRED, ...),
	 * and these members will be available.
	 */
	uid_t		farside_uid;	/* far side uid */
	gid_t		farside_gid;	/* far side gid */
};

struct IPC_QUEUE{
	size_t		current_qlen;	/* Current qlen */
	size_t		max_qlen;	/* Max allowed qlen */
	GList*		queue;		/* List of messages */
	/* keep the time of the last max queue warning */
	time_t		last_maxqlen_warn;
	/* and the number of messages lost */
	unsigned	maxqlen_cnt;
};

/* authentication information : set of gids and uids */
struct IPC_AUTH {
	GHashTable * uid;	/* hash table for user id */
	GHashTable * gid;	/* hash table for group id */
};


/* Message structure. */
struct IPC_MESSAGE{
	size_t	msg_len;
	void*	msg_buf;
	void*	msg_body;
/* 
 * IPC_MESSAGE::msg_done 
 *   the callback function pointer which can be called after this 
 *   message is sent, received or otherwise processed.
 *
 * Parameter:
 * msg: the back pointer to the message which contains this
 *	function pointer.
 * 
 */
	void (* msg_done)(IPC_Message * msg);
	void* msg_private;	/* the message private data.	*/
				/* Belongs to message creator	*/
				/* May be used by callback function. */
	IPC_Channel * msg_ch;	/* Channel the */
				/* message is from/in */

};

struct IPC_WAIT_OPS{
/*
 * IPC_WAIT_OPS::destroy
 *   destroy the wait connection and free the memory space used by
 *	this wait connection.
 * 
 * Parameters:
 *   wait_conn (IN):  the pointer to the wait connection.
 *
 */ 
	void (* destroy)(IPC_WaitConnection *wait_conn);
/*
 * IPC_WAIT_OPS::get_select_fd
 *   provide a fd which user can listen on for a new coming connection.
 *
 * Parameters: 
 *   wait_conn (IN) : the pointer to the wait connection which
 *	we're supposed to return the file descriptor for
 *	(the file descriptor can be used with poll too ;-))
 *
 * Return values:
 *   integer >= 0 :  the select_fd.
 *       -1       :  can't get the select fd.
 *
 */
	int (* get_select_fd)(IPC_WaitConnection *wait_conn);
/*
 * IPC_WAIT_OPS::accept_connection
 *   accept and create a new connection and verify the authentication.
 *
 * Parameters:
 *   wait_conn (IN) : the waiting connection which will accept
 *	create the new connection.
 *   auth_info (IN) : the authentication information which will be
 *	verified for the new connection.
 *
 * Return values:
 *   the pointer to the new IPC channel; NULL if the creation or
 *	authentication fails.
 *
 */
	IPC_Channel * (* accept_connection)
		(IPC_WaitConnection * wait_conn, IPC_Auth *auth_info);
};

/* Standard IPC channel operations */

struct IPC_OPS{
/*
 * IPC_OPS::destroy
 *   brief destroy the channel object.
 *
 * Parameters:
 *   ch  (IN) : the pointer to the channel which will be destroyed.
 *
 */
	void  (*destroy) (IPC_Channel * ch);
/*
 * IPC_OPS::initiate_connection
 *   used by service user side to set up a connection.
 *
 * Parameters:
 *   ch (IN) : the pointer to channel used to initiate the connection. 
 *
 * Return values:
 *   IPC_OK  : the channel set up the connection successfully.
 *   IPC_FAIL     : the connection initiation fails.
 *
 */
	int (* initiate_connection) (IPC_Channel * ch);
/*
 * IPC_OPS::verify_auth
 *   used by either side to verify the identity of peer on connection.
 *
 * Parameters
 *   ch (IN) : the pointer to the channel.
 *
 * Return values:
 *   IPC_OK   : the peer is trust.
 *   IPC_FAIL : verifying authentication fails.
 */
	int (* verify_auth) (IPC_Channel * ch, IPC_Auth* info);
/*
 * IPC_OPS::assert_auth
 *   service user asserts to be certain qualified service user.
 *
 * Parameters:
 *   ch    (IN):  the active channel.
 *   auth  (IN):  the hash table which contains the asserting information.
 *
 * Return values:
 *   IPC_OK :  assert the authentication successfully.
 *   IPC_FAIL    : assertion fails.
 *
 * NOTE:  This operation is a bit obscure.  It isn't needed with
 *	UNIX domain sockets at all.  The intent is that some kinds
 *	of IPC (like FIFOs), do not have an intrinsic method to
 *	authenticate themselves except through file permissions.
 *	The idea is that you must tell it how to chown/grp your
 *	FIFO so that the other side and see that if you can write
 *	this, you can ONLY be the user/group they expect you to be.
 *	But, I think the parameters may be wrong for this ;-)
 */
	int (* assert_auth) (IPC_Channel * ch, GHashTable * auth);
/*
 * IPC_OPS::send
 *   send the message through the sending connection.
 *
 * Parameters:
 *   ch  (IN) : the channel which contains the connection.
 *   msg (IN) : pointer to the sending message. User must
 *	allocate the message space.
 *
 * Return values:
 *   IPC_OK : the message was either sent out successfully or
 *	appended to the send_queue.
 *   IPC_FAIL    : the send operation failed.
 *   IPC_BROKEN  : the channel is broken.
 *
*/    
	int (* send) (IPC_Channel * ch, IPC_Message* msg);

/*
 * IPC_OPS::recv
 *   receive the message through receving queue.
 *
 * Parameters:
 *   ch  (IN) : the channel which contains the connection.
 *   msg (OUT): the IPC_MESSAGE** pointer which contains the pointer
 *		to the received message or NULL if there is no
 *		message available.
 *
 * Return values:
 *   IPC_OK	: receive operation is completed successfully.
 *   IPC_FAIL	: operation failed.
 *   IPC_BROKEN	: the channel is broken (disconnected)
 *
 * Note: 
 *   return value IPC_OK doesn't mean the message is already 
 *   sent out to (or received by) the peer. It may be pending
 *   in the send_queue.  In order to make sure the message is no
 *   longer needed, please specify the msg_done function in the
 *   message structure and once this function is called, the
 *   message is no longer needed.
 *
 *   is_sending_blocked() is another way to check if there is a message 
 *   pending in the send_queue.
 *
 */
	int (* recv) (IPC_Channel * ch, IPC_Message** msg);

/*
 * IPC_OPS::waitin
 *   Wait for input to become available
 *
 * Parameters:
 *   ch  (IN) : the channel which contains the connection.
 *
 * Side effects:
 *	If output becomes unblocked while waiting, it will automatically
 *	be resumed without comment.
 *
 * Return values:
 *   IPC_OK	: a message is pending or output has become unblocked.
 *   IPC_FAIL	: operation failed.
 *   IPC_BROKEN	: the channel is broken (disconnected)
 *   IPC_INTR	: waiting was interrupted by a signal
 */
	int (* waitin) (IPC_Channel * ch);
/*
 * IPC_OPS::waitout
 *   Wait for output to finish
 *
 * Parameters:
 *   ch  (IN) : the channel which contains the connection.
 *
 * Side effects:
 *	If input becomes available while waiting, it will automatically
 *	be read into the channel queue without comment.
 *
 * Return values:
 *   IPC_OK	: output no longer blocked
 *   IPC_FAIL	: operation failed.
 *   IPC_BROKEN	: the channel is broken (disconnected)
 *   IPC_INTR	: waiting was interrupted by a signal
 */
	int (* waitout) (IPC_Channel * ch);

/*
 * IPC_OPS::is_message_pending
 *   check to see if there is any messages ready to read, or hangup has
 *   occurred.
 *
 * Parameters:
 *   ch (IN) : the pointer to the channel.
 *
 * Return values:
 *   TRUE : there are messages ready to read, or hangup.
 *   FALSE: there are no messages ready to be read.
 */
	gboolean (* is_message_pending) (IPC_Channel  * ch);

/*
 * IPC_OPS::is_sending_blocked
 *   check the send_queue to see if there are any messages blocked. 
 *
 * Parameters:
 *   ch (IN) : the pointer to the channel.
 *
 * Return values:
 *   TRUE : there are messages blocked (waiting) in the send_queue.
 *   FALSE: there are no message blocked (waiting) in the send_queue.
 *
 *  See also:
 *	get_send_select_fd()
 */  
	gboolean (* is_sending_blocked) (IPC_Channel  *ch);

/*
 * IPC_OPS::resume_io
 *   Resume all possible IO operations through the IPC transport
 *
 * Parameters:
 *   the pointer to the channel.
 *
 * Return values:
 *   IPC_OK : resume all the possible I/O operation successfully.
 *   IPC_FAIL   : the operation fails.
 *   IPC_BROKEN : the channel is broken.
 *
 */
	int (* resume_io) (IPC_Channel  *ch);
/*
 * IPC_OPS::get_send_select_fd()
 *   return a file descriptor which can be given to select/poll. This fd
 *   is used by the IPC code for sending.  It is intended that this be
 *   ONLY used with select, poll, or similar mechanisms, not for direct I/O.
 *   Note that due to select(2) and poll(2) semantics, you must check
 *   is_sending_blocked() to see whether you should include this FD in
 *   your poll for writability, or you will loop very fast in your
 *   select/poll loop ;-)
 *
 * Parameters:
 *   ch (IN) : the pointer to the channel.
 *
 * Return values:
 *   integer >= 0 : the send fd for selection.
 *      -1         : there is no send fd.
 *
 *  See also:
 *	is_sending_blocked()
 */
	int   (* get_send_select_fd) (IPC_Channel * ch);
/*
 * IPC_OPS::get_recv_select_fd
 *   return a file descriptor which can be given to select. This fd
 *   is for receiving.  It is intended that this be ONLY used with select,
 *   poll, or similar mechanisms, NOT for direct I/O.
 *
 * Parameters:
 *   ch (IN) : the pointer to the channel.
 *
 * Return values:
 *   integer >= 0 : the recv fd for selection.
 *       -1        : there is no recv fd.
 *
 *	NOTE:  This file descriptor is often the same as the send
 *	file descriptor.
 */
	int   (* get_recv_select_fd) (IPC_Channel * ch);
/*
 * IPC_OPS::set_send_qlen
 *   allow user to set the maximum send_queue length.
 *
 * Parameters
 *   ch    (IN) : the pointer to the channel.
 *   q_len (IN) : the max length for the send_queue.
 *
 * Return values:
 *   IPC_OK : set the send queue length successfully.
 *   IPC_FAIL    : there is no send queue. (This isn't supposed
 *		 	to happen).
 *                It means something bad happened.
 *
 */
	int  (* set_send_qlen) (IPC_Channel * ch, int q_len);
/*
 * IPC_OPS::set_recv_qlen
 *   allow user to set the maximum recv_queue length.
 *
 * Parameters:
 *   ch    (IN) : the pointer to the channel.
 *   q_len (IN) : the max length for the recv_queue.
 *
 * Return values:
 *   IPC_OK : set the recv queue length successfully.
 *   IPC_FAIL    : there is no recv queue.
 *
 */
	int  (* set_recv_qlen) (IPC_Channel * ch, int q_len);


/*
 * IPC_OPS: set callback for high/low flow mark
 * ch	(IN) : the pointer to the channel
 * callback (IN) : the callback function
 * user_data(IN) : a pointer to user_data
 *		   callback will be called with channel and
 *		   this user_data as parameters
 *
 * Return values:
 *	void
 *
 */
	
	
	void (* set_high_flow_callback) (IPC_Channel* ch , 	
					 flow_callback_t callback,
					 void* user_data);
	
	void (* set_low_flow_callback) (IPC_Channel* ch , 	
					 flow_callback_t callback,
					 void* user_data);
	
/*
 * IPC_OPS::new_ipcmsg
 * ch	(IN) : the pointer to the channel
 * data (IN) : data to be copied to the message body
 * len	(IN) : data len
 * private (IN): the pointer value to set as in the message
 *
 * Return values:
 *	the pointer to a new created message will be
 *	returned if success or NULL if failure
 *
 */
	
	IPC_Message*	(*new_ipcmsg)(IPC_Channel* ch, const void* data, 
				      int len, void* private);
	
	
/*
 * IPC_OPS::nget_chan_status
 * ch	(IN) : the pointer to the channel
 *
 * Return value:
 *	channel status.
 *
 */
	int	(*get_chan_status)(IPC_Channel* ch);

	
/*
 * These two functions returns true if the corresponding queue 
 * is full, otherwise it returns false
 */
	
	gboolean (*is_sendq_full)(struct IPC_CHANNEL * ch);
	gboolean (*is_recvq_full)(struct IPC_CHANNEL * ch);


	/* Get the connection type for the channel
	 * it can be IPC_SERVER, IPC_CLIENT, IPC_PEER
	 */
	
	int (*get_conntype)(struct IPC_CHANNEL* ch);

	int (*disconnect)(struct IPC_CHANNEL* ch);
		
};


/*
 * ipc_wait_conn_constructor:
 *    the common constructor for ipc waiting connection. 
 *    Use ch_type to identify the connection type. Usually it's only
 *    needed by server side.
 *
 * Parameters:
 *    ch_type   (IN) : the type of the waiting connection to create.
 *    ch_attrs  (IN) : the hash table which contains the attributes
 *			needed by this waiting connection in name/value
 *			pair format.
 *
 *			For example, the only attribute needed by UNIX
 *			domain sockets is path name.
 *
 * Return values:
 *    the pointer to a new waiting connection or NULL if the connection
 *			can't be created.
 * Note:
 *    current implementation supports
 *    IPC_ANYTYPE:       This is what program code should typically use.
 *                       Internally it is an alias to IPC_UDS_CRED.
 *    IPC_UDS_CRED:      Unix Domain Sockets,
 *                       farside uid + gid credentials is available.
 *                       Available since libplumb.so.2.1.0.
 *    IPC_DOMAIN_SOCKET: An other alias to Unix Domain Sockets;
 *                       internally it is equivalent to both above.
 *                       Using this explicitly, your code will work
 *                       even with libplumb.so.2.0.0.
 *                       Which also means that you MUST NOT use the
 *                       farside_uid/gid functionality then.
 */
extern IPC_WaitConnection * ipc_wait_conn_constructor(const char * ch_type
,	GHashTable* ch_attrs);

/*
 * ipc_channel_constructor:
 *   brief the common constructor for ipc channel. 
 *   Use ch_type to identify the channel type.
 *   Usually this function is only called by client side.
 *
 * Parameters:
 *   ch_type  (IN): the type of the channel you want to create.
 *   ch_attrs (IN): the hash table which contains the attributes needed
 *		by this channel.
 *                  For example, the only attribute needed by UNIX domain
 *			socket is path name.
 *
 * Return values:
 *   the pointer to the new channel whose status is IPC_DISCONNECT
 *	or NULL if the channel can't be created.
 *
 * Note:
 *    See comments for ipc_wait_conn_constructor above
 *    for currently implemented ch_type channel types.
 */
extern IPC_Channel  * ipc_channel_constructor(const char * ch_type
,	GHashTable* ch_attrs);

/*
 * ipc_channel_pair:
 *   Construct a pair of connected IPC channels in a fashion analogous
 *	to pipe(2) or socketpair(2).
 *
 * Parameters:
 *   channels: an array of two IPC_Channel pointers for return result
 */
int ipc_channel_pair(IPC_Channel* channels[2]);

/*
 * ipc_set_auth:
 *   A helper function used to convert array of uid and gid into
 *	an authentication structure (IPC_Auth)
 *
 * Parameters:
 *   a_uid    (IN): the array of a set of user ids.
 *   a_gid    (IN): the array of a set of group ids.
 *   num_uid  (IN): the number of user ids.
 *   num_gid  (IN): the number of group ids.
 *
 * Return values:
 *   the pointer to the authentication structure which contains the 
 *   set of uid and the set of gid. Or NULL if this structure can't
 *	be created.
 *
 */


IPC_Auth*  ipc_str_to_auth(const char * uidlist, int, const char * gidlist, int);

extern IPC_Auth * ipc_set_auth(uid_t * a_uid, gid_t * a_gid
,	int num_uid, int num_gid);

/* Destroys an object constructed by ipc_set_auth or ipc_str_to_auth() */
extern void ipc_destroy_auth(IPC_Auth * auth);

extern void ipc_set_pollfunc(int (*)(struct pollfd*, unsigned int, int));
extern void ipc_bufpool_dump_stats(void);

#ifdef IPC_TIME_DEBUG

enum MSGPOS_IN_IPC{
	MSGPOS_ENQUEUE,
	MSGPOS_SEND,
	MSGPOS_RECV,
	MSGPOS_DEQUEUE
};

#endif


struct SOCKET_MSG_HEAD{
	int msg_len;
	unsigned int magic;
#ifdef IPC_TIME_DEBUG
	longclock_t enqueue_time;
	longclock_t send_time;
	longclock_t recv_time;
	longclock_t dequeue_time;
#endif

};


/* MAXMSG is the maximum final message size on the wire. */
#define	MAXMSG		(256*1024)
/* MAXUNCOMPRESSED is the maximum, raw data size prior to compression. */
/* 1:8 compression ratio is to be expected on data such as xml */
#define	MAXUNCOMPRESSED	(2048*1024)
#define HEADMAGIC	0xabcd
#define POOL_SIZE (4*1024)
struct ipc_bufpool{
	
	int refcount;
	char* currpos;
	char* consumepos;
	char* startpos;
	char* endpos;
	int size;
};

struct ipc_bufpool* ipc_bufpool_new(int);

void	ipc_bufpool_del(struct ipc_bufpool* pool);

int	ipc_bufpool_spaceleft(struct ipc_bufpool* pool);

int	ipc_bufpool_update(struct ipc_bufpool* pool,
			   struct IPC_CHANNEL * ch,
			   int msg_len,
			   IPC_Queue* rqueue);

gboolean	ipc_bufpool_full(struct ipc_bufpool* pool,
				 struct IPC_CHANNEL* ch,
				 int*);
int		ipc_bufpool_partial_copy(struct ipc_bufpool* dstpool,
					 struct ipc_bufpool* srcpool);

void	ipc_bufpool_ref(struct ipc_bufpool* pool);

void	ipc_bufpool_unref(struct ipc_bufpool* pool);

void	set_ipc_time_debug_flag(gboolean flag);

/* pathname attribute */
#define	IPC_PATH_ATTR		"path"
/* socket mode attribute */
#define IPC_MODE_ATTR           "sockmode"
/* Unix domain socket, used by old code.
 * See also the comment block above ipc_wait_conn_constructor() */
#define	IPC_DOMAIN_SOCKET	"uds"
/* Unix domain socket with farside uid + gid credentials.
 * Available since libplumb.so.2.1.0 */
#define	IPC_UDS_CRED		"uds_c"

#ifdef IPC_UDS_CRED
#	define	IPC_ANYTYPE		IPC_UDS_CRED
#else
#	error "No IPC types defined(!)"
#endif

#endif
