/* $Id: ocf_ipc.c,v 1.27 2005/04/01 22:55:40 gshi Exp $ */
/*
 *
 * ocf_ipc.c: IPC abstraction implementation.
 *
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <clplumbing/cl_log.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef IPC_TIME_DEBUG
extern struct ha_msg* wirefmt2msg(const char* s, size_t length);
void cl_log_message (int log_level, const struct ha_msg *m);
int  timediff(longclock_t t1, longclock_t t2);
void   ha_msg_del(struct ha_msg* msg);
void	ipc_time_debug(IPC_Channel* ch, IPC_Message* ipcmsg, int whichpos);

#endif

struct IPC_WAIT_CONNECTION * socket_wait_conn_new(GHashTable* ch_attrs);
struct IPC_CHANNEL * socket_client_channel_new(GHashTable* ch_attrs);

int (*ipc_pollfunc_ptr)(struct pollfd*, unsigned int, int)
=	(int (*)(struct pollfd*, unsigned int, int)) poll;

/* Set the IPC poll function to the given function */
void
ipc_set_pollfunc(int (*pf)(struct pollfd*, unsigned int, int))
{
	ipc_pollfunc_ptr = pf;
}

struct IPC_WAIT_CONNECTION * 
ipc_wait_conn_constructor(const char * ch_type, GHashTable* ch_attrs)
{
  if (strcmp(ch_type, "domain_socket") == 0
  ||	strcmp(ch_type, IPC_ANYTYPE) == 0
  ||	strcmp(ch_type, IPC_DOMAIN_SOCKET) == 0) {
    return socket_wait_conn_new(ch_attrs);
  }
  return NULL;
}

struct IPC_CHANNEL * 
ipc_channel_constructor(const char * ch_type, GHashTable* ch_attrs)
{
  if	(strcmp(ch_type, "domain_socket") == 0
  ||	strcmp(ch_type, IPC_ANYTYPE) == 0
  ||	strcmp(ch_type, IPC_DOMAIN_SOCKET) == 0) {

	return socket_client_channel_new(ch_attrs);
  }
  return NULL;
}


struct IPC_AUTH * 
ipc_set_auth(uid_t * a_uid, gid_t * a_gid, int num_uid, int num_gid)
{
  struct IPC_AUTH *temp_auth;
  int i;
  static int v = 1;

  temp_auth = g_new(struct IPC_AUTH, 1);
  temp_auth->uid = g_hash_table_new(g_direct_hash, g_direct_equal);
  temp_auth->gid = g_hash_table_new(g_direct_hash, g_direct_equal);

  if (num_uid > 0) {
    for (i=0; i<num_uid; i++) {
      g_hash_table_insert(temp_auth->uid, GINT_TO_POINTER((gint)a_uid[i])
      ,		&v);
    }
  }

  if (num_gid > 0) {
    for (i=0; i<num_gid; i++) {
      g_hash_table_insert(temp_auth->gid, GINT_TO_POINTER((gint)a_gid[i])
      ,		&v);
    }
  }

  return temp_auth;
}

void
ipc_destroy_auth(struct IPC_AUTH *auth)
{
	if (auth != NULL) {
		if (auth->uid) {
			g_hash_table_destroy(auth->uid);
		}
		if (auth->gid) {
			g_hash_table_destroy(auth->gid);
		}
		g_free((void *)auth);
	}
}

	
struct ipc_bufpool*
ipc_bufpool_new(int size)
{
	struct ipc_bufpool* pool;
	int	totalsize;
	
	
	/* there are memories for two struct SOCKET_MSG_HEAD
	 * one for the big message, the other one for the next
	 * message. This code prevents allocating 
	 *	<big memory> <4k> <big memory><4k> ... 
	 * from happening when a client sends big messages
	 * constantly*/

	totalsize = size + sizeof(struct ipc_bufpool) 
		+ sizeof(struct SOCKET_MSG_HEAD) * 2 ;		
	
	if (totalsize < POOL_SIZE){
		totalsize = POOL_SIZE;
	}
	
	if (totalsize > MAXDATASIZE){
		cl_log(LOG_INFO, "ipc_bufpool_new: "
		       "asking for buffer with size %d"
		       "corrupted data len???", totalsize);
		return NULL;
	}
	
	pool = (struct ipc_bufpool*)g_malloc(totalsize+1);
	memset(pool, 0, totalsize);
	pool->refcount = 1;
	pool->startpos = pool->currpos = pool->consumepos =
		((char*)pool) + sizeof(struct ipc_bufpool); 
	
	pool->endpos = ((char*)pool)  + totalsize;
	pool->size = totalsize;
	
	return pool;
}

void
ipc_bufpool_del(struct ipc_bufpool* pool)
{
	
	if (pool == NULL){
		return;
	}
	
	if (pool->refcount > 0){
		cl_log(LOG_ERR," ipc_bufpool_del:"
		       " IPC buffer pool reference count"
		       " > 0");
		return;
	}
	
	memset(pool, 0, pool->size);
	g_free(pool);	
	return;
}

int
ipc_bufpool_spaceleft(struct ipc_bufpool* pool)
{

	if( pool == NULL){
		cl_log(LOG_ERR, "ipc_bufpool_spacelft:"
		       "invalid input argument");
		return 0;		
	}
	
	return pool->endpos - pool->currpos;
}




/* brief free the memory space allocated to msg and destroy msg. */

static void
ipc_bufpool_msg_done(struct IPC_MESSAGE * msg) {
	
	struct ipc_bufpool* pool;
	
	if (msg == NULL){
		cl_log(LOG_ERR, "ipc_bufpool_msg_done:"
		       "invalid input");
		return;
	}
	
	pool = (struct ipc_bufpool*)msg->msg_private;
	
	ipc_bufpool_unref(pool);
	g_free(msg);
	
}

static struct IPC_MESSAGE*
ipc_bufpool_msg_new(void)
{
	struct IPC_MESSAGE * temp_msg;
	
	temp_msg = g_malloc(sizeof(struct IPC_MESSAGE));
	if (temp_msg == NULL){
		cl_log(LOG_ERR, "ipc_bufpool_msg_new:"
		       "allocating new msg failed");
		return NULL;
	}
	
	memset(temp_msg, 0, sizeof(struct IPC_MESSAGE));

	return temp_msg;
}


/* after a recv call, we have new data
 * in the pool buf, we need to update our
 * pool struct to consume it
 *
 */

int
ipc_bufpool_update(struct ipc_bufpool* pool,
		   struct IPC_CHANNEL * ch,
		   int msg_len,
		   IPC_Queue* rqueue)
{
	IPC_Message*			ipcmsg;
	struct SOCKET_MSG_HEAD		localhead;
	struct SOCKET_MSG_HEAD*		head = &localhead;
	int				nmsgs = 0 ;
	

	if (rqueue == NULL){
		cl_log(LOG_ERR, "ipc_update_bufpool:"
		       "invalid input");
		return 0;
	}
	
	pool->currpos += msg_len;
	
	while(TRUE){
		/*not enough data for head*/
		if ((int)(pool->currpos - pool->consumepos) < (int)ch->msgpad){
			break;
		}
		
		memcpy(head, pool->consumepos, sizeof(struct SOCKET_MSG_HEAD));
		
		if (head->magic != HEADMAGIC){
			cl_log(LOG_ERR, "ipc_bufpool_update: "
			       "magic number in head does not match."
			       "Something very bad happened, abort now, farside pid =%d",
			       ch->farside_pid);
			abort();
		}

		if ( head->msg_len > MAXDATASIZE){
			cl_log(LOG_ERR, "ipc_update_bufpool:"
			       "msg length is corruptted(%d)",
			       head->msg_len);
			break;
		}
		
		if (pool->consumepos + ch->msgpad + head->msg_len
		    > pool->currpos){
			break;			
		}
		
		ipcmsg = ipc_bufpool_msg_new();
		if (ipcmsg == NULL){
			cl_log(LOG_ERR, "ipc_update_bufpool:"
			       "allocating memory for new ipcmsg failed");
			break;
			
		}
		ipcmsg->msg_buf = pool->consumepos;
		ipcmsg->msg_body = pool->consumepos + ch->msgpad;
		ipcmsg->msg_len = head->msg_len;
		ipcmsg->msg_private = pool;
		ipcmsg->msg_done = ipc_bufpool_msg_done;
		
#ifdef IPC_TIME_DEBUG				
		ipc_time_debug(ch,ipcmsg, MSGPOS_RECV);
#endif				


		rqueue->queue = g_list_append(rqueue->queue, ipcmsg);
		rqueue->current_qlen ++;
		nmsgs++;
		
		pool->consumepos += ch->msgpad + head->msg_len;
		ipc_bufpool_ref(pool);
	}
	
	return nmsgs;
}






gboolean
ipc_bufpool_full(struct ipc_bufpool* pool, 
		 struct IPC_CHANNEL* ch, 
		 int* dataspaceneeded)
{
	
	struct SOCKET_MSG_HEAD  localhead;
	struct SOCKET_MSG_HEAD* head = &localhead;

	*dataspaceneeded = 0;
	/* not enough space for head */
	if ((int)(pool->endpos - pool->consumepos) < (int)ch->msgpad){
		return TRUE;
	}
	
	/*enough space for head*/
	if ((int)(pool->currpos - pool->consumepos) >= (int)ch->msgpad){
		memcpy(head, pool->consumepos, sizeof(struct SOCKET_MSG_HEAD));
		
		/* not enough space for data*/
		if ( pool->consumepos + ch->msgpad + head->msg_len >= pool->endpos){
			*dataspaceneeded = head->msg_len;
			return TRUE;
		}
	}
	
	
	/* Either we are sure we have enough space 
	 * or we cannot tell because we have not received
	 * head yet. But we are sure we have enough space
	 * for head
	 */
	return FALSE;


	
}


int 
ipc_bufpool_partial_copy(struct ipc_bufpool* dstpool,
			      struct ipc_bufpool* srcpool)
{
	struct SOCKET_MSG_HEAD	localhead;
	struct SOCKET_MSG_HEAD *head = &localhead;
	int space_needed;
	int nbytes;
	
	if (dstpool == NULL
	    || srcpool == NULL){
		cl_log(LOG_ERR, "ipc_bufpool_partial_ipcmsg_cp:"
		       "invalid input");		
		return IPC_FAIL;
	}
	
	if (srcpool->currpos - srcpool->consumepos >=
	    (ssize_t)sizeof(struct SOCKET_MSG_HEAD)){
		
		memcpy(head, srcpool->consumepos, sizeof(struct SOCKET_MSG_HEAD));
		space_needed = head->msg_len + sizeof(*head);
		
		if (space_needed >  ipc_bufpool_spaceleft(dstpool)){
			cl_log(LOG_ERR, "ipc_bufpool_partial_ipcmsg_cp:"
			       " not enough space left in dst pool,spaced needed=%d",
			       space_needed);
			return IPC_FAIL;	
		}	
	}
	
	nbytes = srcpool->currpos - srcpool->consumepos;
	memcpy(dstpool->consumepos, srcpool->consumepos,nbytes);
	
	
	srcpool->currpos = srcpool->consumepos;
	dstpool->currpos = dstpool->consumepos + nbytes;
	
	return IPC_OK;
}


void
ipc_bufpool_ref(struct ipc_bufpool* pool)
{
	if (pool == NULL){
		cl_log(LOG_ERR, "ref_pool:"
		       " invalid input");
		return;		
	}
	
	pool->refcount ++;
	
}

void
ipc_bufpool_unref(struct ipc_bufpool* pool){
	
	if (pool == NULL){
		cl_log(LOG_ERR, "unref_pool:"
		       " invalid input");
		return;		
	}
	
	pool->refcount --;

	if (pool->refcount <= 0){
		ipc_bufpool_del(pool);
	}
	
	return;
}
