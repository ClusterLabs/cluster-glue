/* $Id: ipctransientserver.c,v 1.14 2006/04/10 07:50:14 lars Exp $ */
/* 
 * Copyright (C) 2004 Andrew Beekhof <andrew@beekhof.net>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#undef _GNU_SOURCE  /* in case it was defined on the command line */
#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_poll.h>
#include <clplumbing/GSource.h>
#include <clplumbing/ipc.h>
#include <clplumbing/realtime.h>
#include <clplumbing/lsb_exitcodes.h>
#include <ha_config.h>
#include <errno.h>

#define	MAXERRORS	    1000
#define MAX_IPC_FAIL    10
#define WORKING_DIR     HA_VARLIBDIR"/heartbeat/"
#define FIFO_LEN        1024

gboolean transient_server_callback(IPC_Channel *client, gpointer user_data);
gboolean transient_server_connect(IPC_Channel *client_channel, gpointer user_data);
IPC_Message *create_simple_message(char *text, IPC_Channel *ch);
int init_server_ipc_comms(const char *child,
						  gboolean (*channel_client_connect)(IPC_Channel *newclient, gpointer user_data),
						  void (*channel_input_destroy)(gpointer user_data),
						  gboolean usenormalpoll);
void default_ipc_input_destroy(gpointer user_data);

int
main(int argc, char ** argv)
{
	int	iteration = 0;
    GMainLoop* mainloop = NULL;
    
    cl_log_set_entity("ipc_transient_server_test");
    cl_log_enable_stderr(TRUE);
    
    init_server_ipc_comms("echo", transient_server_connect, default_ipc_input_destroy, FALSE);
    
    /* wait for the reply by creating a mainloop and running it until
     * the callbacks are invoked...
     */
    mainloop = g_main_new(FALSE);

    cl_log(LOG_INFO, "#--#--#--# Echo Server %d is active...", iteration);
    g_main_run(mainloop);
    cl_log(LOG_INFO, "#--#--#--# Echo Server %d is stopped...", iteration);
    
    return 0;
}


int
init_server_ipc_comms(const char *child,
					  gboolean (*channel_client_connect)(IPC_Channel *newclient, gpointer user_data),
					  void (*channel_input_destroy)(gpointer user_data),
					  gboolean usenormalpoll)
{
    /* the clients wait channel is the other source of events.
     * This source delivers the clients connection events.
     * listen to this source at a relatively lower priority.
     */
    int local_sock_len = 2; /* 2 = '/' + '\0' */
    char    *commpath = NULL;
    char path[] = IPC_PATH_ATTR;
    mode_t mask;
    IPC_WaitConnection *wait_ch;
	GHashTable * attrs = g_hash_table_new(g_str_hash,g_str_equal);
	
    local_sock_len += strlen(child);
    local_sock_len += strlen(WORKING_DIR);
    
    commpath = (char*)malloc(sizeof(char)*local_sock_len);
    if (commpath == NULL){
	    cl_log(LOG_ERR, "init_server_ipc_comms:"
		   " allocating memory failed");
	    exit(1);
    }
    sprintf(commpath, WORKING_DIR "/%s", child);
    commpath[local_sock_len - 1] = '\0';

    g_hash_table_insert(attrs, path, commpath);
    
    mask = umask(0);
    wait_ch = ipc_wait_conn_constructor(IPC_ANYTYPE, attrs);
    if (wait_ch == NULL){
	    cl_perror("[Server] Can't create wait channel of type %s", IPC_ANYTYPE);
	    exit(1);
    }
    mask = umask(mask);
    g_hash_table_destroy(attrs);

	G_main_add_IPC_WaitConnection(G_PRIORITY_LOW,
								  wait_ch,
								  NULL,
								  FALSE,
								  channel_client_connect,
								  wait_ch, /* user data passed to ?? */
								  channel_input_destroy);

    cl_log(LOG_INFO, "[Server] Listening on: %s", commpath);

/*     if (!usenormalpoll) { */
/* 		g_main_set_poll_func(cl_glibpoll); */
/* 		ipc_set_pollfunc(cl_poll); */
/*     } */
    return 0;
}


void
default_ipc_input_destroy(gpointer user_data)
{
    cl_log(LOG_INFO, "default_ipc_input_destroy:received HUP");
}

gboolean
transient_server_callback(IPC_Channel *client, gpointer user_data)
{
    int lpc = 0;
    IPC_Message *msg = NULL;
    char *buffer = NULL;
    IPC_Message *reply = NULL;
    int llpc = 0;

    cl_log(LOG_DEBUG, "channel: %p", client);

    cl_log(LOG_DEBUG, "Client status %d (disconnect=%d)", client->ch_status, IPC_DISCONNECT);

    while(client->ops->is_message_pending(client)) {
    		if (client->ch_status == IPC_DISCONNECT) {
			/* The message which was pending for us is that
			 * the IPC status is now IPC_DISCONNECT */
			break;
	        }
		if(client->ops->recv(client, &msg) != IPC_OK) {
			cl_perror("[Server] Receive failure");
			return FALSE;
		}
		
		if(msg != NULL){
			lpc++;
			buffer = (char*)g_malloc(msg->msg_len+1);
			memcpy(buffer,msg->msg_body, msg->msg_len);
			buffer[msg->msg_len] = '\0';
			cl_log(LOG_DEBUG, "[Server] Got xml [text=%s]", buffer);
			
			reply = create_simple_message(strdup(buffer), client);
			if (!reply) {
				cl_log(LOG_ERR, "[Server] Could allocate reply msg.");
				return FALSE;
			}
			
			llpc = 0;
			while(llpc++ < MAX_IPC_FAIL && client->ops->send(client, reply) == IPC_FAIL) {
				cl_log(LOG_WARNING, "[Server] ipc channel blocked");
				cl_shortsleep();
			}
			
			if(lpc == MAX_IPC_FAIL) {
				cl_log(LOG_ERR, "[Server] Could not send IPC, message.  Channel is dead.");
				free(reply);
				return FALSE;
			}
			
			cl_log(LOG_DEBUG, "[Server] Sent reply");
			msg->msg_done(msg);
		} else {
			cl_log(LOG_ERR, "[Server] No message this time");
			continue;
		}
    }

    cl_log(LOG_DEBUG, "[Server] Processed %d messages", lpc);
    
    cl_log(LOG_DEBUG, "[Server] Client status %d", client->ch_status);
    if(client->ch_status != IPC_CONNECT) {
		cl_log(LOG_INFO, "[Server] Server received HUP from child");
		return FALSE;
    }
    
	 
    return TRUE;
}


gboolean
transient_server_connect(IPC_Channel *client_channel, gpointer user_data)
{
    /* assign the client to be something, or put in a hashtable */
    cl_log(LOG_DEBUG, "A client tried to connect... and there was much rejoicing.");

    if(client_channel == NULL) {
		cl_log(LOG_ERR, "[Server] Channel was NULL");
    } else if(client_channel->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_ERR, "[Server] Channel was disconnected");
    } else {
		cl_log(LOG_DEBUG, "[Server] Client is %s %p", client_channel == NULL?"NULL":"valid", client_channel);
		cl_log(LOG_DEBUG, "[Server] Client status %d (disconnect=%d)", client_channel->ch_status, IPC_DISCONNECT);
		
		cl_log(LOG_DEBUG, "[Server] Adding IPC Channel to main thread.");
		G_main_add_IPC_Channel(G_PRIORITY_LOW,
							   client_channel,
							   FALSE, 
							   transient_server_callback,
							   NULL,
							   default_ipc_input_destroy);
    }
    
    return TRUE;
}

IPC_Message *
create_simple_message(char *text, IPC_Channel *ch)
{
    IPC_Message *ack_msg = NULL;
    char *copy_text = NULL;

    if(text == NULL) {
		cl_log(LOG_ERR, "ERROR: can't create IPC_Message with no text");
		return NULL;
	} else if(ch == NULL) {
		cl_log(LOG_ERR, "ERROR: can't create IPC_Message with no channel");
		return NULL;
	}

    ack_msg = (IPC_Message *)malloc(sizeof(IPC_Message));
    if (ack_msg == NULL){
	    cl_log(LOG_ERR, "create_simple_message:"
		   "allocating memory for IPC_Message failed");		
	    return NULL;
    }
    
    memset(ack_msg, 0, sizeof(IPC_Message));
    
    copy_text = strdup(text);
    
    ack_msg->msg_private = NULL;
    ack_msg->msg_done    = NULL;
    ack_msg->msg_body    = copy_text;
    ack_msg->msg_ch      = ch;

    ack_msg->msg_len = strlen(text)+1;
    
    return ack_msg;
}
