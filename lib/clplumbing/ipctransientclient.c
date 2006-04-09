/* $Id: ipctransientclient.c,v 1.16 2006/04/09 22:20:15 lars Exp $ */
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

#define	MAXERRORS	1000
#define MAX_IPC_FAIL    10
#define WORKING_DIR     HA_VARLIBDIR"/heartbeat/"
#define FIFO_LEN        1024
#define MAX_MESSAGES 3
char *messages[MAX_MESSAGES];

IPC_Message *create_simple_message(const char *text, IPC_Channel *ch);
IPC_Channel *init_client_ipctest_comms(
	const char *child, gboolean (*dispatch)(
		IPC_Channel* source_data, gpointer    user_data),
	void *user_data);
gboolean transient_client_callback(IPC_Channel* server, void* private_data);
void client_send_message(
	const char *message_text, IPC_Channel *server_channel, int iteration);
void default_ipctest_input_destroy(gpointer user_data);

int
main(int argc, char ** argv)
{
	int	lpc =0, iteration=0;
	GMainLoop* client_main = NULL;
	IPC_Channel *server_channel = NULL;
    
	cl_log_set_entity("ipc_transient_client_test");
	cl_log_enable_stderr(TRUE);
    
	/* give the server a chance to start */
	cl_log(LOG_INFO, "#--#--#--#--# Beginning test run %d against server %d...", lpc, iteration);
	client_main = g_main_new(FALSE);
    
	/* connect, send messages */
	server_channel = init_client_ipctest_comms("echo", transient_client_callback, client_main);
    
	if(server_channel == NULL) {
		cl_log(LOG_ERR, "[Client %d] Could not connect to server", lpc);
		return 1;
	}

	for(lpc = 0; lpc < MAX_MESSAGES; lpc++) {
		messages[lpc] = (char *)malloc(sizeof(char)*1000);
	}
	sprintf(messages[0], "%s_%ld%c", "hello", (long)getpid(), '\0');
	sprintf(messages[1], "%s_%ld%c", "hello_world", (long)getpid(), '\0');
	sprintf(messages[2], "%s_%ld%c", "hello_world_again", (long)getpid(), '\0');

	for(lpc = 0; lpc < MAX_MESSAGES; lpc++) {
		client_send_message(messages[lpc], server_channel, lpc);
	}
    
	server_channel->ops->waitout(server_channel);
    
	/* wait for the reply by creating a mainloop and running it until
	 * the callbacks are invoked...
	 */
    
	cl_log(LOG_DEBUG, "Waiting for replies from the echo server");
	g_main_run(client_main);
	cl_log(LOG_INFO, "[Iteration %d] Client %d completed successfully", iteration, lpc);
    
	return 0;
}


IPC_Channel *
init_client_ipctest_comms(const char *child,
			  gboolean (*dispatch)(IPC_Channel* source_data
					       ,gpointer    user_data),
			  void *user_data)
{
	IPC_Channel *ch;
	GHashTable * attrs;
	int local_sock_len = 2; /* 2 = '/' + '\0' */
	char    *commpath = NULL;
	static char 	path[] = IPC_PATH_ATTR;
	
	local_sock_len += strlen(child);
	local_sock_len += strlen(WORKING_DIR);
	
	commpath = (char*)malloc(sizeof(char)*local_sock_len);
	if (commpath == NULL){
		cl_log(LOG_ERR, "init_client_ipc_comms:"
		       " allocating memory failed");
		return NULL;
		
	}
	sprintf(commpath, WORKING_DIR "/%s", child);
	commpath[local_sock_len - 1] = '\0';
	
	cl_log(LOG_DEBUG, "[Client] Attempting to talk on: %s", commpath);

	attrs = g_hash_table_new(g_str_hash,g_str_equal);
	g_hash_table_insert(attrs, path, commpath);
	ch = ipc_channel_constructor(IPC_ANYTYPE, attrs);
	g_hash_table_destroy(attrs);
	
	if (ch == NULL) {
		cl_log(LOG_ERR, "[Client] Could not access channel on: %s", commpath);
		return NULL;
	} else if(ch->ops->initiate_connection(ch) != IPC_OK) {
		cl_log(LOG_ERR, "[Client] Could not init comms on: %s", commpath);
		return NULL;
	}

	G_main_add_IPC_Channel(G_PRIORITY_LOW,
			       ch, FALSE, dispatch, user_data, 
			       default_ipctest_input_destroy);
	
	return ch;
}


gboolean
transient_client_callback(IPC_Channel* server, void* private_data)
{
	int lpc = 0;
	IPC_Message *msg = NULL;
	static int recieved_responses = 0;
	char *buffer = NULL;

	GMainLoop *mainloop = (GMainLoop*)private_data;

	while(server->ops->is_message_pending(server) == TRUE) {
		if (server->ch_status == IPC_DISCONNECT) {
			/* The message which was pending for us is the
			 * new status of IPC_DISCONNECT */
			break;
		}
		if(server->ops->recv(server, &msg) != IPC_OK) {
			cl_log(LOG_ERR, "[Client] Error while invoking recv()");
			perror("[Client] Receive failure:");
			return FALSE;
		}
		
		if(msg != NULL) {
			buffer = (char*)msg->msg_body;
			cl_log(LOG_DEBUG, "[Client] Got text [text=%s]", buffer);
			recieved_responses++;

			if(lpc < MAX_MESSAGES && strcmp(messages[lpc], buffer) != 0)
			{
				cl_log(LOG_ERR, "[Client] Recieved someone else's message [%s] instead of [%s]", buffer, messages[lpc]);
			}
			else if(lpc >= MAX_MESSAGES)
			{
				cl_log(LOG_ERR, "[Client] Recieved an extra message [%s]", buffer);
			}
			
			lpc++;
			msg->msg_done(msg);
		} else {
			cl_log(LOG_ERR, "[Client] No message this time");
		}
	}
    
	if(server->ch_status == IPC_DISCONNECT) {
		cl_log(LOG_ERR, "[Client] Client received HUP");
		return FALSE;
	}

	cl_log(LOG_DEBUG, "[Client] Processed %d IPC messages this time, %d total", lpc, recieved_responses);

	if(recieved_responses > 2) {
		cl_log(LOG_INFO, "[Client] Processed %d IPC messages, all done.", recieved_responses);
		recieved_responses = 0;
		g_main_quit(mainloop);
		cl_log(LOG_INFO, "[Client] Exiting.");
		return FALSE;
	}
    
	return TRUE;
}

void
client_send_message(const char *message_text,
		    IPC_Channel *server_channel,
		    int iteration)
{
	IPC_Message *a_message = NULL;
	if(server_channel->ch_status != IPC_CONNECT) {
		cl_log(LOG_WARNING, "[Client %d] Channel is in state %d before sending message [%s]",
		       iteration, server_channel->ch_status, message_text);
		return;
	}
    
	a_message = create_simple_message(message_text, server_channel);
	if(a_message == NULL) {
		cl_log(LOG_ERR, "Could not create message to send");
	} else {
		cl_log(LOG_DEBUG, "[Client %d] Sending message: %s", iteration, (char*)a_message->msg_body);
		while(server_channel->ops->send(server_channel, a_message) == IPC_FAIL) {
			cl_log(LOG_ERR, "[Client %d] IPC channel is blocked", iteration);
			cl_shortsleep();
		}
		
		if(server_channel->ch_status != IPC_CONNECT) {
			cl_log(LOG_WARNING,
			       "[Client %d] Channel is in state %d after sending message [%s]",
			       iteration, server_channel->ch_status, message_text);
		}
	}
}

void
default_ipctest_input_destroy(gpointer user_data)
{
	cl_log(LOG_INFO, "default_ipc_input_destroy:received HUP");
}

IPC_Message *
create_simple_message(const char *text, IPC_Channel *ch)
{
	char *copy_text = NULL;
	IPC_Message *ack_msg = NULL;
	
	if(text == NULL) {
		cl_log(LOG_ERR, "can't create IPC_Message with no text");
		return NULL;
	} else if(ch == NULL) {
		cl_log(LOG_ERR, "can't create IPC_Message with no channel");
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
	ack_msg->msg_len     = strlen(text)+1;
	
	return ack_msg;
}
