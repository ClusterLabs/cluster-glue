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

#include <ipctransient.h>

#define MAX_MESSAGES 3
static char *messages[MAX_MESSAGES];

IPC_Message *create_simple_message(const char *text, IPC_Channel *ch);
IPC_Channel *init_client_ipctest_comms(
	const char *child, gboolean (*dispatch)(
		IPC_Channel* source_data, gpointer    user_data),
	void *user_data);
gboolean transient_client_callback(IPC_Channel* server, void* private_data);
void client_send_message(
	const char *message_text, IPC_Channel *server_channel, int iteration);

#define	MAXTSTMSG	1000

int
main(int argc, char ** argv)
{
	int	lpc =0, iteration=0;
	GMainLoop* client_main = NULL;
	IPC_Channel *server_channel = NULL;

	trans_getargs(argc, argv);
    
	cl_log_set_entity(procname);
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
		messages[lpc] = (char *)malloc(sizeof(char)*MAXTSTMSG);
	}
	snprintf(messages[0], MAXTSTMSG
	,	"%s_%ld%c", "hello", (long)getpid(), '\0');
	snprintf(messages[1], MAXTSTMSG
	,	"%s_%ld%c", "hello_world", (long)getpid(), '\0');
	snprintf(messages[2], MAXTSTMSG
	,	"%s_%ld%c", "hello_world_again", (long)getpid(), '\0');

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
	static char path[] = IPC_PATH_ATTR;

	local_sock_len += strlen(child);
	local_sock_len += strlen(commdir);
	
	commpath = (char*)malloc(sizeof(char)*local_sock_len);
	if (commpath == NULL){
		cl_log(LOG_ERR, "%s: allocating memory failed", __FUNCTION__);
		return NULL;
	}
	sprintf(commpath, "%s/%s", commdir, child);
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
	char *buffer = NULL;
	static int received_responses = 0;

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
		
		if (msg != NULL) {
			buffer = (char*)msg->msg_body;
			cl_log(LOG_DEBUG, "[Client] Got text [text=%s]", buffer);
			received_responses++;

			if(lpc < MAX_MESSAGES && strcmp(messages[lpc], buffer) != 0)
			{
				cl_log(LOG_ERR, "[Client] Received someone else's message [%s] instead of [%s]", buffer, messages[lpc]);
			}
			else if(lpc >= MAX_MESSAGES)
			{
				cl_log(LOG_ERR, "[Client] Receivedan extra message [%s]", buffer);
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

	cl_log(LOG_DEBUG, "[Client] Processed %d IPC messages this time, %d total", lpc, received_responses);

	if(received_responses > 2) {
		cl_log(LOG_INFO, "[Client] Processed %d IPC messages, all done.", received_responses);
		received_responses = 0;
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
