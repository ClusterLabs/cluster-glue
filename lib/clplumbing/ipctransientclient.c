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

typedef int (*TestFunc_t)(IPC_Channel*chan, int count);

gboolean echoserver_callback(IPC_Channel *client, gpointer user_data);
gboolean echoserver_connect(IPC_Channel *client_channel, gpointer user_data);
IPC_Message *create_simple_message(char *text, IPC_Channel *ch);
int test_iter(int iteration, int child_iters, unsigned int wait_time);
int init_server_ipc_comms(const char *child,
			  gboolean (*channel_client_connect)(IPC_Channel *newclient, gpointer user_data),
			  void (*channel_input_destroy)(gpointer user_data),
			  gboolean usenormalpoll);
IPC_Channel *init_client_ipc_comms(const char *child,
				   gboolean (*dispatch)(IPC_Channel* source_data, gpointer    user_data),
				   void *user_data);
gboolean echoclient_callback(IPC_Channel* server, void* private_data);
void client_send_message(const char *message_text,
			 IPC_Channel *server_channel,
			 int iteration);
void default_ipc_input_destroy(gpointer user_data);
/*
static int checksock(IPC_Channel* channel);
static void checkifblocked(IPC_Channel* channel);

static int (*PollFunc)(struct pollfd * fds, unsigned int, int)
=	(int (*)(struct pollfd * fds, unsigned int, int))  poll;
static gboolean checkmsg(IPC_Message* rmsg, const char * who, int rcount);
static void
checkifblocked(IPC_Channel* chan)
{
	if (chan->ops->is_sending_blocked(chan)) {
		cl_log(LOG_INFO, "Sending is blocked.");
		chan->ops->resume_io(chan);
	}
}


static int
checksock(IPC_Channel* channel)
{

	if (!IPC_ISRCONN(channel)) {
		cl_log(LOG_ERR, "Channel status is %d"
		", not IPC_CONNECT", channel->ch_status);
		return 1;
	}
	return 0;
}

static void
EOFcheck(IPC_Channel* chan)
{
	int		fd = chan->ops->get_recv_select_fd(chan);
	struct pollfd 	pf[1];
	int		rc;

	cl_log(LOG_INFO, "channel state: %d", chan->ch_status);

	if (chan->recv_queue->current_qlen > 0) {
		cl_log(LOG_INFO, "EOF Receive queue has %d messages in it"
		,	chan->recv_queue->current_qlen);
	}
	if (fd <= 0) {
		cl_log(LOG_INFO, "EOF receive fd: %d", fd);
	}


	pf[0].fd	= fd;
	pf[0].events	= POLLIN|POLLHUP;
	pf[0].revents	= 0;

	rc = poll(pf, 1, 0);

	if (rc < 0) {
		cl_perror("failed poll(2) call in EOFcheck");
		return;
	}

	// Got input?
	if (pf[0].revents & POLLIN) {
		cl_log(LOG_INFO, "EOF socket %d (still) has input ready (real poll)"
		,	fd);
	}
	if ((pf[0].revents & ~(POLLIN|POLLHUP)) != 0) {
		cl_log(LOG_INFO, "EOFcheck poll(2) bits: 0x%lx"
		,	(unsigned long)pf[0].revents);
	}
	pf[0].fd	= fd;
	pf[0].events	= POLLIN|POLLHUP;
	pf[0].revents	= 0;
	rc = PollFunc(pf, 1, 0);
	if (rc < 0) {
		cl_perror("failed PollFunc() call in EOFcheck");
		return;
	}

	// Got input?
	if (pf[0].revents & POLLIN) {
		cl_log(LOG_INFO, "EOF socket %d (still) has input ready (PollFunc())"
		,	fd);
	}
	if ((pf[0].revents & ~(POLLIN|POLLHUP)) != 0) {
		cl_log(LOG_INFO, "EOFcheck PollFunc() bits: 0x%lx"
		,	(unsigned long)pf[0].revents);
	}
	abort();
}
*/


int
main(int argc, char ** argv)
{
    int	lpc =0, iteration=0;
    
    cl_log_set_entity("ipc_transient_client_test");
    cl_log_enable_stderr(TRUE);
    
    // give the server a chance to start
    cl_log(LOG_INFO, "#--#--#--#--# Beginning test run %d against server %d...", lpc, iteration);
    GMainLoop* client_main = g_main_new(FALSE);
    
    // connect, send messages
    IPC_Channel *server_channel = init_client_ipc_comms("echo", echoclient_callback, client_main);
    
    if(server_channel == NULL)
    {
	cl_log(LOG_ERR, "[Client %d] Could not connect to server", lpc);
	return 1;
    }
    
    client_send_message("hello", server_channel, lpc);
    
    client_send_message("hello world", server_channel, lpc);
    
    client_send_message("hello world again", server_channel, lpc);

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
init_client_ipc_comms(const char *child,
		      gboolean (*dispatch)(IPC_Channel* source_data
					   ,gpointer    user_data),
		      void *user_data)
{
    IPC_Channel *ch;
    GHashTable * attrs;
    int local_sock_len = 7; // 7 = '/' + ".fifo" + '\0'
    local_sock_len += strlen(child);
    local_sock_len += strlen(WORKING_DIR);

    static char 	path[] = IPC_PATH_ATTR;
    char    commpath[local_sock_len];
    sprintf(commpath, WORKING_DIR "/%s.sock", child);
    commpath[local_sock_len - 1] = '\0';
    
    cl_log(LOG_DEBUG, "[Client] Attempting to talk on: %s", commpath);

    attrs = g_hash_table_new(g_str_hash,g_str_equal);
    g_hash_table_insert(attrs, path, commpath);
//    ch = ipc_channel_constructor(IPC_DOMAIN_SOCKET, attrs);
    ch = ipc_channel_constructor(IPC_ANYTYPE, attrs);
    g_hash_table_destroy(attrs);

    if (ch == NULL)
    {
	cl_log(LOG_CRIT, "[Client] Could not access channel on: %s", commpath);
    }
    else if(ch->ops->initiate_connection(ch) != IPC_OK)
    {
	cl_log(LOG_CRIT, "[Client] Could not init comms on: %s", commpath);
	return NULL;
    }

    G_main_add_IPC_Channel(G_PRIORITY_LOW,
			   ch,
			   FALSE, 
			   dispatch,
			   user_data, 
			   default_ipc_input_destroy);
    
    return ch;
}


gboolean
echoclient_callback(IPC_Channel* server, void* private_data)
{
    int lpc = 0;
    IPC_Message *msg = NULL;
    static int recieved_responses = 0;

    GMainLoop *mainloop = (GMainLoop*)private_data;

    while(server->ch_status != IPC_DISCONNECT && server->ops->is_message_pending(server) == TRUE)
    {
	if(server->ops->recv(server, &msg) != IPC_OK)
	{
	    cl_log(LOG_ERR, "[Client] Error while invoking recv()");
	    perror("[Client]Receive failure:");
	    return FALSE;
	}
	
	if(msg == NULL)
	{
	    cl_log(LOG_DEBUG, "[Client] No message this time");
	    continue;
	}

	lpc++;
	char *buffer = (char*)msg->msg_body;
	cl_log(LOG_DEBUG, "[Client] Got text [text=%s]", buffer);
	recieved_responses++;
    }
    
    if(server->ch_status == IPC_DISCONNECT)
    {
	cl_log(LOG_ERR, "[Client] Client received HUP");
	return FALSE;
    }

    cl_log(LOG_DEBUG, "[Client] Processed %d IPC messages this time, %d total", lpc, recieved_responses);

    if(recieved_responses > 2)
    {
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
    if(server_channel->ch_status != IPC_OK)
    {
	cl_log(LOG_ERR, "[Client %d] Channel is disconnected (status=%d)",
	       iteration, server_channel->ch_status);
	return;
    }
    
    cl_log(LOG_DEBUG, "[Client %d] Sending %s", iteration, message_text);
    IPC_Message *a_message = create_simple_message(strdup(message_text), server_channel);

    while(server_channel->ops->send(server_channel, a_message) == IPC_FAIL)
    {
	cl_log(LOG_ERR, "[Client %d] IPC channel is blocked", iteration);
	cl_shortsleep();
    }
    
    if(server_channel->ch_status != IPC_CONNECT)
    {
	cl_log(LOG_ERR, "[Client %d] Channel is disconnected (status=%d) after first message",
	       iteration, server_channel->ch_status);
    }
}

void
default_ipc_input_destroy(gpointer user_data)
{
    cl_log(LOG_INFO, "default_ipc_input_destroy:received HUP");
}

IPC_Message *
create_simple_message(char *text, IPC_Channel *ch)
{
    if(text == NULL) return NULL;

    //    char	       str[256];
    IPC_Message        *ack_msg = NULL;

    ack_msg = (IPC_Message *)malloc(sizeof(IPC_Message));

    int text_len = strlen(text) + 1;
    char *copy_text = (char *)malloc(sizeof(char)*text_len);
    strcpy(copy_text, text);
    copy_text[text_len-1] = '\0';
    
    ack_msg->msg_private = NULL;
    ack_msg->msg_done    = NULL;
    ack_msg->msg_body    = copy_text;
    ack_msg->msg_ch      = ch;

    ack_msg->msg_len = strlen(text)+1;
    
    return ack_msg;
}

