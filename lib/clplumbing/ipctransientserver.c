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
    int	iteration = 0;
    GMainLoop* mainloop = NULL;
    
    cl_log_set_entity("ipc_transient_server_test");
    cl_log_enable_stderr(TRUE);
    
    init_server_ipc_comms("echo", echoserver_connect, default_ipc_input_destroy, FALSE);
    
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
    
    IPC_WaitConnection *wait_ch;
    char    commpath[FIFO_LEN];

    mode_t mask;
    char path[] = IPC_PATH_ATTR;
    
    GHashTable * attrs = g_hash_table_new(g_str_hash,g_str_equal);

    sprintf(commpath, WORKING_DIR "/%s.sock", child);

    g_hash_table_insert(attrs, path, commpath);
    
    mask = umask(0);
    wait_ch = ipc_wait_conn_constructor(IPC_ANYTYPE, attrs);
    if (wait_ch == NULL)
    {
	cl_perror("[Server] Can't create wait channel of type %s", IPC_ANYTYPE);
	exit(1);
    }
    mask = umask(mask);
    g_hash_table_destroy(attrs);

    
    if(wait_ch == NULL) return 1;
    G_main_add_IPC_WaitConnection(G_PRIORITY_LOW,
				  wait_ch,
				  NULL,
				  FALSE,
				  channel_client_connect,
				  wait_ch, // user data passed to ??
				  channel_input_destroy);

    cl_log(LOG_INFO, "[Server] Listening on: %s", commpath);

    if (!usenormalpoll) { 
	g_main_set_poll_func(cl_glibpoll);
	ipc_set_pollfunc(cl_poll); 
    } 
    return 0;
}


void
default_ipc_input_destroy(gpointer user_data)
{
    cl_log(LOG_INFO, "default_ipc_input_destroy:received HUP");
}

gboolean
echoserver_callback(IPC_Channel *client, gpointer user_data)
{
    int lpc = 0;
    IPC_Message *msg = NULL;
    char *buffer = NULL;
    IPC_Message *reply = NULL;
    int llpc = 0;

    cl_log(LOG_DEBUG, "channel: %p", client);

    cl_log(LOG_DEBUG, "Client status %d (disconnect=%d)", client->ch_status, IPC_DISCONNECT);

    while(client->ch_status != IPC_DISCONNECT && client->ops->is_message_pending(client) == TRUE)
    {
	if(client->ops->recv(client, &msg) != IPC_OK)
	{
	    perror("[Server] Receive failure:");
	    return FALSE;
	}
	
	if(msg == NULL)
	{
	    cl_log(LOG_DEBUG, "[Server] No message this time");
	    continue;
	}

	lpc++;
	buffer = (char*)msg->msg_body;
	cl_log(LOG_DEBUG, "[Server] Got xml [text=%s]", buffer);

	reply = create_simple_message(strdup(buffer), client);

	while(llpc++ < MAX_IPC_FAIL && client->ops->send(client, reply) == IPC_FAIL)
	{
	    cl_log(LOG_WARNING, "[Server] ipc channel blocked");
	    cl_shortsleep();
	}
	
	if(lpc == MAX_IPC_FAIL)
	{
	    cl_log(LOG_ERR, "[Server] Could not send IPC, message.  Channel is dead.");
	    return FALSE;
	}
    
	cl_log(LOG_DEBUG, "[Server] Sent reply");
	msg->msg_done(msg);
    }

    cl_log(LOG_DEBUG, "[Server] Processed %d messages", lpc);
    
    cl_log(LOG_DEBUG, "[Server] Client status %d", client->ch_status);
    if(client->ch_status != IPC_OK)
    {
	cl_log(LOG_INFO, "[Server] Server received HUP from child");
	return FALSE;
    }
    
	 
    return TRUE;
}


gboolean
echoserver_connect(IPC_Channel *client_channel, gpointer user_data)
{
    // assign the client to be something, or put in a hashtable
    cl_log(LOG_DEBUG, "A client tried to connect... and there was much rejoicing.");

    if(client_channel == NULL)
    {
	cl_log(LOG_ERR, "[Server] Channel was NULL");
    }
    else if(client_channel->ch_status == IPC_DISCONNECT)
    {
	cl_log(LOG_ERR, "[Server] Channel was disconnected");
    }
    else
    {
	cl_log(LOG_DEBUG, "[Server] Client is %s %p", client_channel == NULL?"NULL":"valid", client_channel);
	cl_log(LOG_DEBUG, "[Server] Client status %d (disconnect=%d)", client_channel->ch_status, IPC_DISCONNECT);
	
	cl_log(LOG_DEBUG, "[Server] Adding IPC Channel to main thread.");
	G_main_add_IPC_Channel(G_PRIORITY_LOW,
			       client_channel,
			       FALSE, 
			       echoserver_callback,
			       NULL,
			       default_ipc_input_destroy);
    }
    
    return TRUE;
}

IPC_Message *
create_simple_message(char *text, IPC_Channel *ch)
{
    //    char	       str[256];
    IPC_Message        *ack_msg = NULL;
    int text_len = 0;
    char *copy_text = NULL;

    if(text == NULL) return NULL;

    ack_msg = (IPC_Message *)malloc(sizeof(IPC_Message));

    text_len = strlen(text) + 1;
    copy_text = (char *)malloc(sizeof(char)*text_len);
    strcpy(copy_text, text);
    copy_text[text_len-1] = '\0';
    
    ack_msg->msg_private = NULL;
    ack_msg->msg_done    = NULL;
    ack_msg->msg_body    = copy_text;
    ack_msg->msg_ch      = ch;

    ack_msg->msg_len = strlen(text)+1;
    
    return ack_msg;
}
