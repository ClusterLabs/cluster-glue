#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/ipc.h>

typedef int (*TestFunc_t)(IPC_Channel*chan, int count);

static int channelpair(TestFunc_t client, TestFunc_t server, int count);
#if 0
static void clientserverpair(IPC_Channel* channels[2]);
#endif
static int echoserver(IPC_Channel*, int repcount);
static int echoclient(IPC_Channel*, int repcount);

static int checksock(IPC_Channel* channel);
static void checkifblocked(IPC_Channel* channel);

static int
channelpair(TestFunc_t	clientfunc, TestFunc_t serverfunc, int count)
{
	IPC_Channel* channels[2];
	int		rc;

	if (ipc_channel_pair(channels) != IPC_OK) {
		perror("Can't create ipc channel pair");
		exit(1);
	}
	checksock(channels[0]);
	checksock(channels[1]);
	switch (fork()) {
		case -1:
			perror("can't fork");
			exit(1);
			break;

		case 0:		/* Child */
			rc =clientfunc(channels[0], count);
			exit (rc > 127 ? 127 : rc);
			break;

		default:	 /* Server */
			return serverfunc(channels[1], count);
	}
	return -1; /* This can't happen ;-) */
}

#if 0
static void
clientserverpair(IPC_Channel* channels[2])
{
	char			path[] = IPC_PATH_ATTR;
	char			commpath[] = "/tmp/foobar"
	GHashTable *		wattrs;
	IPC_WAIT_CONNECTION*	wconn;

	wattrs = g_hash_table_new(g_str_hash, g_str_equal);

	g_hash_table_insert(wattrs, path, commpath);

	wconn = ipc_wait_conn_constructor(IPC_ANYTYPE, wconnattrs);

	if (wconn == NULL) {
		perror("Can't create wait connection");
		exit(1);
	}

}
#endif
static void
checkifblocked(IPC_Channel* chan)
{
	if (chan->ops->is_sending_blocked(chan)) {
		fprintf(stderr, "Sending is blocked.\n");
		chan->ops->resume_io(chan);
	}
}

int
main(int argc, char ** argv)
{
	int	rc = 0;

	cl_log_enable_stderr(TRUE);


	channelpair(echoclient, echoserver, 10000);

	return rc;
}
static int
checksock(IPC_Channel* channel)
{

	if (channel->ch_status != IPC_CONNECT) {
		fprintf(stderr, "Channel status is %d"
		", not IPC_CONNECT", channel->ch_status);
		return 1;
	}
	return 0;
}

static int
echoserver(IPC_Channel* wchan, int repcount)
{
	char	str[256];
	int	j;
	int	errcount = 0;
	IPC_Message	wmsg;
	IPC_Message*	rmsg;


	wmsg.msg_private = NULL;
	wmsg.msg_done = NULL;
	wmsg.msg_body = str;
	wmsg.msg_ch = wchan;

	fprintf(stderr, "Echo server: %d reps.\n", repcount);
	for (j=1; j <= repcount
	;++j, rmsg != NULL && (rmsg->msg_done(rmsg),1)) {
		int	rc;
		snprintf(str, sizeof(str)-1, "String-%d", j);
		wmsg.msg_len = strlen(str)+1;
		if ((rc = wchan->ops->send(wchan, &wmsg)) != IPC_OK) {
			fprintf(stderr
			,	"echotest: send failed %d rc iter %d\n"
			,	rc, j);
			++errcount;
			continue;
		}

		//fprintf(stderr, "+");
		wchan->ops->waitout(wchan);
		checkifblocked(wchan);
		//fprintf(stderr, "S");

		if ((rc = wchan->ops->waitin(wchan)) != IPC_OK) {
			fprintf(stderr
			,	"echotest server: waitin failed %d rc iter %d"
			" errno=%d\n"
			,	rc, j, errno);
			perror("waitin");
			exit(1);
		}

		//fprintf(stderr, "-");
		if ((rc = wchan->ops->recv(wchan, &rmsg)) != IPC_OK) {
			fprintf(stderr
			,	"echotest server: recv failed %d rc iter %d"
			" errno=%d\n"
			,	rc, j, errno);
			perror("recv");
			++errcount;
			rmsg=NULL;
			continue;
		}
		//fprintf(stderr, "s");
		if (rmsg->msg_len != wmsg.msg_len) {
			fprintf(stderr
			,	"echotest: length mismatch [%zd,%zd] iter %d\n"
			,	rmsg->msg_len, wmsg.msg_len, j);
			++errcount;
			continue;
		}
		if (strncmp(rmsg->msg_body, wmsg.msg_body, wmsg.msg_len)
		!= 0) {
			fprintf(stderr
			,	"echotest: data mismatch. iteration %d\n"
			,	j);
			++errcount;
			continue;
		}
		
	}
	fprintf(stderr, "echoserver: %d errors\n", errcount);
	return errcount;
}
static int
echoclient(IPC_Channel* rchan, int repcount)
{
	int	j;
	int	errcount = 0;
	IPC_Message*	rmsg;



	fprintf(stderr, "Echo client: %d reps.\n", repcount);
	for (j=1; j <= repcount ;++j) {

		int	rc;

		if ((rc = rchan->ops->waitin(rchan)) != IPC_OK) {
			fprintf(stderr
			,	"echotest client: waitin failed %d rc iter %d"
			" errno=%d\n"
			,	rc, j, errno);
			perror("waitin");
			exit(1);
		}
		//fprintf(stderr, "/");

		if ((rc = rchan->ops->recv(rchan, &rmsg)) != IPC_OK) {
			fprintf(stderr
			,	"echoclient: recv failed %d rc iter %d"
			" errno=%d\n"
			,	rc, j, errno);
			perror("recv");
			++errcount;
			rmsg=NULL;
			continue;
		}
		//fprintf(stderr, "c");
		if ((rc = rchan->ops->send(rchan, rmsg)) != IPC_OK) {
			fprintf(stderr
			,	"echoclient: send failed %d rc iter %d\n"
			,	rc, j);
			++errcount;
			continue;
		}
		//fprintf(stderr, "%%");
		rchan->ops->waitout(rchan);
		checkifblocked(rchan);
		//fprintf(stderr, "C");
	}
	fprintf(stderr, "echoclient: %d errors\n", errcount);
	return errcount;
}
