/* $Id: loggingdaemon.h,v 1.2 2004/02/17 22:11:58 lars Exp $ */
/* Messages sent to the logging daemon */
#define	LD_LOGIT	2
struct LogDaemonMsg_s {
	int		msgtype;
	int		facility;
	int		priority;
	int		msglen;
	char		message[1]; /* Actually much bigger ;-) */
};
typedef	struct LogDaemonMsg_s	LogDaemonMsg;
