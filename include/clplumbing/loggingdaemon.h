/* $Id: loggingdaemon.h,v 1.3 2004/11/08 20:48:36 gshi Exp $ */
/* Messages sent to the logging daemon */
#define	LD_LOGIT	2
struct LogDaemonMsg_s {
	int		msgtype;
	int		facility;
	int		priority;
	int		msglen;
	gboolean	use_pri_str;
	char		message[1]; /* Actually much bigger ;-) */
};
typedef	struct LogDaemonMsg_s	LogDaemonMsg;
