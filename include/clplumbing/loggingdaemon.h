/* $Id: loggingdaemon.h,v 1.4 2004/11/18 02:27:18 gshi Exp $ */
/* Messages sent to the logging daemon */
#define	LD_LOGIT	2
struct LogDaemonMsg_s {
	int		msgtype;
	int		facility;
	int		priority;
	int		msglen;
	gboolean	use_pri_str;
	char		message[0]; /* Actually much bigger ;-) */
};
typedef	struct LogDaemonMsg_s	LogDaemonMsg;
