/* $Id: loggingdaemon.h,v 1.5 2005/02/02 08:13:50 gshi Exp $ */
/* Messages sent to the logging daemon */
#define	LD_LOGIT	2
#define MAXENTITY	32
struct LogDaemonMsg_s {
	int		msgtype;
	int		facility;
	int		priority;
	int		msglen;
	gboolean	use_pri_str;
	char		entity[MAXENTITY];
	char		message[0]; /* Actually much bigger ;-) */
};
typedef	struct LogDaemonMsg_s	LogDaemonMsg;
