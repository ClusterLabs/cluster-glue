/* $Id: loggingdaemon.h,v 1.7 2005/02/17 23:20:02 gshi Exp $ */
/* Messages sent to the logging daemon */
#define	LD_LOGIT	2
#define MAXENTITY	32
struct LogDaemonMsg_s {
	int		msgtype;
	int		facility;
	int		priority;
	int		msglen;
	gboolean	use_pri_str;
	int		entity_pid;
	char		entity[MAXENTITY];
	TIME_T		timestamp;
	char		message[0]; /* Actually much bigger ;-) */
};
typedef	struct LogDaemonMsg_s	LogDaemonMsg;
