#ifndef _CLPLUMBING_APPHB_CS_H
#define _CLPLUMBING_APPHB_CS_H

/* Internal client-server messages for APP heartbeat service */

#define APPHBSOCKPATH		"/var/lib/heartbeat/apphb.comm"

#define APPHB_TLEN	8
#define APPHB_OLEN	256

#define	REGISTER	"reg"
#define	UNREGISTER	"unreg"
#define	HEARTBEAT	"hb"
#define	SETINTERVAL	"setint"

/*
 * These messages are really primitive.
 * They don't have any form of version control, they're in host byte order,
 * and they're all in binary...
 *
 * Fortunately, this is a very simple local service ;-)
 */

/* Generic (no parameter) App heartbeat message */
struct apphb_msg {
	char msgtype [APPHB_TLEN];
};

/* App heartbeat Registration message */
struct apphb_signupmsg {
	char msgtype [APPHB_TLEN];
	char appname [APPHB_OLEN];
	pid_t	pid;
};

/* App heartbeat setinterval message */
struct apphb_msmsg {
	char	msgtype [APPHB_TLEN];
	int	ms;
};

/* App heartbeat server return code (errno) */
struct apphb_rc {
	int	rc;
};
#endif
