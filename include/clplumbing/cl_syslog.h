/*
 * Functions to support syslog.
 * 	David Lee (c) 2005
 */

#ifndef _CLPLUMBING_CL_SYSLOG_H
#define _CLPLUMBING_CL_SYSLOG_H

/* Convert string "auth" to equivalent number "LOG_AUTH" etc. */
int cl_syslogfac_str2int(const char *);

/* Convert number "LOG_AUTH" to equivalent string "auth" etc. */
/* Returns static string; caller must NOT free. */
const char *cl_syslogfac_int2str(int);

#endif /* _CLPLUMBING_CL_SYSLOG_H */
