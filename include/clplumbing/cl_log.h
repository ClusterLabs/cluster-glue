/* $Id: cl_log.h,v 1.13 2005/04/04 21:08:18 gshi Exp $ */
#ifndef _CLPLUMBING_CL_LOG_H
#	define _CLPLUMBING_CL_LOG_H
#	include <glib.h>
#	include <syslog.h>

#define TIME_T  unsigned long
#define	HA_FAIL		0
#define	HA_OK		1
#define MAXMSG		40000
void		cl_direct_log(int priority, const char* buf, gboolean, const char*, int, TIME_T);
void            cl_log(int priority, const char * fmt, ...) G_GNUC_PRINTF(2,3);
void            cl_perror(const char * fmt, ...) G_GNUC_PRINTF(1,2);
void		cl_log_enable_stderr(int truefalse);
int		cl_set_logging_wqueue_maxlen(int);
gboolean	cl_log_test_logd(void);
void		cl_log_set_uselogd(int truefalse);
gboolean	cl_log_get_uselogd(void);
void		cl_log_set_facility(int facility);
void		cl_log_set_entity(const char *	entity);
void		cl_log_set_logfile(const char *	path);
void		cl_log_set_debugfile(const char * path);

char *		ha_timestamp(TIME_T t);
void		cl_glib_msg_handler(const gchar *log_domain
,		GLogLevelFlags log_level, const gchar *message
,		gpointer user_data);
#endif
