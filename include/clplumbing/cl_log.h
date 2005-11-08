/* $Id: cl_log.h,v 1.25 2005/11/08 06:27:38 gshi Exp $ */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _CLPLUMBING_CL_LOG_H
#	define _CLPLUMBING_CL_LOG_H
#	include <glib.h>
#	include <syslog.h>

#define TIME_T  unsigned long
#define	HA_FAIL		0
#define	HA_OK		1
#define	MAXLINE		(512*10)

struct IPC_CHANNEL;

#define	ANYDEBUG	(debug_level)
#define	DEBUGDETAILS	(debug_level >= 2)
#define	DEBUGAUTH	(debug_level >=3)
#define	DEBUGMODULE	(debug_level >=3)
#define	DEBUGPKT	(debug_level >= 4)
#define	DEBUGPKTCONT	(debug_level >= 5)

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
gboolean	cl_inherit_use_logd(const char*, int);
void		inherit_compress(void);
void		inherit_logconfig_from_environment(void);
int		cl_log_set_logd_channel_source( void (*create_callback)(struct IPC_CHANNEL* chan),
						GDestroyNotify destroy_callback);
int		cl_log_get_logdtime(void);
void		cl_log_set_logdtime(int logdintval);

char *		ha_timestamp(TIME_T t);
void		cl_glib_msg_handler(const gchar *log_domain
,		GLogLevelFlags log_level, const gchar *message
,		gpointer user_data);


typedef struct CircularBuffer_s 
{
	const char*	name;
	size_t		size;
	gboolean	empty_after_dump;
	GQueue*		queue;
	
} CircularBuffer_t;

typedef struct CircularBufferEntry_s 
{
	int level;
	char *buf;
	
} CircularBufferEntry_t;

CircularBuffer_t *NewCircularBuffer(
	const char *name, unsigned int size, gboolean empty_after_dump);
void LogToCircularBuffer(
	CircularBuffer_t *buffer, int level, const char *fmt, ...) G_GNUC_PRINTF(3,4);

void EmptyCircularBuffer(CircularBuffer_t *buffer);

/* the prototype is designed to be easy to give to G_main_add_SignalHandler() */
gboolean DumpCircularBuffer(int nsig, gpointer buffer);

#endif
