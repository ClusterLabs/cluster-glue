/* $Id: loggingdaemon.h,v 1.8 2005/07/28 08:20:05 sunjd Exp $ */
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
