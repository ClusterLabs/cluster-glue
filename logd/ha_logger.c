/*
 * ha_logger.c utility to log a message to the logging daemon
 *
 * Copyright (C) 2004 Guochun Shi <gshi@ncsa.uiuc.edu>
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/ipc.h>
#include <clplumbing/GSource.h>
#include <clplumbing/cl_malloc.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <ha_config.h>
#include <clplumbing/loggingdaemon.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#define	HA_FAIL		0
#define	HA_OK		1

int LogToLoggingDaemon(int priority, const char * buf, int bstrlen, gboolean use_pri_str);

static void
usage(int argc, char** argv)
{
	printf("usage: "
	       "%s: <destination> <message>\n\n"
	       "@destination  can be  either ha-log or ha-debug\n"
	       "@message is the message you want to log into file\n\n",
	       argv[0]);	
	return;
}
int
main(int argc, char** argv)
{
	int	priority; 

	if (argc != 3 || argv[1] == NULL || argv[2] == NULL ){
		goto err_exit;
	}
	if (strcmp(argv[1], "ha-log") == 0){
		priority = LOG_INFO;
	} else if (strcmp(argv[1], "ha-debug") == 0){
		priority = LOG_DEBUG;
	}else{
		goto err_exit;
	}
	
	if (LogToLoggingDaemon(priority, argv[2],strlen(argv[2]), FALSE) == HA_OK){
		return 0;
	}else {
		return 1;
	}
	
 err_exit:
	usage(argc, argv);
	return(1);

}

