/*
 * ha_logger.c utility to log a message to the logging daemon
 *
 * Copyright (C) 2004 Guochun Shi <gshi@ncsa.uiuc.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
#include <lha_internal.h>
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/ipc.h>
#include <clplumbing/GSource.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <clplumbing/loggingdaemon.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>

#define EXIT_OK		0
#define EXIT_FAIL	1

int LogToDaemon(int priority, const char * buf, int bstrlen, gboolean use_pri_str);
void            cl_log(int priority, const char * fmt, ...) G_GNUC_PRINTF(2,3);
static void
usage(void)
{
	printf("usage: "
	       "ha_logger [-t tag] [-D <ha-log/ha-debug>] [message]\n");
	return;
}
#define BUFSIZE 1024
int
main(int argc, char** argv)
{
	int	priority; 
	char*	entity = NULL;
	int	c;
	char	buf[BUFSIZE];
	const char* logtype = "ha-log";

	
	while (( c =getopt(argc, argv,"t:D:h")) != -1){
		switch(c){
			
		case 't':
			entity = optarg;
			break;
		case 'D':
			logtype=optarg;
			break;
		case 'h':
			usage();
			exit(1);		
		default:
			usage();
			exit(1);
		}
		
	}

	if(!cl_log_test_logd()){
		fprintf(stderr, "logd is not running");
		return EXIT_FAIL;
	}
	
	argc -=optind;
	argv += optind;
		
	if (entity != NULL){
		cl_log_set_entity(entity);		
	}
	
	if (strcmp(logtype, "ha-log") == 0){
		priority = LOG_INFO;
	} else if (strcmp(logtype, "ha-debug") == 0){
		priority = LOG_DEBUG;
	}else{
		goto err_exit;
	}	
	
	if (argc > 0){
		register char *p;

		for (p = *argv; *argv; argv++, p = *argv) {
			while (strlen(p) > BUFSIZE-1) {
				memcpy(buf, p, BUFSIZE-1);
				*(buf+BUFSIZE-1) = '\0';
				if (LogToDaemon(priority,buf,
						BUFSIZE,FALSE) != HA_OK){
					return EXIT_FAIL;
				}
				p += BUFSIZE-1;
			}
			if (LogToDaemon(priority,p,
					strnlen(p, BUFSIZE),FALSE) != HA_OK){
				return EXIT_FAIL;
			}
		}
		return EXIT_OK;
	}else {
		while (fgets(buf, sizeof(buf), stdin) != NULL) {
			/* glibc is buggy and adds an additional newline,
			   so we have to remove it here until glibc is fixed */
			int len = strlen(buf);
			
			if (len > 0 && buf[len - 1] == '\n')
				buf[len - 1] = '\0';
			
			if (LogToDaemon(priority, buf,strlen(buf), FALSE) == HA_OK){
				continue;
			}else {
				return EXIT_FAIL;
			}
		}
		
		return EXIT_OK;
	}
	
 err_exit:
	usage();
	return(1);

}

