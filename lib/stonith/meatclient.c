/*
 * Stonith client for Human Operator Stonith device
 *
 * Copyright (c) 2001 Gregor Binder <gbinder@sysfive.com>
 *
 *   This program is a rewrite of the "do_meatware" program by
 *   David C. Teigland <teigland@sistina.com> originally appeared
 *   in the GFS stomith meatware agent.
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

#include <lha_internal.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stonith/stonith.h>
#include <glib.h>

#define OPTIONS "c:w"

void usage(const char * cmd);

void
usage(const char * cmd)
{
	fprintf(stderr, "usage: %s -c node [-w]\n", cmd);
	exit(S_INVAL);
}

extern char *	optarg;
extern int	optind, opterr, optopt;
int
main(int argc, char** argv)
{
	char *		cmdname;
	const char *	meatpipe_pr = HA_VARRUNDIR "/meatware";	/* if you intend to
							 change this, modify
							 meatware.c as well */
	char *		opthost = NULL;
	int		clearhost = 0;

	int		c, argcount, waitmode = 0;
	int		errors = 0;

	if ((cmdname = strrchr(argv[0], '/')) == NULL) {
		cmdname = argv[0];
	}else{
		++cmdname;
	}

	while ((c = getopt(argc, argv, OPTIONS)) != -1) {
		switch(c) {
		case 'c':	opthost = optarg;
				++clearhost;
				break;
		case 'w':	++waitmode;
				break;
		default:	++errors;
				break;
		}
	}
	argcount = argc - optind;
	if (!(argcount == 0) || !opthost) {
		errors++;
	}

	if (errors) {
		usage(cmdname);
	}
	
	strdown(opthost);

	if (clearhost) {

		int rc, fd;
		char resp[3];

		char line[256];
		char meatpipe[256];

		gboolean waited=FALSE;

		snprintf(meatpipe, 256, "%s.%s", meatpipe_pr, opthost);

		while(1) {
			fd = open(meatpipe, O_WRONLY | O_NONBLOCK);
			if (fd >= 0)
				break;
			if (!waitmode || (errno != ENOENT && errno != ENXIO)) {
				if (waited) printf("\n");
				snprintf(line, sizeof(line)
				,	"Meatware_IPC failed: %s", meatpipe);
				perror(line);
				exit(S_BADHOST);
			}
			printf("."); fflush(stdout); waited=TRUE;
			sleep(1);
		}
		if (waited) printf("\n");

		printf("\nWARNING!\n\n"
			"If node \"%s\" has not been manually power-cycled or "
			"disconnected from all shared resources and networks, "
			"data on shared disks may become corrupted and "
			"migrated services might not work as expected.\n"
			"Please verify that the name or address above "
			"corresponds to the node you just rebooted.\n\n"
			"PROCEED? [yN] ", opthost);

		rc = scanf("%s", resp);

		if (rc == 0 || rc == EOF || tolower(resp[0] != 'y')) {
			printf("Meatware_client: operation canceled.\n");
			exit(S_INVAL);
		}

		sprintf(line, "meatware reply %s", opthost);

		rc = write(fd, line, 256);

		if (rc < 0) {
			sprintf(line, "Meatware_IPC failed: %s", meatpipe);
			perror(line);
			exit(S_OOPS);
		}
    
		printf("Meatware_client: reset confirmed.\n");
	}

	exit(S_OK);
}
