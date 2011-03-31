/*
 * Copyright (C) 2008 Lars Marowsky-Bree <lmb@suse.de>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <fcntl.h>
#include <time.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/coredumps.h>
#include <clplumbing/realtime.h>
#include <clplumbing/cl_reboot.h>
#include <malloc.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/watchdog.h>
#include <linux/fs.h>

#include "sbd.h"

static int daemonize(int devfd);
static int daemonize(int devfd)
{
	struct sector_mbox_s	*s_mbox = NULL;
	int			mbox;
	int			rc = 0;
	time_t			t0, t1, latency;

	mbox = slot_allocate(devfd, local_uname);
	if (mbox < 0) {
		cl_log(LOG_ERR, "No slot allocated, and automatic allocation failed.");
		rc = -1; goto out;
	}
	cl_log(LOG_INFO, "Monitoring slot %d", mbox);

	/* Clear mbox once on start */
	s_mbox = sector_alloc();
	if (mbox_write(devfd, mbox, s_mbox) < 0) {
		rc = -1; goto out;
	}

	if (watchdog_use != 0) {
		if (watchdog_init() < 0) {
			rc = -1; goto out;
		}
	}

	make_daemon();

	while (1) {
		t0 = time(NULL);
		sleep(timeout_loop);

		if (mbox_read(devfd, mbox, s_mbox) < 0) {
			cl_log(LOG_ERR, "mbox read failed.");
			do_reset();
		}

		if (s_mbox->cmd > 0) {
			cl_log(LOG_INFO, "Received command %s from %s",
					char2cmd(s_mbox->cmd), s_mbox->from);

			switch (s_mbox->cmd) {
			case SBD_MSG_TEST:
				memset(s_mbox, 0, sizeof(*s_mbox));
				mbox_write(devfd, mbox, s_mbox);
				break;
			case SBD_MSG_RESET:
				do_reset();
				break;
			case SBD_MSG_OFF:
				do_off();
				break;
			case SBD_MSG_EXIT:
				watchdog_close();
				goto out;
				break;
			default:
				/* TODO: Should we do something on
				 * unknown messages? */
				cl_log(LOG_ERR, "Unknown message; suicide!");
				do_reset();
				break;
			}
		}
		if (watchdog_tickle() < 0) {
			cl_log(LOG_ERR, "Tickling the watchdog failed!");
			do_reset();
		}


		t1 = time(NULL);
		latency = t1 - t0;

		if (timeout_watchdog_warn 
				&& (latency > timeout_watchdog_warn)) {
			cl_log(LOG_WARNING, "Latency: %d exceeded threshold %d",
				(int)latency, (int)timeout_watchdog_warn);
		} else if (debug) {
			cl_log(LOG_INFO, "Latency: %d",
				(int)latency);
		}

	}

out:
	free(s_mbox);
	return rc;
}

int
main(int argc, char** argv)
{
	int		exit_status = 0;
	int		c;
	int		devfd;
	const char* devname;

	if ((cmdname = strrchr(argv[0], '/')) == NULL) {
		cmdname = argv[0];
	}else{
		++cmdname;
	}

	cl_log_set_entity(cmdname);
	cl_log_enable_stderr(0);
	cl_log_set_facility(LOG_DAEMON);
	
	get_uname();

	while ((c = getopt (argc, argv, "DRWhvw:d:n:1:2:3:4:5:")) != -1) {
		switch (c) {
		case 'D':
			go_daemon = 1;
			break;
		case 'R':
			skip_rt = 1;
			break;
		case 'v':
			debug = 1;
			break;
		case 'T':
			watchdog_set_timeout = 0;
			break;
		case 'W':
			watchdog_use = 1;
			break;
		case 'w':
			watchdogdev = optarg;
			break;
		case 'd':
			devname = optarg;
			break;
		case 'n':
			local_uname = optarg;
			break;
		case '1':
			timeout_watchdog = atoi(optarg);
			break;
		case '2':
			timeout_allocate = atoi(optarg);
			break;
		case '3':
			timeout_loop = atoi(optarg);
			break;
		case '4':
			timeout_msgwait = atoi(optarg);
			break;
		case '5':
			timeout_watchdog_warn = atoi(optarg);
			break;
		case 'h':
			usage();
			return(0);
		default:
			exit_status = -1;
			goto out;
			break;
		}
	}
	
	/* There must at least be one command following the options: */
	if ( (argc - optind) < 1) {
		fprintf(stderr, "Not enough arguments.\n");
		exit_status = -1;
		goto out;
	}

	maximize_priority();
	if ((devfd = open_device(devname)) < 0) {
		exit_status = -1;
		goto out;
	}

	if (strcmp(argv[optind],"create") == 0) {
		exit_status = init_device(devfd);
	} else if (strcmp(argv[optind],"dump") == 0) {
		exit_status = header_dump(devfd);
	} else if (strcmp(argv[optind],"allocate") == 0) {
		exit_status = slot_allocate(devfd, argv[optind+1]);
	} else if (strcmp(argv[optind],"list") == 0) {
		exit_status = slot_list(devfd);
	} else if (strcmp(argv[optind],"message") == 0) {
		exit_status = slot_msg(devfd, argv[optind+1], argv[optind+2]);
	} else if (strcmp(argv[optind],"ping") == 0) {
		exit_status = slot_ping(devfd, argv[optind+1]);
	} else if (strcmp(argv[optind],"watch") == 0) {
		exit_status = daemonize(devfd);
	} else {
		exit_status = -1;
	}

out:
	if (exit_status < 0) {
		usage();
		return(1);
	}
	return(0);
}
