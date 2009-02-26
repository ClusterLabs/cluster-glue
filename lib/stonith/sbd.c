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
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
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

/* These have to match the values in the header of the partition */
static char		sbd_magic[8] = "SBD_SBD_";
static char		sbd_version  = 0x02;

/* Tunable defaults: */
static unsigned long	timeout_watchdog 	= 5;
static int		timeout_allocate 	= 2;
static int		timeout_loop	    	= 1;
static int		timeout_msgwait		= 10;

static int	watchdog_use		= 0;
static int	go_daemon		= 0;
const char *	watchdogdev 		= "/dev/watchdog";
static char *	local_uname;

/* Global, non-tunable variables: */
static unsigned long	sector_size	= 0;
static int	watchdogfd 		= -1;
static int	devfd;
static char	*devname;
static char	*cmdname;

void
usage()
{
	fprintf(stderr, 
"Shared storage fencing tool.\n"
"Syntax:\n"
"	%s <options> <command> <cmdarguments>\n"
"Options:\n"
"-d <devname>	Block device to use (mandatory)\n"
"-n <node>	Set local node name; defaults to uname -n (optional)\n"
"\n"
"-W		Use watchdog (recommended) (watch only)\n"
"-w <dev>	Specify watchdog device (optional) (watch only)\n"
"-D		Run as background daemon (optional) (watch only)\n"
"\n"
"-1 <N>		Set watchdog timeout to N seconds (optional) (create only)\n"
"-2 <N>		Set slot allocation timeout to N seconds (optional) (create only)\n"
"-3 <N>		Set daemon loop timeout to N seconds (optional) (create only)\n"
"-4 <N>		Set msgwait timeout to N seconds (optional) (create only)\n"
"Commands:\n"
"create		initialize N slots on <dev> - OVERWRITES DEVICE!\n"
"list		List all allocated slots on device, and messages.\n"
"watch		Loop forever, monitoring own slot\n"
"allocate <node>\n"
"		Allocate a slot for node (optional)\n"
"message <node> (test|reset|off|clear|exit)\n"
"		Writes the specified message to node's slot.\n"
, cmdname);
}

static void
watchdog_init_interval(void)
{
	if (watchdogfd < 0) {
		return;
	}

	if (ioctl(watchdogfd, WDIOC_SETTIMEOUT, &timeout_watchdog) < 0) {
		cl_perror( "WDIOC_SETTIMEOUT"
		": Failed to set watchdog timer to %lu seconds.",
		timeout_watchdog);
	}
	cl_log(LOG_INFO, "Set watchdog timeout to %lu seconds.",
		timeout_watchdog);
}

static void
watchdog_tickle(void)
{
	if (watchdogfd >= 0) {
		if (write(watchdogfd, "", 1) != 1) {
			cl_perror("Watchdog write failure: %s!",
					watchdogdev);
			/* TODO: Should we force the crash, or wait for
			 * the watchdog to time us out? */
		}
	}
}

static void
watchdog_init(void)
{
	if (watchdogfd < 0 && watchdogdev != NULL) {
		watchdogfd = open(watchdogdev, O_WRONLY);
		if (watchdogfd >= 0) {
			if (fcntl(watchdogfd, F_SETFD, FD_CLOEXEC)) {
				cl_perror("Error setting the "
				"close-on-exec flag for watchdog");
			}
			cl_log(LOG_NOTICE, "Using watchdog device: %s",
					watchdogdev);
			watchdog_init_interval();
			watchdog_tickle();
		}else{
			cl_perror("Cannot open watchdog device: %s",
					watchdogdev);
		}
	}
}

static void
watchdog_close(void)
{
	if (watchdogfd >= 0) {
		if (write(watchdogfd, "V", 1) != 1) {
			cl_perror(
			"Watchdog write magic character failure: closing %s!",
				watchdogdev);
		}
		if (close(watchdogfd) < 0) {
			cl_perror("Watchdog close(2) failed.");
		}
		watchdogfd = -1;
	}
}

static int
open_device(const char* devname)
{
	if (!devname)
		return -1;

	devfd = open(devname, O_SYNC|O_RDWR|O_DIRECT);

	if (devfd == -1) {
		cl_perror("Opening device %s failed.", devname);
		return -1;
	}

	ioctl(devfd, BLKSSZGET, &sector_size);

	if (sector_size == 0) {
		cl_perror("Get sector size failed.\n");
		return -1;
	}
	return 0;
}

static signed char
cmd2char(const char *cmd)
{
	if (strcmp("clear", cmd) == 0) {
		return SBD_MSG_EMPTY;
	} else if (strcmp("test", cmd) == 0) {
		return SBD_MSG_TEST;
	} else if (strcmp("reset", cmd) == 0) {
		return SBD_MSG_RESET;
	} else if (strcmp("off", cmd) == 0) {
		return SBD_MSG_OFF;
	} else if (strcmp("exit", cmd) == 0) {
		return SBD_MSG_EXIT;
	}
	return -1;
}

void *
sector_alloc(void)
{
	void *x;

	x = valloc(sector_size);
	if (!x) {
		exit(1);
	}
	memset(x, 0, sector_size);
	
	return x;
}

static const char*
char2cmd(const char cmd)
{
	switch (cmd) {
		case SBD_MSG_EMPTY:
			return "clear";
			break;
		case SBD_MSG_TEST:
			return "test";
			break;
		case SBD_MSG_RESET:
			return "reset";
			break;
		case SBD_MSG_OFF:
			return "off";
			break;
		case SBD_MSG_EXIT:
			return "exit";
			break;
		default:
			return "undefined";
			break;
	}
}

static int
sector_write(int sector, const void *data)
{
	if (lseek(devfd, sector_size*sector, 0) < 0) {
		cl_perror("sector_write: lseek() failed");
		return -1;
	}

	if (write(devfd, data, sector_size) <= 0) {
		cl_perror("sector_write: write_sector() failed");
		return -1;
	}
	return(0);
}

static int
sector_read(int sector, void *data)
{
	if (lseek(devfd, sector_size*sector, 0) < 0) {
		cl_perror("sector_read: lseek() failed");
		return -1;
	}

	if (read(devfd, data, sector_size) < sector_size) {
		cl_perror("sector_read: read() failed");
		return -1;
	}
	return(0);
}

static int
slot_read(int slot, struct sector_node_s *s_node)
{
	return sector_read(SLOT_TO_SECTOR(slot), s_node);
}

static int
slot_write(int slot, const struct sector_node_s *s_node)
{
	return sector_write(SLOT_TO_SECTOR(slot), s_node);
}

static int
mbox_write(int mbox, const struct sector_mbox_s *s_mbox)
{
	return sector_write(MBOX_TO_SECTOR(mbox), s_mbox);
}

static int
mbox_read(int mbox, struct sector_mbox_s *s_mbox)
{
	return sector_read(MBOX_TO_SECTOR(mbox), s_mbox);
}

static int
mbox_write_verify(int mbox, const struct sector_mbox_s *s_mbox)
{
	void *data;

	if (sector_write(MBOX_TO_SECTOR(mbox), s_mbox) < 0)
		return -1;

	data = sector_alloc();
	if (sector_read(MBOX_TO_SECTOR(mbox), data) < 0)
		return -1;

	if (memcmp(s_mbox, data, sector_size) != 0) {
		cl_log(LOG_ERR, "Write verification failed!");
		return -1;
	}

	return 0;
}

static int
header_write(struct sector_header_s *s_header)
{
	s_header->sector_size = htonl(s_header->sector_size);
	s_header->timeout_watchdog = htonl(s_header->timeout_watchdog);
	s_header->timeout_allocate = htonl(s_header->timeout_allocate);
	s_header->timeout_loop = htonl(s_header->timeout_loop);
	s_header->timeout_msgwait = htonl(s_header->timeout_msgwait);
	return sector_write(0, s_header);
}

static int
header_read(struct sector_header_s *s_header)
{
	if (sector_read(0, s_header) < 0)
		return -1;
	
	s_header->sector_size = ntohl(s_header->sector_size);
	s_header->timeout_watchdog = ntohl(s_header->timeout_watchdog);
	s_header->timeout_allocate = ntohl(s_header->timeout_allocate);
	s_header->timeout_loop = ntohl(s_header->timeout_loop);
	s_header->timeout_msgwait = ntohl(s_header->timeout_msgwait);
	/* This sets the global defaults: */
	timeout_watchdog = s_header->timeout_watchdog;
	timeout_allocate = s_header->timeout_allocate;
	timeout_loop     = s_header->timeout_loop;
	timeout_msgwait  = s_header->timeout_msgwait;

	return 0;
}

static int
valid_header(const struct sector_header_s *s_header)
{
	if (memcmp(s_header->magic, sbd_magic, sizeof(s_header->magic)) != 0) {
		cl_log(LOG_ERR, "Header magic does not match.");
		return -1;
	}
	if (s_header->version != sbd_version) {
		cl_log(LOG_ERR, "Header version does not match.");
		return -1;
	}
	if (s_header->sector_size != sector_size) {
		cl_log(LOG_ERR, "Header sector size does not match.");
		return -1;
	}
	return 0;
}

static struct sector_header_s *
header_get(void)
{
	struct sector_header_s *s_header;
	s_header = sector_alloc();
	
	if (header_read(s_header) < 0) {
		cl_log(LOG_ERR, "Unable to read header from %s", devname);
		return NULL;
	}

	if (valid_header(s_header) < 0) {
		cl_log(LOG_ERR, "%s is not valid.", devname);
		return NULL;
	}
	
	/* cl_log(LOG_INFO, "Found version %d header with %d slots",
			s_header->version, s_header->slots); */

	return s_header;
}

static int
init_device(void)
{
	struct sector_header_s	*s_header;
	struct sector_node_s	*s_node;
	struct sector_mbox_s	*s_mbox;
	struct stat 		s;
	int			i;	
	int			rc = 0;

	s_header = sector_alloc();
	s_node = sector_alloc();
	s_mbox = sector_alloc();
	memcpy(s_header->magic, sbd_magic, sizeof(s_header->magic));
	s_header->version = sbd_version;
	s_header->slots = 255;
	s_header->sector_size = sector_size;
	s_header->timeout_watchdog = timeout_watchdog;
	s_header->timeout_allocate = timeout_allocate;
	s_header->timeout_loop = timeout_loop;
	s_header->timeout_msgwait = timeout_msgwait;

	fstat(devfd, &s);
	/* printf("st_size = %ld, st_blksize = %ld, st_blocks = %ld\n",
			s.st_size, s.st_blksize, s.st_blocks); */
	
	cl_log(LOG_INFO, "Creating version %d header on %s",
			s_header->version,
			devname);
	if (header_write(s_header) < 0) {
		rc = -1; goto out;
	}
	cl_log(LOG_INFO, "Initializing %d slots on %s",
			s_header->slots,
			devname);
	for (i=0;i < s_header->slots;i++) {
		if (slot_write(i, s_node) < 0) {
			rc = -1; goto out;
		}
		if (mbox_write(i, s_mbox) < 0) {
			rc = -1; goto out;
		}
	}

out:	free(s_node);
	free(s_header);
	free(s_mbox);
	return(rc);
}

/* Check if there already is a slot allocated to said name; returns the
 * slot number. If not found, returns -1.
 * This is necessary because slots might not be continuous. */
static int
slot_lookup(const struct sector_header_s *s_header, const char *name)
{
	struct sector_node_s	*s_node = NULL;
	int 			i;
	int			rc = -1;

	if (!name) {
		cl_log(LOG_ERR, "slot_lookup(): No name specified.\n");
		goto out;
	}

	s_node = sector_alloc();

	for (i=0; i < s_header->slots; i++) {
		if (slot_read(i, s_node) < 0) {
			rc = -1; goto out;
		}
		if (s_node->in_use != 0) {
			if (strncmp(s_node->name, name, sizeof(s_node->name)) == 0) {
				cl_log(LOG_INFO, "%s owns slot %d", name, i);
				rc = i; goto out;
			}
		}
	}

out:	free(s_node);
	return rc;
}

static int
slot_unused(const struct sector_header_s *s_header)
{
	struct sector_node_s	*s_node;
	int 			i;
	int			rc = -1;

	s_node = sector_alloc();

	for (i=0; i < s_header->slots; i++) {
		if (slot_read(i, s_node) < 0) {
			rc = -1; goto out;
		}
		if (s_node->in_use == 0) {
			rc = i; goto out;
		}
	}

out:	free(s_node);
	return rc;
}


static int
slot_allocate(const char *name)
{
	struct sector_header_s	*s_header = NULL;
	struct sector_node_s	*s_node = NULL;
	struct sector_mbox_s	*s_mbox = NULL;
	int			i;	
	int			rc = 0;
	
	if (!name) {
		cl_log(LOG_ERR, "slot_allocate(): No name specified.\n");
		rc = -1; goto out;
	}

	s_header = header_get();
	if (!s_header) {
		rc = -1; goto out;
	}

	s_node = sector_alloc();
	s_mbox = sector_alloc();

	while (1) {
		i = slot_lookup(s_header, name);
		if (i >= 0) {
			rc = i; goto out;
		}

		i = slot_unused(s_header);
		if (i >= 0) {
			cl_log(LOG_INFO, "slot %d is unused - trying to own", i);
			memset(s_node, 0, sizeof(*s_node));
			s_node->in_use = 1;
			strncpy(s_node->name, name, sizeof(s_node->name));
			if (slot_write(i, s_node) < 0) {
				rc = -1; goto out;
			}
			sleep(timeout_allocate);
		} else {
			cl_log(LOG_ERR, "No more free slots.");
			rc = -1; goto out;
		}
	}
	
out:	free(s_node);
	free(s_header);
	free(s_mbox);
	return(rc);
}

static int
slot_list(void)
{
	struct sector_header_s	*s_header = NULL;
	struct sector_node_s	*s_node = NULL;
	struct sector_mbox_s	*s_mbox = NULL;
	int 			i;
	int			rc = 0;

	s_header = header_get();
	if (!s_header) {
		rc = -1; goto out;
	}

	s_node = sector_alloc();
	s_mbox = sector_alloc();

	for (i=0; i < s_header->slots; i++) {
		if (slot_read(i, s_node) < 0) {
			rc = -1; goto out;
		}
		if (s_node->in_use > 0) {
			if (mbox_read(i, s_mbox) < 0) {
				rc = -1; goto out;
			}
			printf("%d\t%s\t%s\t%s\n",
				i, s_node->name, char2cmd(s_mbox->cmd),
				s_mbox->from);
		}
	}

out:	free(s_node);
	free(s_header);
	free(s_mbox);
	return rc;
}

static int
slot_msg(const char *name, const char *cmd)
{
	struct sector_header_s	*s_header = NULL;
	struct sector_mbox_s	*s_mbox = NULL;
	int			mbox;
	int			rc = 0;

	if (!name || !cmd) {
		cl_log(LOG_ERR, "slot_msg(): No recipient / cmd specified.\n");
		rc = -1; goto out;
	}

	s_header = header_get();
	if (!s_header) {
		rc = -1; goto out;
	}

	if (strcmp(name, "LOCAL") == 0) {
		name = local_uname;
	}

	mbox = slot_lookup(s_header, name);
	if (mbox < 0) {
		cl_log(LOG_ERR, "slot_msg(): No slot found for %s.", name);
		rc = -1; goto out;
	}

	s_mbox = sector_alloc();
	
	s_mbox->cmd = cmd2char(cmd);
	if (s_mbox->cmd < 0) {
		cl_log(LOG_ERR, "slot_msg(): Invalid command %s.", cmd);
		rc = -1; goto out;
	}

	strncpy(s_mbox->from, local_uname, sizeof(s_mbox->from)-1);

	cl_log(LOG_INFO, "Writing %s to node slot %s",
			cmd, name);
	if (mbox_write_verify(mbox, s_mbox) < -1) {
		rc = -1; goto out;
	}
	sleep(timeout_msgwait);
	cl_log(LOG_INFO, "%s successfully delivered to %s",
			cmd, name);

out:	free(s_mbox);
	free(s_header);
	return rc;
}

static int
slot_ping(const char *name)
{
	struct sector_header_s	*s_header = NULL;
	struct sector_mbox_s	*s_mbox = NULL;
	int			mbox;
	int			waited = 0;
	int			rc = 0;

	if (!name) {
		cl_log(LOG_ERR, "slot_ping(): No recipient specified.\n");
		rc = -1; goto out;
	}

	s_header = header_get();
	if (!s_header) {
		rc = -1; goto out;
	}

	if (strcmp(name, "LOCAL") == 0) {
		name = local_uname;
	}

	mbox = slot_lookup(s_header, name);
	if (mbox < 0) {
		cl_log(LOG_ERR, "slot_msg(): No slot found for %s.", name);
		rc = 1; goto out;
	}

	s_mbox = sector_alloc();
	s_mbox->cmd = SBD_MSG_TEST;

	strncpy(s_mbox->from, local_uname, sizeof(s_mbox->from)-1);

	cl_log(LOG_DEBUG, "Pinging node %s", name);
	if (mbox_write(mbox, s_mbox) < -1) {
		rc = 1; goto out;
	}

	rc = 1;
	while (waited <= timeout_msgwait) {
		if (mbox_read(mbox, s_mbox) < 0)
			break;
		if (s_mbox->cmd != SBD_MSG_TEST) {
			rc = 0;
			break;
		}
		sleep(1);
		waited++;
	}

	if (rc == 0) {
		cl_log(LOG_DEBUG, "%s successfully pinged.", name);
	} else {
		cl_log(LOG_ERR, "%s failed to ping.", name);
	}

out:	free(s_mbox);
	free(s_header);
	return rc;
}

static void
sysrq_trigger(char t)
{
	FILE *procf;

	procf = fopen("/proc/sysrq-trigger", "a");
	if (!procf) {
		cl_perror("Opening sysrq-trigger failed.");
		return;
	}
	cl_log(LOG_INFO, "sysrq-trigger: %c\n", t);
	fprintf(procf, "%c\n", t);
	fclose(procf);
	return;
}

static void
do_reset(void)
{
	sysrq_trigger('b');
	cl_reboot(5, "sbd is self-fencing (reset)");
	sleep(timeout_watchdog * 2);
	exit(1);
}

static void
do_off(void)
{
	sysrq_trigger('o');
	cl_reboot(5, "sbd is self-fencing (power-off)");
	sleep(timeout_watchdog * 2);
	exit(1);
}

static void
make_daemon(void)
{
	long			pid;
	const char *		devnull = "/dev/null";

	if (go_daemon > 0) {
		pid = fork();
		if (pid < 0) {
			cl_log(LOG_ERR, "%s: could not start daemon\n",
					cmdname);
			cl_perror("fork");
			exit(1);
		}else if (pid > 0) {
			exit(0);
		}
	}

	cl_log_enable_stderr(FALSE);

	umask(022);
	close(0);
	(void)open(devnull, O_RDONLY);
	close(1);
	(void)open(devnull, O_WRONLY);
	close(2);
	(void)open(devnull, O_WRONLY);
	cl_cdtocoredir();
	cl_make_realtime(-1, -1, 128, 128);

}


static int
daemonize(void)
{
	struct sector_mbox_s	*s_mbox = NULL;
	int			mbox;
	int			rc = 0;

	mbox = slot_allocate(local_uname);
	if (mbox < 0) {
		cl_log(LOG_ERR, "No slot allocated, and automatic allocation failed.");
		rc = -1; goto out;
	}
	cl_log(LOG_INFO, "Monitoring slot %d", mbox);

	/* Clear mbox once on start */
	s_mbox = sector_alloc();
	if (mbox_write(mbox, s_mbox) < 0) {
		rc = -1; goto out;
	}

	make_daemon();

	if (watchdog_use != 0)
		watchdog_init();
	
	while (1) {
		if (mbox_read(mbox, s_mbox) < 0) {
			cl_log(LOG_ERR, "mbox read failed.");
			do_reset();
		}

		if (s_mbox->cmd > 0) {
			cl_log(LOG_INFO, "Received command %s from %s",
					char2cmd(s_mbox->cmd), s_mbox->from);

			switch (s_mbox->cmd) {
			case SBD_MSG_TEST:
				memset(s_mbox, 0, sizeof(*s_mbox));
				mbox_write(mbox, s_mbox);
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
		watchdog_tickle();
		sleep(timeout_loop);
	}

out:
	free(s_mbox);
	return rc;
}

static int
header_dump(void)
{
	struct sector_header_s *s_header;
	s_header = header_get();
	if (s_header == NULL)
		return -1;

	printf("Header version     : %u\n", s_header->version);
	printf("Number of slots    : %u\n", s_header->slots);
	printf("Sector size        : %lu\n",
			(unsigned long)s_header->sector_size);
	printf("Timeout (watchdog) : %lu\n",
			(unsigned long)s_header->timeout_watchdog);
	printf("Timeout (allocate) : %lu\n",
			(unsigned long)s_header->timeout_allocate);
	printf("Timeout (loop)     : %lu\n",
			(unsigned long)s_header->timeout_loop);
	printf("Timeout (msgwait)  : %lu\n",
			(unsigned long)s_header->timeout_msgwait);
	return 0;
}

static void
get_uname(void)
{
	struct utsname		uname_buf;
	int i;

	if (uname(&uname_buf) < 0) {
		cl_perror("uname() failed?");
		exit(1);
	}
	
	local_uname = strdup(uname_buf.nodename);

	for (i = 0; i < strlen(local_uname); i++)
		local_uname[i] = tolower(local_uname[i]);
}

int
main(int argc, char** argv)
{
	int		exit_status = 0;
	int		c;

	if ((cmdname = strrchr(argv[0], '/')) == NULL) {
		cmdname = argv[0];
	}else{
		++cmdname;
	}

	cl_log_set_entity(cmdname);
	cl_log_enable_stderr(1);
	cl_log_set_facility(LOG_DAEMON);
	
	get_uname();

	while ((c = getopt (argc, argv, "DWw:d:n:1:2:3:4:")) != -1) {
		switch (c) {
		case 'D':
			go_daemon = 1;
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

	if (open_device(devname) < 0) {
		exit_status = -1;
		goto out;
	}

	if (strcmp(argv[optind],"create") == 0) {
		exit_status = init_device();
	} else if (strcmp(argv[optind],"dump") == 0) {
		exit_status = header_dump();
	} else if (strcmp(argv[optind],"allocate") == 0) {
		exit_status = slot_allocate(argv[optind+1]);
	} else if (strcmp(argv[optind],"list") == 0) {
		exit_status = slot_list();
	} else if (strcmp(argv[optind],"message") == 0) {
		exit_status = slot_msg(argv[optind+1], argv[optind+2]);
	} else if (strcmp(argv[optind],"ping") == 0) {
		exit_status = slot_ping(argv[optind+1]);
	} else if (strcmp(argv[optind],"watch") == 0) {
		exit_status = daemonize();
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
