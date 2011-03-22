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

/* These have to match the values in the header of the partition */
static char		sbd_magic[8] = "SBD_SBD_";
static char		sbd_version  = 0x02;

/* Tunable defaults: */
unsigned long	timeout_watchdog 	= 5;
unsigned long	timeout_watchdog_warn 	= 3;
int		timeout_allocate 	= 2;
int		timeout_loop	    	= 1;
int		timeout_msgwait		= 10;

int	watchdog_use		= 0;
int	go_daemon		= 0;
int	skip_rt			= 0;
int	debug			= 0;
const char *watchdogdev		= "/dev/watchdog";
char *	local_uname;

/* Global, non-tunable variables: */
int	sector_size		= 0;
int	watchdogfd 		= -1;

/*const char	*devname;*/
const char	*cmdname;

void
usage(void)
{
	fprintf(stderr,
"Shared storage fencing tool.\n"
"Syntax:\n"
"	%s <options> <command> <cmdarguments>\n"
"Options:\n"
"-d <devname>	Block device to use (mandatory)\n"
"-h		Display this help.\n"
"-n <node>	Set local node name; defaults to uname -n (optional)\n"
"\n"
"-R		Do NOT enable realtime priority (debugging only)\n"
"-W		Use watchdog (recommended) (watch only)\n"
"-w <dev>	Specify watchdog device (optional) (watch only)\n"
"-D		Run as background daemon (optional) (watch only)\n"
"-v		Enable some verbose debug logging (optional)\n"
"\n"
"-1 <N>		Set watchdog timeout to N seconds (optional) (create only)\n"
"-2 <N>		Set slot allocation timeout to N seconds (optional) (create only)\n"
"-3 <N>		Set daemon loop timeout to N seconds (optional) (create only)\n"
"-4 <N>		Set msgwait timeout to N seconds (optional) (create only)\n"
"-5 <N>		Warn if loop latency exceeds threshold (optional) (watch only)\n"
"			(default is 3, set to 0 to disable)\n"
"Commands:\n"
"create		initialize N slots on <dev> - OVERWRITES DEVICE!\n"
"list		List all allocated slots on device, and messages.\n"
"dump		Dump meta-data header from device.\n"
"watch		Loop forever, monitoring own slot\n"
"allocate <node>\n"
"		Allocate a slot for node (optional)\n"
"message <node> (test|reset|off|clear|exit)\n"
"		Writes the specified message to node's slot.\n"
, cmdname);
}

int
watchdog_init_interval(void)
{
	int     timeout = timeout_watchdog;

	if (watchdogfd < 0) {
		return 0;
	}

	if (ioctl(watchdogfd, WDIOC_SETTIMEOUT, &timeout) < 0) {
		cl_perror( "WDIOC_SETTIMEOUT"
				": Failed to set watchdog timer to %u seconds.",
				timeout);
		return -1;
	} else {
		cl_log(LOG_INFO, "Set watchdog timeout to %u seconds.",
				timeout);
	}
	return 0;
}

int
watchdog_tickle(void)
{
	if (watchdogfd >= 0) {
		if (write(watchdogfd, "", 1) != 1) {
			cl_perror("Watchdog write failure: %s!",
					watchdogdev);
			return -1;
		}
	}
	return 0;
}

int
watchdog_init(void)
{
	if (watchdogfd < 0 && watchdogdev != NULL) {
		watchdogfd = open(watchdogdev, O_WRONLY);
		if (watchdogfd >= 0) {
			cl_log(LOG_NOTICE, "Using watchdog device: %s",
					watchdogdev);
			if ((watchdog_init_interval() < 0)
					|| (watchdog_tickle() < 0)) {
				return -1;
			}
		}else{
			cl_perror("Cannot open watchdog device: %s",
					watchdogdev);
			return -1;
		}
	}
	return 0;
}

void
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

/* This duplicates some code from linux/ioprio.h since these are not included
 * even in linux-kernel-headers. Sucks. See also
 * /usr/src/linux/Documentation/block/ioprio.txt and ioprio_set(2) */
extern int sys_ioprio_set(int, int, int);
int ioprio_set(int which, int who, int ioprio);
inline int ioprio_set(int which, int who, int ioprio)
{
        return syscall(__NR_ioprio_set, which, who, ioprio);
}

enum {
        IOPRIO_CLASS_NONE,
        IOPRIO_CLASS_RT,
        IOPRIO_CLASS_BE,
        IOPRIO_CLASS_IDLE,
};

enum {
        IOPRIO_WHO_PROCESS = 1,
        IOPRIO_WHO_PGRP,
        IOPRIO_WHO_USER,
};

#define IOPRIO_BITS             (16)
#define IOPRIO_CLASS_SHIFT      (13)
#define IOPRIO_PRIO_MASK        ((1UL << IOPRIO_CLASS_SHIFT) - 1)

#define IOPRIO_PRIO_CLASS(mask) ((mask) >> IOPRIO_CLASS_SHIFT)
#define IOPRIO_PRIO_DATA(mask)  ((mask) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(class, data)  (((class) << IOPRIO_CLASS_SHIFT) | data)

void
maximize_priority(void)
{
	if (skip_rt) {
		cl_log(LOG_INFO, "Not elevating to realtime (-R specified).");
		return;
	}

	cl_make_realtime(-1, -1, 256, 256);

	if (ioprio_set(IOPRIO_WHO_PROCESS, getpid(),
			IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 1)) != 0) {
		cl_perror("ioprio_set() call failed.");
	}
}

int
open_device(const char* devname)
{
	int devfd;
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
	return devfd;
}

signed char
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

const char*
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

int
sector_write(int devfd, int sector, const void *data)
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

int
sector_read(int devfd, int sector, void *data)
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

int
slot_read(int devfd, int slot, struct sector_node_s *s_node)
{
	return sector_read(devfd, SLOT_TO_SECTOR(slot), s_node);
}

int
slot_write(int devfd, int slot, const struct sector_node_s *s_node)
{
	return sector_write(devfd, SLOT_TO_SECTOR(slot), s_node);
}

int
mbox_write(int devfd, int mbox, const struct sector_mbox_s *s_mbox)
{
	return sector_write(devfd, MBOX_TO_SECTOR(mbox), s_mbox);
}

int
mbox_read(int devfd, int mbox, struct sector_mbox_s *s_mbox)
{
	return sector_read(devfd, MBOX_TO_SECTOR(mbox), s_mbox);
}

int
mbox_write_verify(int devfd, int mbox, const struct sector_mbox_s *s_mbox)
{
	void *data;
	int rc = 0;

	if (sector_write(devfd, MBOX_TO_SECTOR(mbox), s_mbox) < 0)
		return -1;

	data = sector_alloc();
	if (sector_read(devfd, MBOX_TO_SECTOR(mbox), data) < 0) {
		rc = -1;
		goto out;
	}


	if (memcmp(s_mbox, data, sector_size) != 0) {
		cl_log(LOG_ERR, "Write verification failed!");
		rc = -1;
		goto out;
	}
	rc = 0;
out:
	free(data);
	return rc;
}

int header_write(int devfd, struct sector_header_s *s_header)
{
	s_header->sector_size = htonl(s_header->sector_size);
	s_header->timeout_watchdog = htonl(s_header->timeout_watchdog);
	s_header->timeout_allocate = htonl(s_header->timeout_allocate);
	s_header->timeout_loop = htonl(s_header->timeout_loop);
	s_header->timeout_msgwait = htonl(s_header->timeout_msgwait);
	return sector_write(devfd, 0, s_header);
}

int
header_read(int devfd, struct sector_header_s *s_header)
{
	if (sector_read(devfd, 0, s_header) < 0)
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

int
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

struct sector_header_s *
header_get(int devfd)
{
	struct sector_header_s *s_header;
	s_header = sector_alloc();

	if (header_read(devfd, s_header) < 0) {
		cl_log(LOG_ERR, "Unable to read header from device %d", devfd);
		return NULL;
	}

	if (valid_header(s_header) < 0) {
		cl_log(LOG_ERR, "header on device %d is not valid.", devfd);
		return NULL;
	}

	/* cl_log(LOG_INFO, "Found version %d header with %d slots",
			s_header->version, s_header->slots); */

	return s_header;
}

int
init_device(int devfd)
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

	cl_log(LOG_INFO, "Creating version %d header on device %d",
			s_header->version,
			devfd);
	if (header_write(devfd, s_header) < 0) {
		rc = -1; goto out;
	}
	cl_log(LOG_INFO, "Initializing %d slots on device %d",
			s_header->slots,
			devfd);
	for (i=0;i < s_header->slots;i++) {
		if (slot_write(devfd, i, s_node) < 0) {
			rc = -1; goto out;
		}
		if (mbox_write(devfd, i, s_mbox) < 0) {
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
int
slot_lookup(int devfd, const struct sector_header_s *s_header, const char *name)
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
		if (slot_read(devfd, i, s_node) < 0) {
			rc = -1; goto out;
		}
		if (s_node->in_use != 0) {
			if (strncasecmp(s_node->name, name,
						sizeof(s_node->name)) == 0) {
				cl_log(LOG_INFO, "%s owns slot %d", name, i);
				rc = i; goto out;
			}
		}
	}

out:	free(s_node);
	return rc;
}

int
slot_unused(int devfd, const struct sector_header_s *s_header)
{
	struct sector_node_s	*s_node;
	int 			i;
	int			rc = -1;

	s_node = sector_alloc();

	for (i=0; i < s_header->slots; i++) {
		if (slot_read(devfd, i, s_node) < 0) {
			rc = -1; goto out;
		}
		if (s_node->in_use == 0) {
			rc = i; goto out;
		}
	}

out:	free(s_node);
	return rc;
}


int
slot_allocate(int devfd, const char *name)
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

	s_header = header_get(devfd);
	if (!s_header) {
		rc = -1; goto out;
	}

	s_node = sector_alloc();
	s_mbox = sector_alloc();

	while (1) {
		i = slot_lookup(devfd, s_header, name);
		if (i >= 0) {
			rc = i; goto out;
		}

		i = slot_unused(devfd, s_header);
		if (i >= 0) {
			cl_log(LOG_INFO, "slot %d is unused - trying to own", i);
			memset(s_node, 0, sizeof(*s_node));
			s_node->in_use = 1;
			strncpy(s_node->name, name, sizeof(s_node->name));
			if (slot_write(devfd, i, s_node) < 0) {
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

int
slot_list(int devfd)
{
	struct sector_header_s	*s_header = NULL;
	struct sector_node_s	*s_node = NULL;
	struct sector_mbox_s	*s_mbox = NULL;
	int 			i;
	int			rc = 0;

	s_header = header_get(devfd);
	if (!s_header) {
		rc = -1; goto out;
	}

	s_node = sector_alloc();
	s_mbox = sector_alloc();

	for (i=0; i < s_header->slots; i++) {
		if (slot_read(devfd, i, s_node) < 0) {
			rc = -1; goto out;
		}
		if (s_node->in_use > 0) {
			if (mbox_read(devfd, i, s_mbox) < 0) {
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

int
slot_msg(int devfd, const char *name, const char *cmd)
{
	struct sector_header_s	*s_header = NULL;
	struct sector_mbox_s	*s_mbox = NULL;
	int			mbox;
	int			rc = 0;

	if (!name || !cmd) {
		cl_log(LOG_ERR, "slot_msg(): No recipient / cmd specified.\n");
		rc = -1; goto out;
	}

	s_header = header_get(devfd);
	if (!s_header) {
		rc = -1; goto out;
	}

	if (strcmp(name, "LOCAL") == 0) {
		name = local_uname;
	}

	mbox = slot_lookup(devfd, s_header, name);
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
	if (mbox_write_verify(devfd, mbox, s_mbox) < -1) {
		rc = -1; goto out;
	}
	if (strcasecmp(cmd, "exit") != 0) {
		sleep(timeout_msgwait);
	}
	cl_log(LOG_INFO, "%s successfully delivered to %s",
			cmd, name);

out:	free(s_mbox);
	free(s_header);
	return rc;
}

int
slot_ping(int devfd, const char *name)
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

	s_header = header_get(devfd);
	if (!s_header) {
		rc = -1; goto out;
	}

	if (strcmp(name, "LOCAL") == 0) {
		name = local_uname;
	}

	mbox = slot_lookup(devfd, s_header, name);
	if (mbox < 0) {
		cl_log(LOG_ERR, "slot_msg(): No slot found for %s.", name);
		rc = -1; goto out;
	}

	s_mbox = sector_alloc();
	s_mbox->cmd = SBD_MSG_TEST;

	strncpy(s_mbox->from, local_uname, sizeof(s_mbox->from)-1);

	cl_log(LOG_DEBUG, "Pinging node %s", name);
	if (mbox_write(devfd, mbox, s_mbox) < -1) {
		rc = -1; goto out;
	}

	rc = -1;
	while (waited <= timeout_msgwait) {
		if (mbox_read(devfd, mbox, s_mbox) < 0)
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

void
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

void
do_reset(void)
{
	sysrq_trigger('b');
	cl_reboot(5, "sbd is self-fencing (reset)");
	sleep(timeout_watchdog * 2);
	exit(1);
}

void
do_off(void)
{
	sysrq_trigger('o');
	cl_reboot(5, "sbd is self-fencing (power-off)");
	sleep(timeout_watchdog * 2);
	exit(1);
}

void
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

	/* This is the child; ensure privileges have not been lost. */
	maximize_priority();

	umask(022);
	close(0);
	(void)open(devnull, O_RDONLY);
	close(1);
	(void)open(devnull, O_WRONLY);
	close(2);
	(void)open(devnull, O_WRONLY);
	cl_cdtocoredir();
}

int
header_dump(int devfd)
{
	struct sector_header_s *s_header;
	s_header = header_get(devfd);
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

void
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

