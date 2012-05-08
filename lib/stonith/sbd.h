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

#include <arpa/inet.h>
#include <asm/unistd.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_reboot.h>
#include <clplumbing/coredumps.h>
#include <clplumbing/realtime.h>
#include <clplumbing/setproctitle.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libaio.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/watchdog.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

/* Sector data types */
struct sector_header_s {
	char	magic[8];
	unsigned char	version;
	unsigned char	slots;
	/* Caveat: stored in network byte-order */
	uint32_t	sector_size;
	uint32_t	timeout_watchdog;
	uint32_t	timeout_allocate;
	uint32_t	timeout_loop;
	uint32_t	timeout_msgwait;
};

struct sector_mbox_s {
	signed char	cmd;
	char		from[64];
};

struct sector_node_s {
	/* slots will be created with in_use == 0 */
	char	in_use;
	char 	name[64];
};

struct servants_list_item {
	const char* devname;
	pid_t pid;
	int restarts;
	struct timespec t_last, t_started;
	struct servants_list_item *next;
};

struct sbd_context {
	int	devfd;
	io_context_t	ioctx;
	struct iocb	io;
};

#define SBD_MSG_EMPTY	0x00
#define SBD_MSG_TEST	0x01
#define SBD_MSG_RESET	0x02
#define SBD_MSG_OFF	0x03
#define SBD_MSG_EXIT	0x04
#define SBD_MSG_CRASHDUMP	0x05
			
#define SLOT_TO_SECTOR(slot) (1+slot*2)
#define MBOX_TO_SECTOR(mbox) (2+mbox*2)

void usage(void);
int watchdog_init_interval(void);
int watchdog_tickle(void);
int watchdog_init(void);
void sysrq_init(void);
void watchdog_close(void);
struct sbd_context *open_device(const char* devname);
void close_device(struct sbd_context *st);
signed char cmd2char(const char *cmd);
void * sector_alloc(void);
const char* char2cmd(const char cmd);
int sector_write(struct sbd_context *st, int sector, const void *data);
int sector_read(struct sbd_context *st, int sector, void *data);
int slot_read(struct sbd_context *st, int slot, struct sector_node_s *s_node);
int slot_write(struct sbd_context *st, int slot, const struct sector_node_s *s_node);
int mbox_write(struct sbd_context *st, int mbox, const struct sector_mbox_s *s_mbox);
int mbox_read(struct sbd_context *st, int mbox, struct sector_mbox_s *s_mbox);
int mbox_write_verify(struct sbd_context *st, int mbox, const struct sector_mbox_s *s_mbox);
/* After a call to header_write(), certain data fields will have been
 * converted to on-disk byte-order; the header should not be accessed
 * afterwards anymore! */
int header_write(struct sbd_context *st, struct sector_header_s *s_header);
int header_read(struct sbd_context *st, struct sector_header_s *s_header);
int valid_header(const struct sector_header_s *s_header);
struct sector_header_s * header_get(struct sbd_context *st);
int init_device(struct sbd_context *st);
int slot_lookup(struct sbd_context *st, const struct sector_header_s *s_header, const char *name);
int slot_unused(struct sbd_context *st, const struct sector_header_s *s_header);
int slot_allocate(struct sbd_context *st, const char *name);
int slot_list(struct sbd_context *st);
int slot_ping(struct sbd_context *st, const char *name);
int slot_msg(struct sbd_context *st, const char *name, const char *cmd);
int header_dump(struct sbd_context *st);
void sysrq_trigger(char t);
void do_crashdump(void);
void do_reset(void);
void do_off(void);
pid_t make_daemon(void);
void maximize_priority(void);
void get_uname(void);

/* Tunable defaults: */
extern unsigned long    timeout_watchdog;
extern unsigned long    timeout_watchdog_warn;
extern int      timeout_allocate;
extern int      timeout_loop;
extern int      timeout_msgwait;
extern int      timeout_io;
extern int  watchdog_use;
extern int  watchdog_set_timeout;
extern int  skip_rt;
extern int  debug;
extern int  debug_mode;
extern const char *watchdogdev;
extern char*  local_uname;

/* Global, non-tunable variables: */
extern int  sector_size;
extern int  watchdogfd;
extern const char* cmdname;

typedef int (*functionp_t)(const char* devname, const void* argp);

int assign_servant(const char* devname, functionp_t functionp, const void* argp);
int init_devices(void);
struct slot_msg_arg_t {
	const char* name;
	const char* msg;
};
int slot_msg_wrapper(const char* devname, const void* argp);
int slot_ping_wrapper(const char* devname, const void* argp);
int allocate_slots(const char *name);
int list_slots(void);
int ping_via_slots(const char *name);
int dump_headers(void);

int check_all_dead(void);
void servant_exit(void);
int servant(const char *diskname, const void* argp);
void recruit_servant(const char *devname, pid_t pid);
struct servants_list_item *lookup_servant_by_dev(const char *devname);
struct servants_list_item *lookup_servant_by_pid(pid_t pid);
void servants_kill(void);
void servants_start(void);
void servant_start(struct servants_list_item *s);
void inquisitor_child(void);
int inquisitor(void);
int inquisitor_decouple(void);
int messenger(const char *name, const char *msg);
int check_timeout_inconsistent(void);
void cleanup_servant_by_pid(pid_t pid);
int quorum_write(int good_servants);
int quorum_read(int good_servants);

