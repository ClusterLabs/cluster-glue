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

#define SBD_MSG_EMPTY	0x00
#define SBD_MSG_TEST	0x01
#define SBD_MSG_RESET	0x02
#define SBD_MSG_OFF	0x03
#define SBD_MSG_EXIT	0x04
			
#define SLOT_TO_SECTOR(slot) (1+slot*2)
#define MBOX_TO_SECTOR(mbox) (2+mbox*2)

void usage(void);
int watchdog_init_interval(void);
int watchdog_tickle(void);
int watchdog_init(void);
void watchdog_close(void);
int open_device(const char* devname);
signed char cmd2char(const char *cmd);
void * sector_alloc(void);
const char* char2cmd(const char cmd);
int sector_write(int sector, const void *data);
int sector_read(int sector, void *data);
int slot_read(int slot, struct sector_node_s *s_node);
int slot_write(int slot, const struct sector_node_s *s_node);
int mbox_write(int mbox, const struct sector_mbox_s *s_mbox);
int mbox_read(int mbox, struct sector_mbox_s *s_mbox);
int mbox_write_verify(int mbox, const struct sector_mbox_s *s_mbox);
/* After a call to header_write(), certain data fields will have been
 * converted to on-disk byte-order; the header should not be accessed
 * afterwards anymore! */
int header_write(struct sector_header_s *s_header);
int header_read(struct sector_header_s *s_header);
int valid_header(const struct sector_header_s *s_header);
struct sector_header_s * header_get(void);
int init_device(void);
int slot_lookup(const struct sector_header_s *s_header, const char *name);
int slot_unused(const struct sector_header_s *s_header);
int slot_allocate(const char *name);
int slot_list(void);
int slot_ping(const char *name);
int slot_msg(const char *name, const char *cmd);
int header_dump(void);
void sysrq_trigger(char t);
void do_reset(void);
void do_off(void);
void make_daemon(void);
void maximize_priority(void);
void get_uname(void);

/* Tunable defaults: */
extern unsigned long    timeout_watchdog;
extern unsigned long    timeout_watchdog_warn;
extern int      timeout_allocate;
extern int      timeout_loop;
extern int      timeout_msgwait;
extern int  watchdog_use;
extern int  go_daemon;
extern int  skip_rt;
extern int  debug;
extern const char *watchdogdev;
extern char*  local_uname;

/* Global, non-tunable variables: */
extern int  sector_size;
extern int  watchdogfd;
extern int  devfd;
extern char *devname;
extern char *cmdname;

