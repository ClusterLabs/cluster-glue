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

#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
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

struct servants_list_item *servants_leader = NULL;

/* signals reserved for multi-disk sbd */
#define SIG_LIVENESS (SIGRTMIN + 1)	/* report liveness of the disk */
#define SIG_EXITREQ  (SIGRTMIN + 2)	/* exit request to inquisitor */
#define SIG_TEST     (SIGRTMIN + 3)	/* trigger self test */
#define SIG_RESTART  (SIGRTMIN + 4)	/* trigger restart of all failed disk */
/* FIXME: should add dynamic check of SIG_XX >= SIGRTMAX */

/* Helper Macros, to reuse existing functions */
#if 0
#define DBGPRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define DBGPRINT(...) do {} while (0)
#endif

#define CALL_WITH_DEVNAME(func, dvn, params...) \
do { \
    int old_devfd = devfd; \
	const char* old_devname = devname; \
	rc = 0; \
    devname = dvn; \
    rc = open_device(devname); \
    if (rc == -1) break; \
    rc = func ( params ); \
    close(devfd); \
	devfd = old_devfd; devname = old_devname; \
    if (rc == -1) break; \
} while (0)

typedef int (*functionp_t)(const char* devname, const void* argp);

int assign_servant_ex(const char* devname, functionp_t functionp, const void* argp);
int assign_servant_ex(const char* devname, functionp_t functionp, const void* argp)
{
	int pid = 0;
	int rc = 0;
	DBGPRINT("fork servant for %s\n", devname);
	pid = fork();
	if (pid == 0) {		/* child */
		rc = (*functionp)(devname, argp);
		if (rc == -1) exit(1);
		else exit(0);
	} else if (pid != -1) {		/* parent */
		return pid;
	} else {
		DBGPRINT("Failed to fork servant\n");
		exit(1);
	}
}

static int init_devices(void);
static int init_devices()
{
	int rc = 0;
	struct servants_list_item *s = servants_leader;
	while (s != NULL) {
		DBGPRINT("init device %s\n", s->devname);
		CALL_WITH_DEVNAME(init_device, s->devname);
		if (rc == -1)
			return rc;
		s = s->next;
	}
	return 0;
}

struct slot_msg_arg_t {
	const char* name;
	const char* msg;
};
int slot_msg_wrapper(const char* devname, const void* argp);
int slot_msg_wrapper(const char* devname, const void* argp)
{
  int rc = 0;
  const struct slot_msg_arg_t* arg = (const struct slot_msg_arg_t*)argp;
  CALL_WITH_DEVNAME(slot_msg, devname, arg->name, arg->msg);
  return rc;
}

int slot_ping_wrapper(const char* devname, const void* argp);
int slot_ping_wrapper(const char* devname, const void* argp)
{
	int rc = 0;
	const char* name = (const char*)argp;
	CALL_WITH_DEVNAME(slot_ping, devname, name);
	return rc;
}

static int allocate_slots(const char *name);
static int allocate_slots(const char *name)
{
	int rc = 0;
	struct servants_list_item *s = servants_leader;
	while (s != NULL) {
		DBGPRINT("allocate on device %s\n", s->devname);
		rc = open_device(s->devname);
		if (rc == -1) {
			return -1;
		}
		devname = s->devname;
		rc = slot_allocate(name);
		close(devfd);
		devname = NULL;
		if (rc == -1)
			return rc;
		DBGPRINT("allocation on %s done\n", s->devname);
		s = s->next;
	}
	return 0;
}

static int list_slots(void);
static int list_slots()
{
	int rc = 0;
	struct servants_list_item *s = servants_leader;
	while (s != NULL) {
		DBGPRINT("list slots on device %s\n", s->devname);
		CALL_WITH_DEVNAME(slot_list, s->devname);
		if (rc == -1)
			return rc;
		s = s->next;
	}
	return 0;
}

static int ping_via_slots(const char *name);
static int ping_via_slots(const char *name)
{
	int sig = 0;
	int pid = 0;
	int status = 0;
	int servant_count = 0;
	int servant_finished = 0;
	sigset_t procmask;
	siginfo_t sinfo;

	struct servants_list_item *s = servants_leader;

	DBGPRINT("you shall know no fear\n");
	sigemptyset(&procmask);
	sigaddset(&procmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &procmask, NULL);

	while (s != NULL) {
		pid = assign_servant_ex(s->devname, &slot_ping_wrapper, (const void*)name);
		s -> pid = pid;
		servant_count++;
		s = s->next;
	}

	while (servant_finished < servant_count) {
		sig = sigwaitinfo(&procmask, &sinfo);
		DBGPRINT("get signal %d\n", sig);
		if (sig == SIGCHLD) {
			while ((pid = wait(&status))) {
				if (pid == -1 && errno == ECHILD) {
					break;
				} else {
					DBGPRINT
					    ("A ping is delivered to %s via %s. ",
					     name,
					     lookup_servant_by_pid(pid)->
					     devname);
					if (!status)
						DBGPRINT
						    ("They responed to the emporer\n");
					else
						DBGPRINT
						    ("There's no response\n");
					servant_finished++;
				}
			}
		}
		DBGPRINT("signal %d handled\n", sig);
	}
	return 0;
}

static int servant(const char *diskname, const void* argp);
static int servant(const char *diskname, const void* argp)
{
	int prepare_only = (int)argp;
	struct sector_mbox_s *s_mbox = NULL;
	int mbox;
	int rc = 0;
	time_t t0, t1, latency;
	union sigval signal_value;
	sigset_t servant_masks;

	if (devfd != -1) {
		close(devfd);
	}

	if (!diskname) {
		cl_log(LOG_ERR, "Empty disk name %s.", diskname);
		return -1;
	}
	devname = diskname;

	/* Block most of the signals */
	sigfillset(&servant_masks);
	sigdelset(&servant_masks, SIGKILL);
	sigdelset(&servant_masks, SIGFPE);
	sigdelset(&servant_masks, SIGILL);
	sigdelset(&servant_masks, SIGSEGV);
	sigdelset(&servant_masks, SIGBUS);
	/* FIXME: check error */
	sigprocmask(SIG_SETMASK, &servant_masks, NULL);

	devfd = open(devname, O_SYNC | O_RDWR | O_DIRECT);
	if (devfd == -1) {
		cl_perror("Opening disk %s failed.", devname);
		return -1;
	}
	ioctl(devfd, BLKSSZGET, &sector_size);
	if (sector_size == 0) {
		cl_perror("Get sector size failed.\n");
		close(devfd);
		return -1;
	}

	mbox = slot_allocate(local_uname);
	if (mbox < 0) {
		cl_log(LOG_ERR,
		       "No slot allocated, and automatic allocation failed for disk %s.",
		       devname);
		rc = -1;
		goto out;
	}
	cl_log(LOG_INFO, "Monitoring slot %d on disk %s", mbox, devname);

	s_mbox = sector_alloc();
	if (mbox_write(mbox, s_mbox) < 0) {
		rc = -1;
		goto out;
	}

	if (prepare_only)
		goto out;

	memset(&signal_value, 0, sizeof(signal_value));

	while (1) {
		t0 = time(NULL);
		sleep(timeout_loop);
		if (mbox_read(mbox, s_mbox) < 0) {
			cl_log(LOG_ERR, "mbox read failed.");
			do_reset();
		}

		if (s_mbox->cmd > 0) {
			cl_log(LOG_INFO,
			       "Received command %s from %s on disk %s",
			       char2cmd(s_mbox->cmd), s_mbox->from, devname);

			switch (s_mbox->cmd) {
			case SBD_MSG_TEST:
				memset(s_mbox, 0, sizeof(*s_mbox));
				mbox_write(mbox, s_mbox);
				sigqueue(getppid(), SIG_TEST, signal_value);
				break;
			case SBD_MSG_RESET:
				do_reset();
				break;
			case SBD_MSG_OFF:
				do_off();
				break;
			case SBD_MSG_EXIT:
				sigqueue(getppid(), SIG_EXITREQ, signal_value);
				break;
			default:
				/* FIXME:
				   An "unknown" message might result
				   from a partial write.
				   log it and clear the slot.
				 */
				cl_log(LOG_ERR, "Unknown message on disk %s",
				       devname);
				memset(s_mbox, 0, sizeof(*s_mbox));
				mbox_write(mbox, s_mbox);
				break;
			}
		}
		sigqueue(getppid(), SIG_LIVENESS, signal_value);

		t1 = time(NULL);
		latency = t1 - t0;
		if (timeout_watchdog_warn && (latency > timeout_watchdog_warn)) {
			cl_log(LOG_WARNING,
			       "Latency: %d exceeded threshold %d on disk %s",
			       (int)latency, (int)timeout_watchdog_warn,
			       devname);
		} else if (debug) {
			cl_log(LOG_INFO, "Latency: %d on disk %s", (int)latency,
			       devname);
		}
	}
 out:
	free(s_mbox);
	close(devfd);
	devfd = -1;
	return rc;
}

int recruit_servant(const char *devname, int pid);
int recruit_servant(const char *devname, int pid)
{
	struct servants_list_item *s = servants_leader;
	struct servants_list_item *p = servants_leader;
	struct servants_list_item *newbie;
	while (s != NULL) {
		if (s == p) {
			s = s->next;
		} else {
			p = s;
			s = s->next;
		}
	}
	DBGPRINT("p: %p, s: %p\n", p, s);
	newbie = malloc(sizeof(*newbie));
	memset(newbie, 0, sizeof(*newbie));
	newbie->devname = strdup(devname);
	newbie->pid = pid;
	if (p == NULL)
		servants_leader = newbie;
	else
		p->next = newbie;
	return 0;
}

#if 0
int disband_servant_by_dev(const char *devname);
int disband_servant_by_dev(const char *devname)
{
	int pid;
	struct servants_list_item *s = servants_leader;
	struct servants_list_item *p = servants_leader;
	while (s != NULL) {
		if (!strncasecmp(s->devname, devname, strlen(s->devname))) {
			pid = s->pid;
			free((char *)(s->devname));
			if (s == p)
				servants_leader = s->next;
			else
				p->next = s->next;
			free(s);
			return pid;
		}
		if (s == p) {
			s = s->next;
		} else {
			p = s;
			s = s->next;
		}
	}
	/* no such servant */
	return 0;
}
#endif

struct servants_list_item *lookup_servant_by_dev(const char *devname);
struct servants_list_item *lookup_servant_by_dev(const char *devname)
{
	struct servants_list_item *s = servants_leader;
	while (s != NULL) {
		if (strncasecmp(s->devname, devname, strlen(s->devname)))
			return s;
		else
			s = s->next;
	}
	return s;
}

struct servants_list_item *lookup_servant_by_pid(int pid);
struct servants_list_item *lookup_servant_by_pid(int pid)
{
	struct servants_list_item *s = servants_leader;
	while (s != NULL) {
		if (s->pid == pid)
			return s;
		else
			s = s->next;
	}
	return s;
}

int assign_servant(const char *devname);
int assign_servant(const char *devname)
{
	int pid = 0;
	pid = fork();
	if (pid == 0) {		/* child */
		servant(devname, (void*)0);
		exit(0);
	} else if (pid != -1) {		/* parent */
		return pid;
	} else {
		DBGPRINT("Failed to fork servant\n");
		exit(1);
	}
}

void deploy_servants(int live);
void deploy_servants(int live)
{
	struct servants_list_item *s = servants_leader;
	int r = 0;
	union sigval svalue;
	while (s != NULL) {
		if (s->pid != 0) {
			r = sigqueue(s->pid, 0, svalue);
			if (r == -1 && errno == ESRCH) {
				/* FIXME: process gone, start a new one */
				if (live)
					s->pid = assign_servant(s->devname);
			} else {
				/* servants still working */
				if (!live)
					sigqueue(s->pid, SIGKILL, svalue);
			}
		} else {
			/* FIXME: start new one */
			if (live)
				s->pid = assign_servant(s->devname);
		}
		s = s->next;
	}
}

static int inquisitor(void);
static int inquisitor(void)
{
	int rc, sig, pid, i;

	sigset_t procmask;
	siginfo_t sinfo;
	int expect_report = 0;
	int *reports;
	int has_new;
	int status;
	const char *tdevname;
	struct servants_list_item *s = servants_leader;
	int servant_count = 0;
	int servant_finished = 0;
	int good_servant = 0;
	int inconsistent = 0;

	DBGPRINT("emporer is watching you\n");

	while (s != NULL) {
		DBGPRINT("disk %s is watched by %d\n", s->devname, s->pid);
		s = s->next;
		expect_report++;
	}

	DBGPRINT("expect_report is %d\n", expect_report);
	reports = malloc(sizeof(int) * expect_report);
	if (reports == 0) {
		cl_log(LOG_ERR, "malloc failed");
		exit(1);
	}
	memset(reports, 0, sizeof(int) * expect_report);

	sigemptyset(&procmask);
	sigaddset(&procmask, SIGCHLD);
	sigaddset(&procmask, SIG_LIVENESS);
	sigaddset(&procmask, SIG_EXITREQ);
	sigaddset(&procmask, SIG_TEST);
	sigaddset(&procmask, SIGUSR1);
	sigaddset(&procmask, SIGUSR2);
	sigaddset(&procmask, SIGINT);
	sigprocmask(SIG_BLOCK, &procmask, NULL);

	s = servants_leader;
	while (s != NULL) {
		pid = assign_servant_ex(s->devname, &servant, (const void*)1);
		servant_count++;
		s = s->next;
	}

	while (servant_finished < servant_count) {
		sig = sigwaitinfo(&procmask, &sinfo);
		DBGPRINT("get signal %d\n", sig);
		if (sig == SIGCHLD) {
			while ((pid = waitpid(-1, &status, WNOHANG))) {
				if (pid == -1 && errno == ECHILD) {
					break;
				} else {
					DBGPRINT("process %d finished\n", pid);
					tdevname = lookup_servant_by_pid(pid)->devname;
					lookup_servant_by_pid(pid)->pid = 0;
					servant_finished++;
					if (WIFEXITED(status)
					    && WEXITSTATUS(status) == 0) {
						DBGPRINT("exit with %d\n",
							 WEXITSTATUS(status));
						good_servant++;
						do {
							struct sector_header_s header;
							unsigned long timeout_watchdog_old = timeout_watchdog;
						    int timeout_loop_old = timeout_loop;
							int timeout_msgwait_old = timeout_msgwait;	

							CALL_WITH_DEVNAME(header_read, tdevname, &header);
							if (rc != 0) {
								/* Servant reports good a while ago, 
								   this should not happen.*/
								DBGPRINT("header_read failed\n");
								exit(1);
							}
							if (good_servant == 1) {
								inconsistent = 0;
							} else {
								if (timeout_loop_old != timeout_loop ||
										timeout_watchdog_old != timeout_watchdog ||
										timeout_msgwait_old != timeout_msgwait)
									inconsistent = 1;
							}

						} while (0);
					}
				}
			}
		}
		DBGPRINT("signal %d handled\n", sig);
	}
	DBGPRINT("total %d, finished %d, report good %d\n", servant_count,
		 servant_finished, good_servant);
	if (good_servant >= servant_count / 2 + 1) {
		DBGPRINT("we are good to proceed\n");
	} else {
		DBGPRINT("no enough good servant\n");
		return -1;
	}

	if (inconsistent) {
		DBGPRINT("Timeout configurations are different on different SBD devices\n");
		DBGPRINT("This may running into problem in long run.\n");
		DBGPRINT("You have to correct them and re-start SBD again.\n");
		return -1;
	}

	make_daemon();
	deploy_servants(1);
	if (watchdog_use != 0)
		watchdog_init();

	while (1) {
		sig = sigwaitinfo(&procmask, &sinfo);
		DBGPRINT("get signal %d\n", sig);
		if (sig == SIGINT || sig == SIG_EXITREQ) {
			deploy_servants(0);
			watchdog_close();
			exit(0);
		} else if (sig == SIGCHLD) {
			while ((pid = waitpid(-1, &status, WNOHANG))) {
				if (pid == -1 && errno == ECHILD) {
					break;
				} else {
					if (WIFEXITED(status)) {	/* terminated normally */
						DBGPRINT
						    ("terminated normally\n");
						lookup_servant_by_pid(pid)->
						    pid = 0;
					} else if (WIFSIGNALED(status)) {	/* by signal */
						if (WTERMSIG(status) != SIGKILL) {
							DBGPRINT
							    ("something wrong, restart it\n");
							tdevname =
							    lookup_servant_by_pid
							    (pid)->devname;
							lookup_servant_by_pid
							    (pid)->pid =
							    assign_servant
							    (tdevname);
						} else {
							DBGPRINT("killed\n");
							lookup_servant_by_pid
							    (pid)->pid = 0;
						}
					}
				}
			}
		} else if (sig == SIG_LIVENESS) {
			for (i = 0; i < expect_report; i++) {
				if (reports[i] == sinfo.si_pid) {
					has_new = 0;
					break;
				} else if (reports[i] == 0) {
					reports[i] = sinfo.si_pid;
					has_new = 1;
					break;
				}
			}
			if (!has_new)
				continue;
			for (i = 0; i < expect_report; i++) {
				if (reports[i] == 0) {
					if (i >= expect_report / 2 + 1) {
						DBGPRINT
						    ("enough reports, purify the planet\n");
						watchdog_tickle();
						memset(reports, 0,
						       sizeof(int) *
						       expect_report);
					} else {
						DBGPRINT("still wait\n");
					}
					break;
				}
			}
		} else if (sig == SIG_TEST) {
		} else if (sig == SIGUSR1) {
			watchdog_tickle();
			DBGPRINT("USR1 recieved\n");
			deploy_servants(1);
			DBGPRINT("servants restarted\n");
			memset(reports, 0, sizeof(int) * expect_report);
			watchdog_tickle();
		} else {
			DBGPRINT("ignore anything else can be ignored\n");
			continue;
		}
	}
}

static int messenger(const char *name, const char *msg);
static int messenger(const char *name, const char *msg)
{
	int sig = 0;
	int pid = 0;
	int status = 0;
	int servant_count = 0;
	int servant_finished = 0;
	int successed_delivery = 0;
	sigset_t procmask;
	siginfo_t sinfo;
	struct servants_list_item *s = servants_leader;
	struct slot_msg_arg_t slot_msg_arg = {name, msg};

	sigemptyset(&procmask);
	sigaddset(&procmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &procmask, NULL);

	while (s != NULL) {
		pid = assign_servant_ex(s->devname, &slot_msg_wrapper, &slot_msg_arg);
		s->pid = pid;
		servant_count++;
		s = s->next;
	}
	
	while (servant_finished < servant_count) {
		sig = sigwaitinfo(&procmask, &sinfo);
		DBGPRINT("get signal %d\n", sig);
		if (sig == SIGCHLD) {
			while ((pid = waitpid(-1, &status, WNOHANG))) {
				if (pid == -1 && errno == ECHILD) {
					break;
				} else {
					DBGPRINT("process %d finished\n", pid);
					servant_finished++;
					if (WIFEXITED(status)
						&& WEXITSTATUS(status) == 0) {
						DBGPRINT("exit with %d\n",
								WEXITSTATUS(status));
						successed_delivery++;
					}
					if (successed_delivery >= (servant_count / 2 + 1)) {
						DBGPRINT("we have done good enough\n");
						return 0;
					}
				}
			}
		}
		DBGPRINT("signal %d handled\n", sig);
	}
	if (successed_delivery >= (servant_count / 2 + 1)) {
		return 0;
	} else {
		DBGPRINT("Message is not delivery via more then a half devices\n");
		return 1;
	}
}

static int dump_headers(void);
static int dump_headers(void)
{
	int rc = 0;
	struct servants_list_item *s = servants_leader;
	while (s != NULL) {
		DBGPRINT("Dumping header on disk %s\n", s->devname);
		CALL_WITH_DEVNAME(header_dump, s->devname);
		if (rc == -1)
			return rc;
		DBGPRINT("Header on disk %s is dumped\n", s->devname);
		s = s->next;
	}
	return rc;
}

int main(int argc, char **argv)
{
	int exit_status = 0;
	int c;

	if ((cmdname = strrchr(argv[0], '/')) == NULL) {
		cmdname = argv[0];
	} else {
		++cmdname;
	}

	cl_log_set_entity(cmdname);
	cl_log_enable_stderr(0);
	cl_log_set_facility(LOG_DAEMON);

	get_uname();

	while ((c = getopt(argc, argv, "DRWhvw:d:n:1:2:3:4:5:")) != -1) {
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
		case 'W':
			watchdog_use = 1;
			break;
		case 'w':
			watchdogdev = optarg;
			break;
		case 'd':
			recruit_servant(optarg, 0);
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
			return (0);
		default:
			exit_status = -1;
			goto out;
			break;
		}
	}

	/* There must at least be one command following the options: */
	if ((argc - optind) < 1) {
		fprintf(stderr, "Not enough arguments.\n");
		exit_status = -1;
		goto out;
	}

	maximize_priority();

	if (strcmp(argv[optind], "create") == 0) {
		exit_status = init_devices();
	} else if (strcmp(argv[optind], "dump") == 0) {
		exit_status = dump_headers();
	} else if (strcmp(argv[optind], "allocate") == 0) {
		exit_status = allocate_slots(argv[optind + 1]);
	} else if (strcmp(argv[optind], "list") == 0) {
		exit_status = list_slots();
	} else if (strcmp(argv[optind], "message") == 0) {
		exit_status = messenger(argv[optind + 1], argv[optind + 2]);
	} else if (strcmp(argv[optind], "ping") == 0) {
		exit_status = ping_via_slots(argv[optind + 1]);
	} else if (strcmp(argv[optind], "watch") == 0) {
		exit_status = inquisitor();
	} else {
		exit_status = -1;
	}

 out:
	if (exit_status < 0) {
		usage();
		return (1);
	}
	return (0);
}
