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
#include <time.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/watchdog.h>
#include <linux/fs.h>

#include "sbd.h"

struct servants_list_item *servants_leader = NULL;

enum {
	SERVANT_DEPLOY,
	SERVANT_CALLBACK
};

enum {
	SERVANT_DO_FULLJOB = 0,
	SERVANT_PREPARE_ONLY = 1
};

static int	servant_count	= 0;

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

int assign_servant(const char* devname, functionp_t functionp, const void* argp)
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

int init_devices()
{
	int rc = 0;
	int devfd;
	struct servants_list_item *s = servants_leader;
	while (s != NULL) {
		DBGPRINT("init device %s\n", s->devname);
		devfd = open_device(s->devname);
		if (devfd == -1) {
			return -1;
		}
		rc = init_device(devfd);
		close(devfd);
		if (rc == -1) {
			fprintf(stderr, "failed to init device %s", s->devname);
			return rc;
		}
		s = s->next;
	}
	return 0;
}

int slot_msg_wrapper(const char* devname, const void* argp)
{
	int rc = 0;
	int devfd;
	const struct slot_msg_arg_t* arg = (const struct slot_msg_arg_t*)argp;
    devfd = open_device(devname);
    if (devfd == -1) 
		return -1;
    rc = slot_msg(devfd, arg->name, arg->msg);
    close(devfd);
	return rc;
}

int slot_ping_wrapper(const char* devname, const void* argp)
{
	int rc = 0;
	const char* name = (const char*)argp;
	int devfd;
    devfd = open_device(devname);
    if (devfd == -1)
		return -1;
    rc = slot_ping(devfd, name);
    close(devfd);
	return rc;
}

int allocate_slots(const char *name)
{
	int rc = 0;
	int devfd;
	struct servants_list_item *s = servants_leader;
	while (s != NULL) {
		DBGPRINT("allocate on device %s\n", s->devname);
		devfd = open_device(s->devname);
		if (devfd == -1) {
			return -1;
		}
		rc = slot_allocate(devfd, name);
		close(devfd);
		if (rc == -1)
			return rc;
		DBGPRINT("allocation on %s done\n", s->devname);
		s = s->next;
	}
	return 0;
}

int list_slots()
{
	int rc = 0;
	struct servants_list_item *s = servants_leader;
	int devfd;
	while (s != NULL) {
		DBGPRINT("list slots on device %s\n", s->devname);
		devfd = open_device(s->devname);
		if (devfd == -1)
		   return -1;
		rc = slot_list(devfd);
		close(devfd);
		if (rc == -1)
			return rc;
		s = s->next;
	}
	return 0;
}

int ping_via_slots(const char *name)
{
	int sig = 0;
	int pid = 0;
	int status = 0;
	int servant_finished = 0;
	sigset_t procmask;
	siginfo_t sinfo;

	struct servants_list_item *s = servants_leader;

	DBGPRINT("you shall know no fear\n");
	sigemptyset(&procmask);
	sigaddset(&procmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &procmask, NULL);

	while (s != NULL) {
		s->pid = assign_servant(s->devname, &slot_ping_wrapper, (const void*)name);
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
					struct servants_list_item *s;
					s = lookup_servant_by_pid(pid);
					if (s) {
						DBGPRINT
						    ("A ping is delivered to %s via %s. ",
						     name, s->devname);
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
		}
		DBGPRINT("signal %d handled\n", sig);
	}
	return 0;
}

int servant(const char *diskname, const void* argp)
{
	intptr_t prepare_only = (intptr_t)argp;
	struct sector_mbox_s *s_mbox = NULL;
	int mbox;
	int rc = 0;
	time_t t0, t1, latency;
	union sigval signal_value;
	sigset_t servant_masks;
	int devfd;
	int ppid;

	if (!diskname) {
		cl_log(LOG_ERR, "Empty disk name %s.", diskname);
		return -1;
	}

	/* Block most of the signals */
	sigfillset(&servant_masks);
	sigdelset(&servant_masks, SIGKILL);
	sigdelset(&servant_masks, SIGFPE);
	sigdelset(&servant_masks, SIGILL);
	sigdelset(&servant_masks, SIGSEGV);
	sigdelset(&servant_masks, SIGBUS);
	sigdelset(&servant_masks, SIGALRM);
	/* FIXME: check error */
	sigprocmask(SIG_SETMASK, &servant_masks, NULL);

	devfd = open(diskname, O_SYNC | O_RDWR | O_DIRECT);
	if (devfd == -1) {
		cl_perror("Opening disk %s failed.", diskname);
		return -1;
	}
	ioctl(devfd, BLKSSZGET, &sector_size);
	if (sector_size == 0) {
		cl_perror("Get sector size failed.\n");
		close(devfd);
		return -1;
	}

	mbox = slot_allocate(devfd, local_uname);
	if (mbox < 0) {
		cl_log(LOG_ERR,
		       "No slot allocated, and automatic allocation failed for disk %s.",
		       diskname);
		rc = -1;
		goto out;
	}
	cl_log(LOG_INFO, "Monitoring slot %d on disk %s", mbox, diskname);

	s_mbox = sector_alloc();
	if (mbox_write(devfd, mbox, s_mbox) < 0) {
		rc = -1;
		goto out;
	}

	if (prepare_only == SERVANT_PREPARE_ONLY)
		goto out;

	memset(&signal_value, 0, sizeof(signal_value));

	while (1) {
		t0 = time(NULL);
		sleep(timeout_loop);

		ppid = getppid();

		if (ppid == 1) {
			/* Our parent died unexpectedly. Triggering
			 * self-fence. */
			do_reset();
		}

		if (mbox_read(devfd, mbox, s_mbox) < 0) {
			cl_log(LOG_ERR, "mbox read failed in servant.");
			exit(1);
		}

		if (s_mbox->cmd > 0) {
			cl_log(LOG_INFO,
			       "Received command %s from %s on disk %s",
			       char2cmd(s_mbox->cmd), s_mbox->from, diskname);

			switch (s_mbox->cmd) {
			case SBD_MSG_TEST:
				memset(s_mbox, 0, sizeof(*s_mbox));
				mbox_write(devfd, mbox, s_mbox);
				sigqueue(ppid, SIG_TEST, signal_value);
				break;
			case SBD_MSG_RESET:
				do_reset();
				break;
			case SBD_MSG_OFF:
				do_off();
				break;
			case SBD_MSG_EXIT:
				sigqueue(ppid, SIG_EXITREQ, signal_value);
				break;
			default:
				/* FIXME:
				   An "unknown" message might result
				   from a partial write.
				   log it and clear the slot.
				 */
				cl_log(LOG_ERR, "Unknown message on disk %s",
				       diskname);
				memset(s_mbox, 0, sizeof(*s_mbox));
				mbox_write(devfd, mbox, s_mbox);
				break;
			}
		}
		sigqueue(ppid, SIG_LIVENESS, signal_value);

		t1 = time(NULL);
		latency = t1 - t0;
		if (timeout_watchdog_warn && (latency > timeout_watchdog_warn)) {
			cl_log(LOG_WARNING,
			       "Latency: %d exceeded threshold %d on disk %s",
			       (int)latency, (int)timeout_watchdog_warn,
			       diskname);
		} else if (debug) {
			cl_log(LOG_INFO, "Latency: %d on disk %s", (int)latency,
			       diskname);
		}
	}
 out:
	free(s_mbox);
	close(devfd);
	devfd = -1;
	return rc;
}

void recruit_servant(const char *devname, int pid)
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
	if (!newbie) {
		fprintf(stderr, "malloc failed in recruit_servant.");
		exit(1);
	}

	memset(newbie, 0, sizeof(*newbie));
	newbie->devname = strdup(devname);
	newbie->pid = pid;
	if (p == NULL)
		servants_leader = newbie;
	else
		p->next = newbie;

	servant_count++;
}

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

int check_all_dead(void)
{
	struct servants_list_item *s = servants_leader;
	int r = 0;
	union sigval svalue;
	while (s != NULL) {
		if (s->pid != 0) {
			r = sigqueue(s->pid, 0, svalue);
			if (r == -1 && errno == ESRCH) {
				/*live*/
			} else {
				/*dead*/
				return 0;
			}
		}
		s = s->next;
	}
	return 1;
}


void foreach_servants(int mission)
{
	struct servants_list_item *s = servants_leader;
	int r = 0;
	union sigval svalue;
	while (s != NULL) {
		if (s->pid != 0) {
			r = sigqueue(s->pid, 0, svalue);
			if (r == -1 && errno == ESRCH) {
				/* FIXME: process gone, start a new one */
				if (mission == SERVANT_DEPLOY)
					s->pid = assign_servant(s->devname, servant, (const void*)SERVANT_DO_FULLJOB);
			} else {
				/* servants still working */
				if (mission == SERVANT_CALLBACK)
					sigqueue(s->pid, SIGKILL, svalue);
			}
		} else {
			/* FIXME: start new one */
			if (mission == SERVANT_DEPLOY)
				s->pid = assign_servant(s->devname, servant, (const void*)SERVANT_DO_FULLJOB);
		}
		s = s->next;
	}
}

int check_timeout_inconsistent(const char* devname)
{
	int devfd;
	struct sector_header_s *s_header;

	unsigned long timeout_watchdog_old = timeout_watchdog;
	int timeout_loop_old = timeout_loop;
	int timeout_msgwait_old = timeout_msgwait;	

	devfd = open_device(devname);
	if (devfd == -1) {
		/* Servant reports good a while ago, 
		   this should not happen.*/
		exit(1);
	}

	s_header = header_get(devfd);
	close(devfd);

	if (s_header == NULL) {
		/* Servant reports good a while ago, 
		   this should not happen.*/
		exit(1);
	} else {
		free(s_header);
	}

	if (timeout_loop_old != timeout_loop ||
			timeout_watchdog_old != timeout_watchdog ||
			timeout_msgwait_old != timeout_msgwait)
		return 1;
	else
		return 0;
}

inline void cleanup_servant_by_pid(int pid)
{
	struct servants_list_item* s;
	s = lookup_servant_by_pid(pid);
	if (s) {
		s->pid = 0;
	} else {
		/* TODO: This points to an inconsistency in our internal
		 * data - how to recover? */
		cl_log(LOG_ERR, "Cannot cleanup after unknown pid %i",
				pid);
	}
}

inline void restart_servant_by_pid(int pid)
{
	struct servants_list_item* s;
	s = lookup_servant_by_pid(pid);
	if (s) {
		s->pid = assign_servant(s->devname, servant, (const void*)SERVANT_DO_FULLJOB);
	} else {
		/* TODO: This points to an inconsistency in our internal
		 * data - how to recover? */
		cl_log(LOG_ERR, "Cannot restart unknown pid %i",
				pid);
	}
}

int inquisitor(void)
{
	int sig, pid, i;

	sigset_t procmask;
	siginfo_t sinfo;
	int *reports;
	int has_new;
	int status;
	const char *tdevname;
	struct servants_list_item *s = servants_leader;
	struct timespec timeout;
	int servant_finished = 0;
	int good_servant = 0;
	int inconsistent = 0;
	int exiting = 0;
	time_t latency;
	struct timespec t_last_tickle, t_now;

	DBGPRINT("emporer is watching you\n");

	while (s != NULL) {
		DBGPRINT("disk %s is watched by %d\n", s->devname, s->pid);
		s = s->next;
	}

	reports = malloc(sizeof(int) * servant_count);
	if (reports == 0) {
		cl_log(LOG_ERR, "malloc failed");
		exit(1);
	}
	memset(reports, 0, sizeof(int) * servant_count);

	sigemptyset(&procmask);
	sigaddset(&procmask, SIGCHLD);
	sigaddset(&procmask, SIG_LIVENESS);
	sigaddset(&procmask, SIG_EXITREQ);
	sigaddset(&procmask, SIG_TEST);
	sigaddset(&procmask, SIGUSR1);
	sigaddset(&procmask, SIGUSR2);
	sigprocmask(SIG_BLOCK, &procmask, NULL);

	s = servants_leader;
	while (s != NULL) {
		s->pid = assign_servant(s->devname, &servant, (const void*)SERVANT_PREPARE_ONLY);
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
					struct servants_list_item *s;
					DBGPRINT("process %d finished\n", pid);
					s = lookup_servant_by_pid(pid);
					if (s) {
						tdevname = s->devname;
						cleanup_servant_by_pid(pid);
						servant_finished++;
						if (WIFEXITED(status)
						    && WEXITSTATUS(status) == 0) {
							DBGPRINT("exit normally %d\n", pid);
							good_servant++;
							if (check_timeout_inconsistent(tdevname)) {
								if (good_servant == 1)
									inconsistent = 0;
								else
									inconsistent = 1;
							} else {
								inconsistent = 0;
							}
						}
					} else {
						fprintf(stderr, "SIGCHLD for unknown child %i received, ignoring.\n", pid);
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
		fprintf(stderr, "Less than half of the SBD devices are available.\n");
		fprintf(stderr, "SBD can not function normally.\n");
		return -1;
	}

	if (inconsistent) {
		fprintf(stderr, "Timeout configurations are different on different SBD devices\n");
		fprintf(stderr, "This may running into problem in long run.\n");
		fprintf(stderr, "You have to correct them and re-start SBD again.\n");
		return -1;
	}

	make_daemon();
	foreach_servants(SERVANT_DEPLOY);
	if (watchdog_use != 0)
		watchdog_init();

	timeout.tv_sec = timeout_loop;
	timeout.tv_nsec = 0;

	while (1) {
		sig = sigtimedwait(&procmask, &sinfo, &timeout);
		DBGPRINT("get signal %d\n", sig);
		if (sig == SIG_EXITREQ) {
			foreach_servants(SERVANT_CALLBACK);
			watchdog_close();
			exiting = 1;
		} else if (sig == SIGCHLD) {
			while ((pid = waitpid(-1, &status, WNOHANG))) {
				if (pid == -1 && errno == ECHILD) {
					break;
				} else if (exiting) {
					cleanup_servant_by_pid(pid);
					if (check_all_dead())
						exit(0);
				} else {
					if (WIFEXITED(status)) {	/* terminated normally */
						DBGPRINT
						    ("terminated normally\n");
						cleanup_servant_by_pid(pid);
					} else if (WIFSIGNALED(status)) {	/* by signal */
						if (WTERMSIG(status) != SIGKILL) {
							DBGPRINT
							    ("something wrong, restart it\n");
							restart_servant_by_pid(pid);
						} else {
							DBGPRINT("killed\n");
							cleanup_servant_by_pid(pid);
						}
					}
				}
			}
		} else if (sig == SIG_LIVENESS) {
			if (exiting)
				continue;
			for (i = 0; i < servant_count; i++) {
				if (reports[i] == sinfo.si_pid) {
					has_new = 0;
					break;
				} else if (reports[i] == 0) {
					reports[i] = sinfo.si_pid;
					has_new = 1;
					break;
				}
			}
			if (has_new) {
				for (i = 0; i < servant_count; i++) {
					if (reports[i] == 0) {
						if (i >= servant_count / 2 + 1) {
							DBGPRINT
							    ("enough reports, purify the planet\n");
							watchdog_tickle();
							clock_gettime(CLOCK_MONOTONIC,
									&t_last_tickle);

							memset(reports, 0,
							       sizeof(int) *
							       servant_count);
						} else {
							DBGPRINT("still wait\n");
						}
						break;
					}
				}
			}
		} else if (sig == SIG_TEST) {
		} else if (sig == SIGUSR1) {
			if (exiting == 1)
				continue;
			watchdog_tickle();
			DBGPRINT("USR1 recieved\n");
			foreach_servants(SERVANT_DEPLOY);
			DBGPRINT("servants restarted\n");
			memset(reports, 0, sizeof(int) * servant_count);
			watchdog_tickle();
		} else if (sig == -1) {
			/* sigtimedwait() returned; no problem, we just
			 * need to recheck our internal timers
			 * periodically. */
		} else {
			DBGPRINT("ignore anything else can be ignored\n");
			continue;
		}

		if (exiting)
			continue;

		clock_gettime(CLOCK_MONOTONIC, &t_now);
		latency = t_now.tv_sec - t_last_tickle.tv_sec;
		if (timeout_watchdog && (latency > timeout_watchdog)) {
			/* We have not received sufficient liveness
			 * messages for quite a while. We can only have
			 * gotten here if the user is not using a
			 * watchdog device, or if the watchdog has
			 * failed us. */
			do_reset();
		}
		if (timeout_watchdog_warn && (latency > timeout_watchdog_warn)) {
			cl_log(LOG_WARNING,
			       "Latency: No liveness for %d s exceeds threshold of %d s",
			       (int)latency, (int)timeout_watchdog_warn);
		}
	}
}

int messenger(const char *name, const char *msg)
{
	int sig = 0;
	int pid = 0;
	int status = 0;
	int servant_finished = 0;
	int successful_delivery = 0;
	sigset_t procmask;
	siginfo_t sinfo;
	struct servants_list_item *s = servants_leader;
	struct slot_msg_arg_t slot_msg_arg = {name, msg};

	sigemptyset(&procmask);
	sigaddset(&procmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &procmask, NULL);

	while (s != NULL) {
		s->pid = assign_servant(s->devname, &slot_msg_wrapper, &slot_msg_arg);
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
						successful_delivery++;
					}
					if (successful_delivery >= (servant_count / 2 + 1)) {
						DBGPRINT("we have done good enough\n");
						return 0;
					}
				}
			}
		}
		DBGPRINT("signal %d handled\n", sig);
	}
	if (successful_delivery >= (servant_count / 2 + 1)) {
		return 0;
	} else {
		fprintf(stderr, "Message is not delivery via more then a half of devices\n");
		return -1;
	}
}

int dump_headers(void)
{
	int rc = 0;
	struct servants_list_item *s = servants_leader;
	int devfd;
	while (s != NULL) {
		DBGPRINT("Dumping header on disk %s\n", s->devname);
		devfd = open_device(s->devname);
		if (devfd == -1)
			return -1;
		rc = header_dump(devfd);
		close(devfd);
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

	if (servant_count != 1 && servant_count != 3) {
		fprintf(stderr, "You must specify either 1 or 3 devices via the -d option.\n");	
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
