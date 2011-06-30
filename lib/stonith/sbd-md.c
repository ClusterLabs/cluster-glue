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
#include <clplumbing/setproctitle.h>
#include <malloc.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/watchdog.h>
#include <linux/fs.h>

#include "sbd.h"

struct servants_list_item *servants_leader = NULL;

static int	servant_count	= 0;
static int	servant_restart_interval = 3600;

/* signals reserved for multi-disk sbd */
#define SIG_LIVENESS (SIGRTMIN + 1)	/* report liveness of the disk */
#define SIG_EXITREQ  (SIGRTMIN + 2)	/* exit request to inquisitor */
#define SIG_TEST     (SIGRTMIN + 3)	/* trigger self test */
#define SIG_RESTART  (SIGRTMIN + 4)	/* trigger restart of all failed disk */
/* FIXME: should add dynamic check of SIG_XX >= SIGRTMAX */

/* Debug Helper */
#if 0
#define DBGPRINT(...) fprintf(stderr, __VA_ARGS__)
#else
#define DBGPRINT(...) do {} while (0)
#endif

int quorum_write(int good_servants)
{
	return (good_servants > servant_count/2);	
}

int quorum_read(int good_servants)
{
	if (servant_count >= 3) 
		return (good_servants > servant_count/2);
	else
		return (good_servants >= 1);
}

int assign_servant(const char* devname, functionp_t functionp, const void* argp)
{
	pid_t pid = 0;
	int rc = 0;

	DBGPRINT("fork servant for %s\n", devname);
	pid = fork();
	if (pid == 0) {		/* child */
		maximize_priority();
		rc = (*functionp)(devname, argp);
		if (rc == -1)
			exit(1);
		else
			exit(0);
	} else if (pid != -1) {		/* parent */
		return pid;
	} else {
		cl_log(LOG_ERR,"Failed to fork servant");
		exit(1);
	}
}

int init_devices()
{
	int rc = 0;
	int devfd;
	struct servants_list_item *s;

	for (s = servants_leader; s; s = s->next) {
		fprintf(stdout, "Initializing device %s\n",
				s->devname);
		devfd = open_device(s->devname);
		if (devfd == -1) {
			return -1;
		}
		rc = init_device(devfd);
		close(devfd);
		if (rc == -1) {
			fprintf(stderr, "Failed to init device %s\n", s->devname);
			return rc;
		}
		fprintf(stdout, "Device %s is initialized.\n", s->devname);
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
	struct servants_list_item *s;

	for (s = servants_leader; s; s = s->next) {
		fprintf(stdout, "Trying to allocate slot for %s on device %s.\n", 
				name,
				s->devname);
		devfd = open_device(s->devname);
		if (devfd == -1) {
			return -1;
		}
		rc = slot_allocate(devfd, name);
		close(devfd);
		if (rc == -1)
			return rc;
		fprintf(stdout, "Slot for %s has been allocated on %s.\n",
				name,
				s->devname);
	}
	return 0;
}

int list_slots()
{
	int rc = 0;
	struct servants_list_item *s;
	int devfd;

	for (s = servants_leader; s; s = s->next) {
		DBGPRINT("list slots on device %s\n", s->devname);
		devfd = open_device(s->devname);
		if (devfd == -1)
			return -1;
		rc = slot_list(devfd);
		close(devfd);
		if (rc == -1)
			return rc;
	}
	return 0;
}

int ping_via_slots(const char *name)
{
	int sig = 0;
	pid_t pid = 0;
	int status = 0;
	int servants_finished = 0;
	sigset_t procmask;
	siginfo_t sinfo;
	struct servants_list_item *s;

	DBGPRINT("you shall know no fear\n");
	sigemptyset(&procmask);
	sigaddset(&procmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &procmask, NULL);

	for (s = servants_leader; s; s = s->next) {
		s->pid = assign_servant(s->devname, &slot_ping_wrapper, (const void*)name);
	}

	while (servants_finished < servant_count) {
		sig = sigwaitinfo(&procmask, &sinfo);
		DBGPRINT("get signal %d\n", sig);
		if (sig == SIGCHLD) {
			while ((pid = wait(&status))) {
				if (pid == -1 && errno == ECHILD) {
					break;
				} else {
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
						servants_finished++;
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
	struct sector_mbox_s *s_mbox = NULL;
	int mbox;
	int rc = 0;
	time_t t0, t1, latency;
	union sigval signal_value;
	sigset_t servant_masks;
	int devfd;
	pid_t ppid;

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

	devfd = open_device(diskname);
	if (devfd == -1) {
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
	set_proc_title("sbd: watcher: %s - slot: %d", diskname, mbox);

	s_mbox = sector_alloc();
	if (mbox_write(devfd, mbox, s_mbox) < 0) {
		rc = -1;
		goto out;
	}

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
			case SBD_MSG_CRASHDUMP:
				do_crashdump();
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

void recruit_servant(const char *devname, pid_t pid)
{
	struct servants_list_item *s = servants_leader;
	struct servants_list_item *newbie;

	newbie = malloc(sizeof(*newbie));
	if (!newbie) {
		fprintf(stderr, "malloc failed in recruit_servant.");
		exit(1);
	}
	memset(newbie, 0, sizeof(*newbie));
	newbie->devname = strdup(devname);
	newbie->pid = pid;

	if (!s) {
		servants_leader = newbie;
	} else {
		while (s->next)
			s = s->next;
		s->next = newbie;
	}

	servant_count++;
}

struct servants_list_item *lookup_servant_by_dev(const char *devname)
{
	struct servants_list_item *s;

	for (s = servants_leader; s; s = s->next) {
		if (strncasecmp(s->devname, devname, strlen(s->devname)))
			break;
	}
	return s;
}

struct servants_list_item *lookup_servant_by_pid(pid_t pid)
{
	struct servants_list_item *s;

	for (s = servants_leader; s; s = s->next) {
		if (s->pid == pid)
			break;
	}
	return s;
}

int check_all_dead(void)
{
	struct servants_list_item *s;
	int r = 0;
	union sigval svalue;

	for (s = servants_leader; s; s = s->next) {
		if (s->pid != 0) {
			r = sigqueue(s->pid, 0, svalue);
			if (r == -1 && errno == ESRCH)
				continue;
			return 0;
		}
	}
	return 1;
}


void servants_start(void)
{
	struct servants_list_item *s;
	int r = 0;
	union sigval svalue;

	for (s = servants_leader; s; s = s->next) {
		if (s->pid != 0) {
			r = sigqueue(s->pid, 0, svalue);
			if ((r != -1 || errno != ESRCH))
				continue;
		}
		s->restarts = 0;
		s->pid = assign_servant(s->devname, servant, NULL);
	}
}

void servants_kill(void)
{
	struct servants_list_item *s;
	union sigval svalue;

	for (s = servants_leader; s; s = s->next) {
		if (s->pid != 0)
			sigqueue(s->pid, SIGKILL, svalue);
	}
}

int check_timeout_inconsistent(void)
{
	int devfd;
	struct sector_header_s *hdr_cur = 0, *hdr_last = 0;
	struct servants_list_item* s;
	int inconsistent = 0;

	for (s = servants_leader; s; s = s->next) {
		devfd = open_device(s->devname);
		if (devfd < 0)
			continue;
		hdr_cur = header_get(devfd);
		close(devfd);
		if (!hdr_cur)
			continue;
		if (hdr_last) {
			if (hdr_last->timeout_watchdog != hdr_cur->timeout_watchdog
			    || hdr_last->timeout_allocate != hdr_cur->timeout_allocate
			    || hdr_last->timeout_loop != hdr_cur->timeout_loop
			    || hdr_last->timeout_msgwait != hdr_cur->timeout_msgwait)
				inconsistent = 1;
			free(hdr_last);
		}
		hdr_last = hdr_cur;
	}

	if (hdr_last) {
		timeout_watchdog = hdr_last->timeout_watchdog;
		timeout_allocate = hdr_last->timeout_allocate;
		timeout_loop = hdr_last->timeout_loop;
		timeout_msgwait = hdr_last->timeout_msgwait;
	} else { 
		cl_log(LOG_ERR, "No devices were available at start-up.");
		exit(1);
	}

	free(hdr_last);
	return inconsistent;
}

inline void cleanup_servant_by_pid(pid_t pid)
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

void restart_servant_by_pid(pid_t pid)
{
	struct servants_list_item* s;

	s = lookup_servant_by_pid(pid);
	if (s) {
		if (s->restarts < 10) {
			s->pid = assign_servant(s->devname, servant, NULL);
			s->restarts++;
		} else {
			cl_log(LOG_WARNING, "Max retry count reached: not restarting servant for %s",
					s->devname);
		}

	} else {
		/* TODO: This points to an inconsistency in our internal
		 * data - how to recover? */
		cl_log(LOG_ERR, "Cannot restart unknown pid %i",
				pid);
	}
}

int inquisitor_decouple(void)
{
	pid_t ppid = getppid();
	union sigval signal_value;

	/* During start-up, we only arm the watchdog once we've got
	 * quorum at least once. */
	if (watchdog_use) {
		if (watchdog_init() < 0) {
			return -1;
		}
	}

	if (ppid > 1) {
		sigqueue(ppid, SIG_LIVENESS, signal_value);
	}
	return 0;
}

void inquisitor_child(void)
{
	int sig, pid, i;
	sigset_t procmask;
	siginfo_t sinfo;
	int *reports;
	int status;
	struct timespec timeout;
	int good_servants = 0;
	int exiting = 0;
	int decoupled = 0;
	time_t latency;
	struct timespec t_last_tickle, t_now, t_last_restarted;

	set_proc_title("sbd: inquisitor");

	reports = malloc(sizeof(int) * servant_count);
	if (!reports) {
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

	servants_start();

	timeout.tv_sec = timeout_loop;
	timeout.tv_nsec = 0;
	good_servants = 0;
	clock_gettime(CLOCK_MONOTONIC, &t_last_tickle);
	clock_gettime(CLOCK_MONOTONIC, &t_last_restarted);

	while (1) {
		sig = sigtimedwait(&procmask, &sinfo, &timeout);
		DBGPRINT("got signal %d\n", sig);

		if (sig == SIG_EXITREQ) {
			servants_kill();
			watchdog_close();
			exiting = 1;
		} else if (sig == SIGCHLD) {
			while ((pid = waitpid(-1, &status, WNOHANG))) {
				if (pid == -1 && errno == ECHILD) {
					break;
				} else if (exiting) {
					cleanup_servant_by_pid(pid);
				} else {
					restart_servant_by_pid(pid);
				}
			}
		} else if (sig == SIG_LIVENESS) {
			for (i = 0; i < servant_count; i++) {
				if (reports[i] == sinfo.si_pid) {
					break;
				} else if (reports[i] == 0) {
					reports[i] = sinfo.si_pid;
					good_servants++;
					break;
				}
			}
		} else if (sig == SIG_TEST) {
		} else if (sig == SIGUSR1) {
			if (exiting)
				continue;
			clock_gettime(CLOCK_MONOTONIC, &t_last_restarted);
			servants_start();
		}

		if (exiting) {
			if (check_all_dead())
				exit(0);
			else
				continue;
		}

		if (quorum_read(good_servants)) {
			DBGPRINT("Enough liveness messages\n");
			if (!decoupled) {
				if (inquisitor_decouple() < 0) {
					servants_kill();
					exiting = 1;
					continue;
				} else {
					decoupled = 1;
				}
			}

			watchdog_tickle();
			clock_gettime(CLOCK_MONOTONIC, &t_last_tickle);
			memset(reports, 0, sizeof(int) * servant_count);
			good_servants = 0;
		}

		clock_gettime(CLOCK_MONOTONIC, &t_now);
		latency = t_now.tv_sec - t_last_tickle.tv_sec;
		if (timeout_watchdog && (latency > timeout_watchdog)) {
			if (!decoupled) {
				/* We're still being watched by our
				 * parent. We don't fence, but exit. */
				cl_log(LOG_ERR, "SBD: Not enough votes to proceed. Aborting start-up.");
				servants_kill();
				exiting = 1;
				continue;
			}
			do_reset();
		}
		if (timeout_watchdog_warn && (latency > timeout_watchdog_warn)) {
			cl_log(LOG_WARNING,
			       "Latency: No liveness for %d s exceeds threshold of %d s (healthy servants: %d)",
			       (int)latency, (int)timeout_watchdog_warn, good_servants);
		}
		
		latency = t_now.tv_sec - t_last_restarted.tv_sec;
		if (servant_restart_interval > 0 
				&& latency > servant_restart_interval) {
			/* Restart all children every hour */
			clock_gettime(CLOCK_MONOTONIC, &t_last_restarted);
			servants_start();
		}
	}
	/* not reached */
	exit(0);
}

int inquisitor(void)
{
	int sig, pid, inquisitor_pid;
	int status;
	sigset_t procmask;
	siginfo_t sinfo;

	DBGPRINT("inquisitor starting\n");

	/* Where's the best place for sysrq init ?*/
	sysrq_init();

	sigemptyset(&procmask);
	sigaddset(&procmask, SIGCHLD);
	sigaddset(&procmask, SIG_LIVENESS);
	sigprocmask(SIG_BLOCK, &procmask, NULL);

	if (check_timeout_inconsistent() == 1) {
		fprintf(stderr, "Timeout settings are different across SBD devices!\n");
		fprintf(stderr, "You have to correct them and re-start SBD again.\n");
		return -1;
	}

	inquisitor_pid = make_daemon();
	if (inquisitor_pid == 0) {
		inquisitor_child();
	} 
	
	/* We're the parent. Wait for a happy signal from our child
	 * before we proceed - we either get "SIG_LIVENESS" when the
	 * inquisitor has completed the first successful round, or
	 * ECHLD when it exits with an error. */

	while (1) {
		sig = sigwaitinfo(&procmask, &sinfo);
		DBGPRINT("get signal %d\n", sig);
		if (sig == SIGCHLD) {
			while ((pid = waitpid(-1, &status, WNOHANG))) {
				if (pid == -1 && errno == ECHILD) {
					break;
				}
				/* We got here because the inquisitor
				 * did not succeed. */
				return -1;
			}
		} else if (sig == SIG_LIVENESS) {
			/* Inquisitor started up properly. */
			return 0;
		} else {
			fprintf(stderr, "Nobody expected the spanish inquisition!\n");
			continue;
		}
	}
	/* not reached */
	return -1;
}

int messenger(const char *name, const char *msg)
{
	int sig = 0;
	pid_t pid = 0;
	int status = 0;
	int servants_finished = 0;
	int successful_delivery = 0;
	sigset_t procmask;
	siginfo_t sinfo;
	struct servants_list_item *s;
	struct slot_msg_arg_t slot_msg_arg = {name, msg};

	sigemptyset(&procmask);
	sigaddset(&procmask, SIGCHLD);
	sigprocmask(SIG_BLOCK, &procmask, NULL);

	for (s = servants_leader; s; s = s->next) {
		s->pid = assign_servant(s->devname, &slot_msg_wrapper, &slot_msg_arg);
	}
	
	while (!(quorum_write(successful_delivery) || 
		(servants_finished == servant_count))) {
		sig = sigwaitinfo(&procmask, &sinfo);
		DBGPRINT("get signal %d\n", sig);
		if (sig == SIGCHLD) {
			while ((pid = waitpid(-1, &status, WNOHANG))) {
				if (pid == -1 && errno == ECHILD) {
					break;
				} else {
					DBGPRINT("process %d finished\n", pid);
					servants_finished++;
					if (WIFEXITED(status)
						&& WEXITSTATUS(status) == 0) {
						DBGPRINT("exit with %d\n",
								WEXITSTATUS(status));
						successful_delivery++;
					}
				}
			}
		}
		DBGPRINT("signal %d handled\n", sig);
	}
	if (quorum_write(successful_delivery)) {
		return 0;
	} else {
		fprintf(stderr, "Message is not delivered via more then a half of devices\n");
		return -1;
	}
}

int dump_headers(void)
{
	int rc = 0;
	struct servants_list_item *s = servants_leader;
	int devfd;

	for (s = servants_leader; s; s = s->next) {
		fprintf(stdout, "==Dumping header on disk %s\n", s->devname);
		devfd = open_device(s->devname);
		if (devfd == -1)
			return -1;
		rc = header_dump(devfd);
		close(devfd);
		if (rc == -1)
			return rc;
		fprintf(stdout, "==Header on disk %s is dumped\n", s->devname);
	}
	return rc;
}

int main(int argc, char **argv, char **envp)
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

	while ((c = getopt(argc, argv, "DRWhvw:d:n:1:2:3:4:5:t:")) != -1) {
		switch (c) {
		case 'D':
			/* Ignore for historical reasons */
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
		case 't':
			servant_restart_interval = atoi(optarg);
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
	
	if (servant_count < 1 || servant_count > 3) {
		fprintf(stderr, "You must specify 1 to 3 devices via the -d option.\n");
		exit_status = -1;
		goto out;
	}

	/* There must at least be one command following the options: */
	if ((argc - optind) < 1) {
		fprintf(stderr, "Not enough arguments.\n");
		exit_status = -1;
		goto out;
	}

	if (init_set_proc_title(argc, argv, envp) < 0) {
		fprintf(stderr, "Allocation of proc title failed.");
		exit(1);
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
