/*
 * Basic Core dump control functions.
 *
 * Author:	Alan Robertson
 *
 * Copyright (C) 2004 IBM Corporation
 *
 * This software licensed under the GNU LGPL.
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
#include <sys/time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <fcntl.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_SYS_PRCTL_H
#	include <sys/prctl.h>
#endif
#include <clplumbing/coredumps.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/uids.h>
#include <clplumbing/cl_signal.h>

static char *	coreroot = NULL;

/* Set the root directory of our core directory hierarchy */
int
cl_set_corerootdir(const char * dir)
{
	if (dir == NULL || *dir != '/') {
		cl_perror("Invalid dir in cl_set_corerootdir() [%s]"
		,	dir ? dir : "<NULL>");
		errno = EINVAL;
		return -1;
	}
	if (coreroot != NULL) {
		free(coreroot);
		coreroot = NULL;
	}
	coreroot = strdup(dir);
	if (coreroot == NULL) {
		return -1;
	}
	return 0;
}

/*
 * Change directory to the directory our core file needs to go in
 * Call after you establish the userid you're running under.
 */
int
cl_cdtocoredir(void)
{
	const char *	dir = coreroot;
	int		rc;
	struct passwd*	pwent;
	
	if (dir == NULL) {
		dir = HA_COREDIR;
	}
	if ((rc=chdir(dir)) < 0) {
		int errsave = errno;
		cl_perror("Cannot chdir to [%s]", dir);
		errno = errsave;
		return rc;
	}
	pwent = getpwuid(getuid());
	if (pwent == NULL) {
		int errsave = errno;
		cl_perror("Cannot get name for uid [%d]", getuid());
		errno = errsave;
		return -1;
	}
	if ((rc=chdir(pwent->pw_name)) < 0) {
		int errsave = errno;
		cl_perror("Cannot chdir to [%s/%s]", dir, pwent->pw_name);
		errno = errsave;
	}
	return rc;
}

#define	CHECKED_KERNEL_CORE_ENV		"_PROC_SYS_CORE_CHECKED_"
#define	PROC_SYS_KERNEL_CORE_PID	"/proc/sys/kernel/core_uses_pid"
#define	PROC_SYS_KERNEL_CORE_PAT	"/proc/sys/kernel/core_pattern"

static void cl_coredump_signal_handler(int nsig);

/*
 *	core_uses_pid():
 *
 *	returns {-1, 0, 1}
 *		-1:	not supported
 *		 0:	supported and disabled
 *		 1:	supported and enabled
 */
#define BUF_MAX 256
static int
core_uses_pid(void)
{
	const char *	uses_pid_pathnames[] = {PROC_SYS_KERNEL_CORE_PID};
	const char *	corepats_pathnames[] = {PROC_SYS_KERNEL_CORE_PAT};
	const char *	goodpats [] = {"%t", "%p"};
	int		j;


	for (j=0; j < DIMOF(corepats_pathnames); ++j) {
		int	fd;
		char	buf[BUF_MAX];
		int	rc;
		int	k;

		if ((fd = open(corepats_pathnames[j], O_RDONLY)) < 0) {
			continue;
		}
		
		memset(buf, 0, BUF_MAX);
		rc = read(fd, buf, BUF_MAX - 1); /* Ensure it is always NULL terminated */
		close(fd);
		
		for (k=0; rc > 0 && k < DIMOF(goodpats); ++k) {
			if (strstr(buf, goodpats[k]) != NULL) {
				return 1;
			}
		}

		break;
	}
	for (j=0; j < DIMOF(uses_pid_pathnames); ++j) {
		int	fd;
		char	buf[2];
		int	rc;
		if ((fd = open(uses_pid_pathnames[j], O_RDONLY)) < 0) {
			continue;
		}
		rc = read(fd, buf, sizeof(buf));
		close(fd);
		if (rc < 1) {
			continue;
		}
		return (buf[0] == '1');
	}
	setenv(CHECKED_KERNEL_CORE_ENV, "1", TRUE);
	return -1;
}

/* Enable/disable core dumps for ourselves and our child processes */
int
cl_enable_coredumps(int doenable)
{
	int		rc;
	struct rlimit	rlim;

	if ((rc = getrlimit(RLIMIT_CORE, &rlim)) < 0) {
		int errsave = errno;
		cl_perror("Cannot get current core limit value.");
		errno = errsave;
		return rc;
	}
	if (rlim.rlim_max == 0 && geteuid() == 0) {
		rlim.rlim_max = RLIM_INFINITY;
	}

	rlim.rlim_cur = (doenable ? rlim.rlim_max : 0);

	if (doenable && rlim.rlim_max == 0) {
		cl_log(LOG_WARNING
		,	"Not possible to enable core dumps (rlim_max is 0)");
	}

	if ((rc = setrlimit(RLIMIT_CORE, &rlim)) < 0) {
		int errsave = errno;
		cl_perror("Unable to %s core dumps"
		,	 doenable ? "enable" : "disable");
		errno = errsave;
		return rc;
	}
	if (getenv(CHECKED_KERNEL_CORE_ENV) == NULL
	&&	core_uses_pid() == 0) {
		cl_log(LOG_WARNING
		,	"Core dumps could be lost if multiple dumps occur.");
		cl_log(LOG_WARNING
		,	"Consider setting non-default value in %s"
		" (or equivalent) for maximum supportability", PROC_SYS_KERNEL_CORE_PAT);
		cl_log(LOG_WARNING
		,	"Consider setting %s (or equivalent) to"
		" 1 for maximum supportability", PROC_SYS_KERNEL_CORE_PID);
	}
	return 0;
}

/*
 *   SIGQUIT      3        Core    Quit from keyboard
 *   SIGILL       4        Core    Illegal Instruction
 *   SIGABRT      6        Core    Abort signal from abort(3)
 *   SIGFPE       8        Core    Floating point exception
 *   SIGSEGV      11       Core    Invalid memory reference
 *   SIGBUS    10,7,10     Core    Bus error (bad memory access)
 *   SIGSYS     2,-,12     Core    Bad argument to routine (SVID)
 *   SIGTRAP      5        Core    Trace/breakpoint trap
 *   SIGXCPU   24,24,30    Core    CPU time limit exceeded (4.2 BSD)
 *   SIGXFSZ   25,25,31    Core    File size limit exceeded (4.2 BSD)
 */

/*
 * This function exists to allow security-sensitive programs
 * to safely take core dumps.  Such programs can't can't call
 * cl_untaint_coredumps() alone - because it might cause a
 * leak of confidential information - as information which should
 * only be known by the "high-privilege" user id will be written
 * into a core dump which is readable by the "low-privilege" user id.
 * This is a bad thing.
 *
 * This function causes this program to call a special signal handler
 * on receipt of any core dumping signal.  This handler then does
 * the following four things on receipt of a core dumping signal:
 *
 *  1)	Set privileges to "maximum" on receipt of a signal
 *  2)	"untaint" themselves with regard to core dumping
 *  3)	set SIG_DFLT for the received signal
 *  4)	Kill themselves with the received core-dumping signal
 *
 * Any process *could* do this to get core dumps, but if your stack
 * is screwed up, then the signal handler might not work.
 * If you're core dumping because of a stack overflow, it certainly won't work.
 *
 * On the other hand, this function may work on some OSes that don't support
 * prctl(2).  This is an untested theory at this time...
 */
void
cl_set_all_coredump_signal_handlers(void)
{
	static const int coresigs [] = {SIGQUIT, SIGILL, SIGABRT, SIGFPE, SIGSEGV
#ifdef SIGBUS
,	SIGBUS
#endif
#ifdef SIGSYS
,	SIGSYS
#endif
#ifdef SIGTRAP
,	SIGTRAP
#endif
#ifdef SIGXCPU
,	SIGXCPU
#endif
#ifdef SIGXFSZ
,	SIGXFSZ
#endif
};
	int	j;

	for (j=0; j < DIMOF(coresigs); ++j) {
		cl_set_coredump_signal_handler(coresigs[j]);
	}
}

/*
 * See note above about why using this function directly is sometimes
 * a bad idea, and you might need to use cl_set_all_coredump_signal_handlers()
 * instead.
 */
void
cl_untaint_coredumps(void)
{
#if defined(PR_SET_DUMPABLE)
	prctl(PR_SET_DUMPABLE, (unsigned long)TRUE, 0UL, 0UL, 0UL);
#endif
}
static void
cl_coredump_signal_handler(int nsig)
{
	return_to_orig_privs();
	if (geteuid() == 0) {
		/* Put ALL privileges back to root... */
		if (setuid(0) < 0) {
			cl_perror("cl_coredump_signal_handler: unable to setuid(0)");
		}
	}
	cl_untaint_coredumps();	/* Do the best we know how to do... */
	CL_SIGNAL(nsig, SIG_DFL);
	kill(getpid(), nsig);
}

void
cl_set_coredump_signal_handler(int nsig)
{
	CL_SIGNAL(nsig, cl_coredump_signal_handler);
}
