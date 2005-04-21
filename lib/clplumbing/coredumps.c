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

#include <portability.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#include <pwd.h>
#ifdef HAVE_SYS_PRCTL_H
#	include <sys/prctl.h>
#endif
#include <clplumbing/cl_malloc.h>
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
		cl_free(coreroot);
		coreroot = NULL;
	}
	coreroot = cl_strdup(dir);
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

static void cl_coredump_signal_handler(int nsig);

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
	return 0;
}

 /*
  *   SIGQUIT       3       Core    Quit from keyboard
  *   SIGILL        4       Core    Illegal Instruction
  *   SIGABRT       6       Core    Abort signal from abort(3)
  *   SIGFPE        8       Core    Floating point exception
  *   SIGSEGV      11       Core    Invalid memory reference
  *   SIGBUS    10,7,10     Core    Bus error (bad memory access)
  *   SIGSYS     2,-,12     Core    Bad argument to routine (SVID)
  *   SIGTRAP      5        Core    Trace/breakpoint trap
  *   SIGXCPU     24,24,30    Core    CPU time limit exceeded (4.2 BSD)
  *   SIGXFSZ     25,25,31    Core    File size limit exceeded (4.2 BSD)

  */
void
cl_set_all_coredump_signal_handlers()
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
