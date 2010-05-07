/*
 * Process tracking object.
 *
 * Copyright (c) 2002 International Business Machines
 * Author:	Alan Robertson <alanr@unix.sh>
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
#include <errno.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>
#include <clplumbing/proctrack.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/uids.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/Gmain_timeout.h>

#define	DEBUGPROCTRACK	debugproctrack


int			debugproctrack = 0;
static int		LoggingIsEnabled = 1;
static GHashTable*	ProcessTable = NULL;
static void		InitProcTable(void);
static void		ForEachProcHelper(gpointer key, gpointer value
,				void * helper);
static gboolean TrackedProcTimeoutFunction(gpointer p);

static void
InitProcTable()
{
	if (ProcessTable) {
		return;
	}

	ProcessTable = g_hash_table_new(g_direct_hash, g_direct_equal);
}

/* Create/Log a new tracked process */
void
NewTrackedProc(pid_t pid, int isapgrp, ProcTrackLogType loglevel
,	void * privatedata, ProcTrack_ops* ops)
{
	ProcTrack*	p = g_new(ProcTrack, 1);

	InitProcTable();
	p->pid = pid;
	p->isapgrp = isapgrp;
	p->loglevel = loglevel;
	p->privatedata = privatedata;
	p->ops = ops;
	p->startticks = time_longclock();
	p->starttime = time(NULL);
	p->timerid = 0;
	p->timeoutseq = -1;
	p->killinfo = NULL;

	g_hash_table_insert(ProcessTable, GINT_TO_POINTER(pid), p);

	/* Tell them that someone registered a process */
	if (p->ops->procregistered) {
		p->ops->procregistered(p);
	}
}

static struct signal_info_s {
	int		signo;
	const char *	sigdefine;
	const char*	sigwords;
} signal_info [] = {

#ifdef SIGHUP
	{SIGHUP,	"SIGHUP",		"Hangup"},
#endif
#ifdef SIGINT
	{SIGINT,	"SIGINT",		"Interrupt"},
#endif
#ifdef SIGQUIT
	{SIGQUIT,	"SIGQUIT",		"Quit"},
#endif
#ifdef SIGILL
	{SIGILL,	"SIGILL",		"Illegal instruction"},
#endif
#ifdef SIGTRAP
	{SIGTRAP,	"SIGTRAP",		"Trace"},
#endif
#ifdef SIGABRT
	{SIGABRT,	"SIGABRT",		"Abort"},
#endif
#ifdef SIGIOT
	{SIGIOT,	"SIGIOT",		"IOT trap"},
#endif
#ifdef SIGBUS
	{SIGBUS,	"SIGBUS",		"BUS error"},
#endif
#ifdef SIGFPE
	{SIGFPE,	"SIGFPE",		"Floating-point exception"},
#endif
#ifdef SIGKILL
	{SIGKILL,	"SIGKILL",		"Kill, unblockable"},
#endif
#ifdef SIGUSR1
	{SIGUSR1,	"SIGUSR1",		"User-defined signal 1"},
#endif
#ifdef SIGSEGV
	{SIGSEGV,	"SIGSEGV",		"Segmentation violation"},
#endif
#ifdef SIGUSR2
	{SIGUSR2,	"SIGUSR2",		"User-defined signal 2"},
#endif
#ifdef SIGPIPE
	{SIGPIPE,	"SIGPIPE",		"Broken pipe (POSIX)"},
#endif
#ifdef SIGALRM
	{SIGALRM,	"SIGALRM",		"Alarm clock (POSIX)"},
#endif
#ifdef SIGTERM
	{SIGTERM,	"SIGTERM",		"Termination (ANSI)"},
#endif
#ifdef SIGSTKFLT
	{SIGSTKFLT,	"SIGSTKFLT",		"Stack fault"},
#endif
#ifdef SIGCHLD
	{SIGCHLD,	"SIGCHLD",		"Child status has changed"},
#endif
#ifdef SIGCLD
	{SIGCLD,	"SIGCLD	",		"Child status has changed"},
#endif
#ifdef SIGCONT
	{SIGCONT,	"SIGCONT",		"Continue"},
#endif
#ifdef SIGSTOP
	{SIGSTOP,	"SIGSTOP",		"Stop, unblockable"},
#endif
#ifdef SIGTSTP
	{SIGTSTP,	"SIGTSTP",		"Keyboard stop"},
#endif
#ifdef SIGTTIN
	{SIGTTIN,	"SIGTTIN",		"Background read from tty"},
#endif
#ifdef SIGTTOU
	{SIGTTOU,	"SIGTTOU",		"Background write to tty"},
#endif
#ifdef SIGURG
	{SIGURG,	"SIGURG	",		"Urgent condition on socket"},
#endif
#ifdef SIGXCPU
	{SIGXCPU,	"SIGXCPU",		"CPU limit exceeded"},
#endif
#ifdef SIGXFSZ
	{SIGXFSZ,	"SIGXFSZ",		"File size limit exceeded"},
#endif
#ifdef SIGVTALRM
	{SIGVTALRM,	"SIGVTALRM",		"Virtual alarm clock"},
#endif
#ifdef SIGPROF
	{SIGPROF,	"SIGPROF",		"Profiling alarm clock"},
#endif
#ifdef SIGWINCH
	{SIGWINCH,	"SIGWINCH",		"Window size change"},
#endif
#ifdef SIGPOLL
	{SIGPOLL,	"SIGPOLL",		"Pollable event occurred"},
#endif
#ifdef SIGIO
	{SIGIO,		"SIGIO",		"I/O now possible"},
#endif
#ifdef SIGPWR
	{SIGPWR,	"SIGPWR",		"Power failure restart"},
#endif
#ifdef SIGSYS
	{SIGSYS,	"SIGSYS",		"Bad system call"},
#endif
};
static const char *
signal_name(int signo, const char ** sigdescription)
{
	int	j;
	for (j=0; j < DIMOF(signal_info); ++j) {
		if (signal_info[j].signo == signo) {
			if (sigdescription) {
				*sigdescription = signal_info[j].sigwords;
			}
			return signal_info[j].sigdefine;
		}
	}
	if (sigdescription) {
		*sigdescription = NULL;
	}
	return NULL;
}

/* returns TRUE if 'pid' was registered */
int
ReportProcHasDied(int pid, int status)
{
	ProcTrack*		p;
	int			signo=0;
	int			deathbyexit=0;
	int			deathbysig=0;
	int			exitcode=0;
	int			doreport = 0;
	int			debugreporting = 0;
	const char *		type;
	ProcTrackLogType	level;
#ifdef WCOREDUMP
	int		didcoredump = 0;
#endif
	if ((p = GetProcInfo(pid)) == NULL) {
		if (DEBUGPROCTRACK) {
			cl_log(LOG_DEBUG
			,	"Process %d died (%d) but is not tracked."
			,	pid, status);
		}
		type = "untracked process";
		level = PT_LOGNONE;
	}else{
		type = p->ops->proctype(p);
		level = p->loglevel;
	}

	if (WIFEXITED(status)) {
		deathbyexit=1;
		exitcode = WEXITSTATUS(status);
	}else if (WIFSIGNALED(status)) {
		deathbysig=1;
		signo = WTERMSIG(status);
		doreport=1;
	}
	switch(level) {
		case PT_LOGVERBOSE:	doreport=1;
					break;

		case PT_LOGNONE:	doreport = 0;
					break;

		case PT_LOGNORMAL:	break;
	}

	if (!LoggingIsEnabled) {
		doreport = 0;
	}
#ifdef WCOREDUMP
	if (WCOREDUMP(status)) {
		/* Force a report on all core dumping processes */
		didcoredump=1;
		doreport=1;
	}
#endif
	if (DEBUGPROCTRACK && !doreport) {
		doreport = 1;
		debugreporting = 1;
	}

	if (doreport) {
		if (deathbyexit) {
			cl_log((exitcode == 0 ? LOG_INFO : LOG_WARNING)
			,	"Managed %s process %d exited with return code %d."
			,	type, pid, exitcode);
		}else if (deathbysig) {
			const char *	signame = NULL;
			const char *	sigwords = NULL;
			int		logtype;
			signame = signal_name(signo, &sigwords);
			logtype = (debugreporting ? LOG_INFO : LOG_WARNING);
			/*
			 * Processes being killed isn't an error if
			 * we're only logging because of debugging.
			 */
			if (signame && sigwords) {
				cl_log(logtype
				,	"Managed %s process %d killed by"
				" signal %d [%s - %s]."
				,	type, pid, signo
				,	signame, sigwords);
			}else{
				cl_log(logtype
				,	"Managed %s process %d killed by signal %d."
				,	type, pid, signo);
			}
		}else{
			cl_log(LOG_ERR, "Managed %s process %d went away"
			" strangely (!)"
			,	type, pid);
		}
	}
#ifdef WCOREDUMP
	if (didcoredump) {
		/* We report ALL core dumps without exception */
		cl_log(LOG_ERR, "Managed %s process %d dumped core"
		,	type, pid);
	}
#endif

	if (p) {
		RemoveTrackedProcTimeouts(pid);
		/*
		 * From clplumbing/proctrack.h:
		 * (ProcTrack* p, int status, int signo, int exitcode
		 * ,	int waslogged);
		 */
		p->ops->procdied(p, status, signo, exitcode,  doreport);
		if (p->privatedata) {
			/* They may have forgotten to free something... */
			cl_log(LOG_ERR, "Managed %s process %d did not"
			" clean up private data!"
			,	type, pid);
		}
		g_hash_table_remove(ProcessTable, GINT_TO_POINTER(pid));
		g_free(p);
	}

	return doreport;
}

/* Return information associated with the given PID (or NULL) */
ProcTrack*
GetProcInfo(pid_t pid)
{
	return (ProcessTable
	?	g_hash_table_lookup(ProcessTable, GINT_TO_POINTER(pid))
	:	NULL);
}

/* "info" is 0-terminated (terminated by a 0 signal) */
int
SetTrackedProcTimeouts(pid_t pid, ProcTrackKillInfo* info)
{
	long		mstimeout;
	ProcTrack*	pinfo;
	pinfo = GetProcInfo(pid);
	
	if (pinfo == NULL) {
		return 0;
	}

	pinfo->timeoutseq = 0;
	pinfo->killinfo = info;
	mstimeout = pinfo->killinfo[0].mstimeout;
	pinfo->timerid = Gmain_timeout_add(mstimeout
	,	TrackedProcTimeoutFunction
	,	GINT_TO_POINTER(pid));
	return pinfo->timerid;
}

void
RemoveTrackedProcTimeouts(pid_t pid)
{
	ProcTrack*	pinfo;
	pinfo = GetProcInfo(pid);
	
	if (pinfo == NULL) {
		return;
	}

	if (pinfo->killinfo && pinfo->timerid) {
		Gmain_timeout_remove(pinfo->timerid);
	}
	pinfo->killinfo = NULL;
	pinfo->timerid = 0;
}

static gboolean
TrackedProcTimeoutFunction(gpointer p)
{
	/* This is safe - Pids are relatively small ints */
	pid_t		pid = POINTER_TO_SIZE_T(p); /*pointer cast as int*/
	ProcTrack*	pinfo;
	int		nsig;
	long		mstimeout;
	int		hadprivs;

	pinfo = GetProcInfo(pid);
	
	if (pinfo == NULL) {
		cl_log(LOG_ERR, "%s: bad pinfo in call (pid %d)", __FUNCTION__, pid);
		return FALSE;
	}
	if (pinfo->timeoutseq < 0 || pinfo->killinfo == NULL) {
		cl_log(LOG_ERR
		,	 "%s: bad call (pid %d): killinfo (%d, 0x%lx)"
		,	__FUNCTION__, pid
		,	pinfo->timeoutseq
		,	(unsigned long)POINTER_TO_SIZE_T(pinfo->killinfo));
		return FALSE;
	}

	pinfo->timerid = 0;
	nsig = pinfo->killinfo[pinfo->timeoutseq].signalno;

	if (nsig == 0) {
		if (CL_PID_EXISTS(pid)) {
			cl_log(LOG_ERR
			,	"%s: %s process (PID %d) will not die!"
			,	__FUNCTION__
			,	pinfo->ops->proctype(pinfo)
			,	(int)pid);
		}
		return FALSE;
	}
	pinfo->timeoutseq++;
	cl_log(LOG_WARNING, "%s process (PID %d) timed out (try %d)"
	".  Killing with signal %s (%d)."
	,	pinfo->ops->proctype(pinfo), (int)pid
	,	pinfo->timeoutseq
	,	signal_name(nsig, NULL)
	,	nsig);

	if (pinfo->isapgrp && nsig > 0) {
		pid = -pid;
	}

	if (!(hadprivs = cl_have_full_privs())) {
		return_to_orig_privs();
	}
	if (kill(pid, nsig) < 0) {
		if (errno == ESRCH) {
			/* Mission accomplished! */
		cl_log(LOG_INFO, "%s process (PID %d) died before killing (try %d)"
		,	pinfo->ops->proctype(pinfo), (int)pid
		,	pinfo->timeoutseq);
			return FALSE;
		}else{
			cl_perror("%s: kill(%d,%d) failed"
			,	__FUNCTION__, pid, nsig);
		}
	}
	if (!hadprivs) {
		return_to_dropped_privs();
	}
	mstimeout = pinfo->killinfo[pinfo->timeoutseq].mstimeout;
	pinfo->timerid = Gmain_timeout_add(mstimeout
	,	TrackedProcTimeoutFunction
	,	p);
	if (pinfo->timerid <= 0) {
		cl_log(LOG_ERR, "%s: Could not add new kill timer [%u]"
		,	__FUNCTION__, pinfo->timerid);
		kill(pid, SIGKILL);
	}
	if (debugproctrack) {
		cl_log(LOG_DEBUG, "%s process (PID %d) scheduled to be killed again"
		" (try %d) in %ld ms [timerid %u]"
		,	pinfo->ops->proctype(pinfo), (int)pid
		,	pinfo->timeoutseq
		,	mstimeout
		,	pinfo->timerid);
	}
	return FALSE;
}

/* Helper struct to allow us to stuff 3 args into one ;-) */
struct prochelper {
	ProcTrack_ops*	type;
	ProcTrackFun	fun;
	void*		data;
};

/* Helper function to call user's function with right args... */
static void
ForEachProcHelper(gpointer key, gpointer value, void * helper)
{
	ProcTrack*		p = value;
	struct prochelper*	ph = helper;

	if (ph->type != NULL && ph->type != p->ops) {
		return;
	}

	ph->fun(p, ph->data);
}
/*
 * Iterate over the set of tracked processes.
 * If proctype is NULL, then walk through them all, otherwise only those
 * of the given type.
 */
void
ForEachProc(ProcTrack_ops* proctype, ProcTrackFun f, void * data)
{
	struct prochelper ph;
	
	InitProcTable();
	ph.fun = f;
	ph.type = proctype;
	ph.data = data;
	g_hash_table_foreach(ProcessTable, ForEachProcHelper, &ph);
}

void
DisableProcLogging()
{
	LoggingIsEnabled = 0;
}

void
EnableProcLogging()
{
	LoggingIsEnabled = 1;
}
