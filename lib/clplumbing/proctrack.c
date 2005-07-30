/* $Id: proctrack.c,v 1.21 2005/07/30 02:33:08 alan Exp $ */
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

#include <portability.h>
#include <errno.h>
#include <sys/wait.h>
#include <heartbeat.h>
#include <sys/types.h>
#include <signal.h>
#include <clplumbing/proctrack.h>
#include <clplumbing/cl_log.h>
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
			,	"Exiting %s process %d returned rc %d."
			,	type, pid, exitcode);
		}else if (deathbysig) {
			/*
			 * Processes being killed isn't an error if
			 * we're only logging because of debugging.
			 */
			cl_log((debugreporting ? LOG_DEBUG : LOG_ERR)
			,	"Exiting %s process %d killed by signal %d."
			,	type, pid, signo);
		}else{
			cl_log(LOG_ERR, "Exiting %s process %d went away"
			" strangely (!)"
			,	type, pid);
		}
	}
#ifdef WCOREDUMP
	if (didcoredump) {
		/* We report ALL core dumps without exception */
		cl_log(LOG_ERR, "Exiting %s process %d dumped core"
		,	type, pid);
	}
#endif

	if (p) {
		if (p->timerid > 0) {
			g_source_remove(p->timerid);
			p->timerid = 0;
		}
		/*
		 * From clplumbing/proctrack.h:
		 * (ProcTrack* p, int status, int signo, int exitcode
		 * ,	int waslogged);
		 */
		p->ops->procdied(p, status, signo, exitcode,  doreport);
		if (p->privatedata) {
			/* They may have forgotten to free something... */
			cl_log(LOG_ERR, "Exiting %s process %d did not"
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

static gboolean
TrackedProcTimeoutFunction(gpointer p)
{
	/* This is safe - Pids are relative small ints */
	pid_t		pid = POINTER_TO_SIZE_T(p); /*pointer cast as int*/
	ProcTrack*	pinfo;
	int		nsig;
	long		mstimeout;

	pinfo = GetProcInfo(pid);
	
	if (pinfo == NULL || pinfo->timeoutseq < 0
	||	pinfo->killinfo == NULL) {
		return FALSE;
	}

	pinfo->timerid = 0;
	nsig = pinfo->killinfo[pinfo->timeoutseq].signalno;
	mstimeout = pinfo->killinfo[pinfo->timeoutseq].mstimeout;

	if (nsig == 0) {
		return FALSE;
	}
	cl_log(LOG_WARNING, "%s process (PID %d) timed out"
	".  Killing with signal %d."
	,	pinfo->ops->proctype(pinfo), (int)pid, nsig);

	if (kill(pid, nsig) < 0) {
		if (errno == EEXIST) {
			/* No point in trying this again ;-) */
			return FALSE;
		}else{
			cl_perror("kill(%d,%d) failed"
			,	pid, nsig);
		}
	}
	pinfo->timerid = Gmain_timeout_add(mstimeout
	,	TrackedProcTimeoutFunction
	,	GINT_TO_POINTER(pid));
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
