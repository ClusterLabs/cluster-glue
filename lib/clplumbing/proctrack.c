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
#include <sys/wait.h>
#include <glib.h>
#include <heartbeat.h>
#include <clplumbing/proctrack.h>


static int		LoggingIsEnabled = 1;
static GHashTable*	ProcessTable = NULL;
static void		InitProcTable(void);
static void		ForEachProcHelper(gpointer key, gpointer value
,				void * helper);

static void
InitProcTable()
{
	(void)_heartbeat_h_Id;
	(void)_ha_msg_h_Id;
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
	p->isapgrp = pid;
	p->loglevel = loglevel;
	p->privatedata = privatedata;
	p->ops = ops;
	p->startticks = time_longclock();
	p->starttime = time(NULL);

	g_hash_table_insert(ProcessTable, GINT_TO_POINTER(pid), p);
	if (ANYDEBUG) {
		ha_log(LOG_DEBUG, "Creating tracked %s process %d"
		,	ops->proctype(p), pid);
	}

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
		if (ANYDEBUG) {
			ha_log(LOG_DEBUG
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
#ifdef WCOREDUMP
	if (WCOREDUMP(status)) {
		/* Force a report on all core dumping processes */
		didcoredump=1;
		doreport=1;
	}
#endif
	switch(level) {
		case PT_LOGVERBOSE:	doreport=1;
					break;

		case PT_LOGNONE:	doreport = 0;
					break;
		default:
	}

	if (!LoggingIsEnabled) {
		doreport = 0;
	}
	if (ANYDEBUG && !doreport) {
		doreport = 1;
		debugreporting = 1;
	}

	if (doreport) {
		if (deathbyexit) {
			ha_log((exitcode == 0 ? LOG_INFO :  LOG_WARNING)
			,	"Exiting %s process %d returned rc %d."
			,	type, pid, exitcode);
		}else if (deathbysig) {
			/*
			 * Processes being killed isn't an error if
			 * we're only logging because of debugging.
			 */
			ha_log((debugreporting ? LOG_DEBUG : LOG_ERR)
			,	"Exiting %s process %d killed by signal %d."
			,	type, pid, signo);
		}else{
			ha_log(LOG_ERR
			,	"Exiting %s process %d went away"
			" strangely (!)"
			,	type, pid);
		}
	}
#ifdef WCOREDUMP
	if (didcoredump) {
		/* We report ALL core dumps without exception */
		ha_log(LOG_ERR
		,	"Exiting %s process %d dumped core"
		,	type, pid);
	}
#endif

	if (p) {
		p->ops->procdied(p, status, exitcode, signo, doreport);
		if (p->privatedata) {
			/* They may have forgotten to free something... */
			ha_log(LOG_ERR
			,	"Exiting %s process %d did not"
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
