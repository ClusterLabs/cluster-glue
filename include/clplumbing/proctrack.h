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

#ifndef _PROCTRACK_H
#	define _PROCTRACK_H
#include <sys/types.h>
#include <sys/times.h>

/*
 * We track processes, mainly so we can do something appropriate
 * when they die, and find processes should we need to kill them...
 */

typedef struct _ProcTrack	ProcTrack;
typedef struct _ProcTrack_ops	ProcTrack_ops;
typedef enum _ProcTrackLogType	ProcTrackLogType;

/*
 * The levels of logging possible for our process
 */
enum _ProcTrackLogType {
	PT_LOGNONE = 2,		/* Exits never automatically logged */
	PT_LOGNORMAL,		/* Automatically log abnormal exits */
	PT_LOGVERBOSE,		/* Automatically log every exit */
};

struct _ProcTrack {
	pid_t			pid;
	int			isapgrp;
	ProcTrackLogType	loglevel;
	void *			privatedata;
	ProcTrack_ops*		ops;

	clock_t			startticks;
	time_t			starttime;
};

/*
 * The set of operations to perform on our tracked processes.
 */
struct _ProcTrack_ops {

	/* Called when a process dies */
	void 	(*procdied)		
		(ProcTrack* p, int status, int signo, int exitcode
		,	int waslogged);

	/* Called when a process registers */
	void	(*procregistered)
		(ProcTrack*p);

	/* Returns a "name" for a process (for messages) */
	/* (must be copied, because it may be a static value) */
	const char *
		(*proctype)
		(ProcTrack* p);
};

/* A function for calling by the process table iterator */
typedef void (*ProcTrackFun) (ProcTrack* p, void * data);

/* Call this function to activate the procdied member function */
/* Returns TRUE if 'pid' was registered */
int ReportProcHasDied(int pid, int status);

/* Create/Log a new tracked process */
void NewTrackedProc(pid_t pid, int isapgrp, ProcTrackLogType loglevel
,	void * privatedata , ProcTrack_ops* ops);

/* Return information associated with the given PID (or NULL) */
ProcTrack* GetProcInfo(pid_t pid);

/*
 * Iterate over the set of tracked processes.
 * If proctype is NULL, then walk through them all, otherwise only those
 * of the given type ("f")
 */
void	ForEachProc(ProcTrack_ops* proctype, ProcTrackFun f, void * data);

void	DisableProcLogging(void);	/* Useful for shutdowns */
void	EnableProcLogging(void);
#endif
