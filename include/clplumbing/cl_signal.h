/*
 * cl_signal.h: signal handling routines to be used by Linux-HA programmes
 *
 * Copyright (C) 2002 Horms <horms@verge.net.au>
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
#ifndef _CL_SIGNAL_H
#define _CL_SIGNAL_H

#include <stdio.h>
#include <signal.h>
#include <sys/signal.h>

typedef struct {
	int     sig;
	void    (*handler)(int);
	int     interrupt;
} cl_signal_mode_t;

#define CL_SIGNAL(_sig, _handler) \
	cl_signal_set_simple_handler((_sig), (_handler), NULL)
#if HAVE_SIGIGNORE
#define CL_IGNORE_SIG(_sig) sigignore((_sig))
#else
#define CL_IGNORE_SIG(_sig) CL_SIGNAL((_sig), SIG_IGN)
#endif
#define CL_DEFAULT_SIG(_sig) CL_SIGNAL((_sig), SIG_DFL)

#define CL_SIGINTERRUPT(_sig, _flag) siginterrupt((_sig), (_flag))

#define CL_SIGACTION(_signum, _act, _oldact) \
	sigaction((_signum), (_act), (_oldact))
#define CL_SIGPROCMASK(_how, _set, _oldset) \
	cl_signal_block_set((_how), (_set), (_oldset))
#define CL_SIGPENDING(_set) sigpending(_set)
#define CL_SIGSUSPEND(_mask) sigsuspend(_mask)

#define CL_SIGEMPTYSET(_set) sigemptyset(_set)
#define CL_SIGFILLSET(_set) sigfillset(_set)
#define CL_SIGADDSET(_set, _signum) sigaddset((_set), (_signum))
#define CL_SIGDELSET(_set, _signum) sigdelset((_set), (_signum))
#define CL_SIGISMEMBER(_set, _signum) sigmember((_set), (_signum))

#define CL_KILL(_pid, _sig) kill((_pid), (_sig))

#define CL_PID_EXISTS(_pid) ( CL_KILL((_pid), 0) >= 0 || errno != ESRCH )

int
cl_signal_set_handler(int sig, void (*handler)(int), sigset_t *mask
,	int flags, struct sigaction *oldact);

int
cl_signal_set_simple_handler(int sig, void (*handler)(int)
,	struct sigaction *oldact);

int
cl_signal_set_action(int sig, void (*action)(int, siginfo_t *, void *)
,	sigset_t *mask, int flags, struct sigaction *oldact);

int
cl_signal_set_simple_action(int sig, void (*action)(int, siginfo_t *, void *)
,	struct sigaction *oldact);

int
cl_signal_set_interrupt(int sig, int flag);

int
cl_signal_block(int how, int signal, sigset_t *oldset);

int
cl_signal_block_set(int how, const sigset_t *set, sigset_t *oldset);

int
cl_signal_set_handler_mode(const cl_signal_mode_t *mode, sigset_t *set);


#endif /* _CL_SIGNAL_H */
