/*
 * cl_signal.c: signal handling routines to be used by Linux-HA programmes
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

#include <lha_internal.h>
#include <string.h>
#include <errno.h>

#include <clplumbing/cl_signal.h>
#include <clplumbing/cl_log.h>


int
cl_signal_set_handler(int sig, void (*handler)(int), sigset_t *mask
,	int flags, struct sigaction *oldact)
{
	struct sigaction sa;

	sa.sa_handler = handler;
	sa.sa_mask = *mask;
	sa.sa_flags = flags;

	if (sigaction(sig, &sa, oldact) < 0) {
		cl_perror("cl_signal_set_handler(): sigaction()");
		return(-1);
	}

	return(0);
}


int
cl_signal_set_simple_handler(int sig, void (*handler)(int)
,	struct sigaction *oldact)
{
	struct sigaction sa;
	sigset_t mask;

	if(sigemptyset(&mask) < 0) {
		cl_perror("cl_signal_set_simple_handler(): "
			"sigemptyset()");
		return(-1);
	}

	sa.sa_handler = handler;
	sa.sa_mask = mask;
	sa.sa_flags = 0;

	if(sigaction(sig, &sa, oldact) < 0) {
		cl_perror("cl_signal_set_simple_handler()"
		": sigaction()");
		return(-1);
	}

	return(0);
}


int
cl_signal_set_action(int sig, void (*action)(int, siginfo_t *, void *)
,	sigset_t *mask, int flags, struct sigaction *oldact)
{
	struct sigaction sa;

	sa.sa_sigaction = action;
	sa.sa_mask = *mask;
	sa.sa_flags = flags;

	if(sigaction(sig, &sa, oldact) < 0) {
		cl_perror("cl_signal_set_action(): sigaction()");
		return(-1);
	}

	return(0);
}


int
cl_signal_set_simple_action(int sig, void (*action)(int, siginfo_t *, void *)
,	struct sigaction *oldact)
{
	struct sigaction sa;
	sigset_t mask;

	if(sigemptyset(&mask) < 0) {
		cl_perror("cl_signal_set_simple_action()"
		": sigemptyset()");
		return(-1);
	}

	sa.sa_sigaction = action;
	sa.sa_mask = mask;
	sa.sa_flags = 0;

	if(sigaction(sig, &sa, oldact) < 0) {
		cl_perror("cl_signal_set_simple_action()"
		": sigaction()");
		return(-1);
	}

	return(0);
}


int
cl_signal_set_interrupt(int sig, int flag) 
{
	if(siginterrupt(sig, flag) < 0) {
		cl_perror("cl_signal_set_interrupt(): siginterrupt()");
		return(-1);
	}

	return(0);
}


int
cl_signal_block(int how, int signal, sigset_t *oldset)
{
	sigset_t set;

	if(sigemptyset(&set) < 0) {
		cl_perror("cl_signal_block(): sigemptyset()");
		return(-1);
	}

	if(sigaddset(&set, signal) < 0) {
		cl_perror("cl_signal_block(): sigaddset()");
		return(-1);
	}

	if(sigprocmask(how, &set, oldset) < 0) {
		cl_perror("cl_signal_block(): sigprocmask()");
		return(-1);
	}

	return(0);
}


int
cl_signal_block_set(int how, const sigset_t *set, sigset_t *oldset)
{
	if(sigprocmask(how, set, oldset) < 0) {
		cl_perror("cl_signal_block_mask(): sigprocmask()");
		return(-1);
	}

	return(0);
}


int
cl_signal_set_handler_mode(const cl_signal_mode_t *mode, sigset_t *set) 
{
	size_t i;
	sigset_t our_set;
	sigset_t *use_set;

	use_set = (set) ? set : &our_set;

	for (i=0; mode[i].sig; ++i) {
		if(sigaddset(use_set, mode[i].sig) < 0) {
			cl_perror("cl_signal_set_handler_mode(): "
				"sigaddset() [signum=%d]", mode[i].sig);
			return(-1);
		}
	}

	if (sigprocmask(SIG_UNBLOCK, use_set, NULL) < 0) {
		cl_perror("cl_signal_set_handler_mode()"
		": sigprocmask()");
		return(-1);
	}

	for (i=0; mode[i].sig; ++i) {
		if(cl_signal_set_handler(mode[i].sig, mode[i]. handler
		,	use_set, SA_NOCLDSTOP, NULL) < 0) {
			cl_log(LOG_ERR, "cl_signal_set_handler_mode(): "
				"ha_set_sig_handler()");
			return(-1);
		}
		if(cl_signal_set_interrupt(mode[i].sig, mode[i].interrupt) < 0) {
			cl_log(LOG_ERR, "cl_signal_set_handler_mode(): "
				"hb_signal_interrupt()");
			return(-1);
		}
	}

	return(0);
}

