/*
 * stonith_signal.h: signal handling routines to be used by stonith
 *                   plugin libraries
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
#ifndef _STONITH_SIGNAL_H
#define _STONITH_SIGNAL_H

#include <signal.h>
#include <sys/signal.h>

int
stonith_signal_set_simple_handler(int sig, void (*handler)(int)
,		struct sigaction *oldact);

int
stonith_signal_set_simple_handler(int sig, void (*handler)(int)
,		struct sigaction *oldact)
{
	struct sigaction sa;
	sigset_t mask;

	(void)stonith_signal_set_simple_handler;
	if(sigemptyset(&mask) < 0) {
		return(-1);
	}

	sa.sa_handler = handler;
	sa.sa_mask = mask;
	sa.sa_flags = 0;

	if(sigaction(sig, &sa, oldact) < 0) {
		return(-1);
	}

	return(0);
}

#define STONITH_SIGNAL(_sig, _handler) \
	stonith_signal_set_simple_handler((_sig), (_handler), NULL)
#ifdef HAVE_SIGIGNORE
#define STONITH_IGNORE_SIG(_sig) \
	sigignore((_sig))
#else
#define STONITH_IGNORE_SIG(_sig) \
	STONITH_SIGNAL((_sig), SIG_IGN)
#endif
#define STONITH_DEFAULT_SIG(_sig) STONITH_SIGNAL((_sig), SIG_DFL)

#define STONITH_KILL(_pid, _sig) kill((_pid), (_sig))

#endif /* _STONITH_SIGNAL_H */
