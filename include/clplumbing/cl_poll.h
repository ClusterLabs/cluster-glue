/* $Id: cl_poll.h,v 1.5 2004/02/17 22:11:58 lars Exp $ */
#ifndef CLPLUMBING_CL_POLL_H
#	define CLPLUMBING_CL_POLL_H

#include <glib.h>
#include <sys/poll.h>

/*
 * Poll the file descriptors described by the NFDS structures starting at
 * FDS.  If TIMEOUT is nonzero and not -1, allow TIMEOUT milliseconds for
 * an event to occur; if TIMEOUT is -1, block until an event occurs.
 * Returns the number of file descriptors with events, zero if timed out,
 * or -1 for errors. 
 *
 * When available, this function uses POSIX signals, and Linux F_SETSIG()
 * calls to provide this capability.  When it is not available it
 * uses the real poll() call.
 *
 */
int cl_poll(struct pollfd *fds, unsigned int nfds, int timeout_ms);

/*
 * Call cl_poll_ignore() when you close a file descriptor you monitored
 * via cl_poll() before, or if you don't want it monitored any more.
 */
int cl_poll_ignore(int fd);

/* Select the signal you want us to use (must be a RT signal) */
int cl_poll_setsig(int nsig);

int cl_glibpoll(GPollFD* ufds, guint nfsd, gint timeout);
#endif
