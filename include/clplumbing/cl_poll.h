/*
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
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
