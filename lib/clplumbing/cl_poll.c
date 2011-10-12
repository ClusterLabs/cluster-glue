#include <lha_internal.h>
#include <stdlib.h>
#include <unistd.h>
/*
 * Substitute poll(2) function using POSIX real time signals.
 *
 * The poll(2) system call often has significant latencies and realtime
 * impacts (probably because of its variable length argument list).
 *
 * These functions let us use real time signals and sigtimedwait(2) instead
 * of poll - for those files which work with real time signals.
 * In the 2.4 series of Linux kernels, this does *not* include FIFOs.
 *
 * NOTE:  We (have to) grab the SIGPOLL signal for our own purposes.
 *		Hope that's OK with you...
 *
 * Special caution:  We can only incompletely simulate the difference between
 * the level-triggered interface of poll(2) and the edge-triggered behavior
 * of I/O signals.  As a result you *must* read all previously-indicated
 * incoming data before calling cl_poll() again.  Otherwise you may miss
 * some incoming data (and possibly hang).
 *
 *
 * Copyright (C) 2003 IBM Corporation
 *
 * Author:	<alanr@unix.sh>
 *
 * This software licensed under the GNU LGPL.
 *
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of version 2.1 of the GNU Lesser General Public
 * License as published by the Free Software Foundation.
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
 **************************************************************************/


#define	__USE_GNU	1
#	include <fcntl.h>
#undef	__USE_GNU

#include <errno.h>
#include <string.h>
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_poll.h>
#include <clplumbing/cl_signal.h>



/* Turn on to log odd realtime behavior */

#define	TIME_CALLS	1
#ifdef	TIME_CALLS
#	include <clplumbing/longclock.h>
#	include <clplumbing/cl_log.h>
#endif

static int	debug = 0;

int	/* Slightly sleazy... */
cl_glibpoll(GPollFD* ufds, guint nfsd, gint timeout)
{
	(void)debug;
	return cl_poll((struct pollfd*)ufds, nfsd, timeout);
}

#if defined (F_SETSIG) && defined(F_SETOWN) && defined (O_ASYNC)
#	define HAVE_FCNTL_F_SETSIG
#endif

#ifndef HAVE_FCNTL_F_SETSIG

/*
 * Dummy cl_poll() and cl_poll_ignore() functions for systems where
 * we don't have all the support we need.
 */

int
cl_poll(struct pollfd *fds, unsigned int nfds, int timeout)
{
	return poll(fds, (nfds_t)nfds, timeout);
}

int
cl_poll_ignore(int fd)
{
	return 0;
}

#else /* HAVE_FCNTL_F_SETSIG */
static void dump_fd_info(struct pollfd *fds, unsigned int nfds, int timeoutms);
static void check_fd_info(struct pollfd *fds, unsigned int nfds);
static void cl_real_poll_fd(int fd);
static void cl_poll_sigpoll_overflow_sigaction(int nsig, siginfo_t* , void*);
static void cl_poll_sigpoll_overflow(void);
static int cl_poll_get_sigqlimit(void);
typedef	unsigned char poll_bool;

/*
 *	Here's our strategy:
 *	We have a set of signals which we use for these file descriptors,
 *	and we use sigtimedwait(2) to wait on information from these various
 *	signals.
 *
 *	If we are ever asked to wait for a particular signal, then we will
 *	enable signals for that file descriptor, and post the events in
 *	our own cache.  The next time you include that signal in a call
 *	to cl_poll(), you will get the information delivered
 *	to you in your cl_poll() call.
 *
 *	If you want to stop monitoring a particular file descriptor, use
 *	cl_poll_ignore() for that purpose.  Doing this is a good idea, but
 *	not fatal if omitted...
 */

/* Information about a file descriptor we're monitoring */

typedef struct poll_fd_info_s {
	short		nsig;		/* Which signal goes with it? */
	short		pendevents;	/* Pending events */
}poll_info_t;

static int		max_allocated = 0;
static poll_bool*	is_monitored = NULL;	/* Sized by max_allocated */
static poll_info_t*	monitorinfo = NULL;	/* Sized by max_allocated */
static int		cl_nsig = 0;
static gboolean		SigQOverflow = FALSE;

static int	cl_init_poll_sig(struct pollfd *fds, unsigned int nfds);
static short	cl_poll_assignsig(int fd);
static void	cl_poll_sigaction(int nsig, siginfo_t* info, void* v);
static int	cl_poll_prepsig(int nsig);


/*
 *	SignalSet is the set of all file descriptors we're monitoring.
 *
 *	We monitor a file descriptor forever, unless you tell us not to
 *	by calling cl_poll_ignore(), or you (mistakenly) give it to
 *	us to look at in another poll call after you've closed it.
 */

static sigset_t	SignalSet;

/* Select the signal you want us to use (must be a RT signal) */
int
cl_poll_setsig(int nsig)
{
	if (nsig < SIGRTMIN || nsig >= SIGRTMAX) {
		errno = EINVAL;
		return -1;
	}
	if (cl_poll_prepsig(nsig) < 0) {
		return -1;
	}
	cl_nsig = nsig;
	return 0;
}

/*
 *	It's harmless to call us multiple times on the same signal.
 */
static int
cl_poll_prepsig(int nsig)
{
	static gboolean	setinityet=FALSE;
	
	if (!setinityet) {
		CL_SIGEMPTYSET(&SignalSet);
		cl_signal_set_simple_action(SIGPOLL
		,	cl_poll_sigpoll_overflow_sigaction
		,	NULL);
		setinityet = TRUE;
	}
	if (CL_SIGINTERRUPT(nsig, FALSE) < 0) {
		cl_perror("sig_interrupt(%d, FALSE)", nsig);
		return -1;
	}
	if (CL_SIGADDSET(&SignalSet, nsig) < 0) {
		cl_perror("sig_addset(&SignalSet, %d)", nsig);
		return -1;
	}
	if (CL_SIGPROCMASK(SIG_BLOCK, &SignalSet, NULL) < 0) {
		cl_perror("sig_sigprocmask(SIG_BLOCK, sig %d)", nsig);
		return -1;
	}
	if (debug) {
		cl_log(LOG_DEBUG
		,	"Signal %d belongs to us...", nsig);
		cl_log(LOG_DEBUG, "cl_poll_prepsig(%d) succeeded.", nsig);
	}
	
	return 0;
}

#define	FD_CHUNKSIZE	64

/* Set of events everyone must monitor whether they want to or not ;-) */
#define	CONSTEVENTS	(POLLHUP|POLLERR|POLLNVAL)

#define	RECORDFDEVENT(fd, flags) (monitorinfo[fd].pendevents |= (flags))

/*
 * Initialized our poll-simulation data structures.
 * This means (among other things) registering any monitored
 * file descriptors.
 */
static int
cl_init_poll_sig(struct pollfd *fds, unsigned int nfds)
{
	unsigned	j;
	int		maxmonfd = -1;
	int		nmatch = 0;


	if (cl_nsig == 0) {
		cl_nsig = ((SIGRTMIN+SIGRTMAX)/2);
		if (cl_poll_setsig(cl_nsig) < 0) {
			return -1;
		}
	}
	for (j=0; j < nfds; ++j) {
		const int fd = fds[j].fd;
		
		if (fd > maxmonfd) {
			maxmonfd = fd;
		}
	}

	/* See if we need to malloc/realloc our data structures */

	if (maxmonfd >= max_allocated) {
		int	newsize;
		int	growthamount;

		newsize = ((maxmonfd + FD_CHUNKSIZE)/FD_CHUNKSIZE)
		*	FD_CHUNKSIZE;
		growthamount = newsize - max_allocated;

		/* This can't happen ;-) */
		if (growthamount <= 0 || newsize <= maxmonfd) {
			errno = EINVAL;
			return -1;
		}

		/* Allocate (more) memory! */

		if ((is_monitored = (poll_bool*)realloc(is_monitored
		,	newsize * sizeof(poll_bool))) == NULL
		||	(monitorinfo = (poll_info_t*) realloc(monitorinfo
		,	newsize * sizeof(poll_info_t))) == NULL) {

			if (is_monitored) {
				free(is_monitored);
				is_monitored = NULL;
			}
			if (monitorinfo) {
				free(monitorinfo);
				monitorinfo = NULL;
			}
			max_allocated = 0;
			errno = ENOMEM;
			return -1;
		}
		memset(monitorinfo+max_allocated, 0
		,	growthamount * sizeof(monitorinfo[0]));
		memset(is_monitored+max_allocated, FALSE
		,	growthamount*sizeof(is_monitored[0]));
		max_allocated = newsize;
	}

	if (fds->events != 0 && debug) {
		cl_log(LOG_DEBUG
		,	"Current event mask for fd [0] {%d} 0x%x"
		,	fds->fd, fds->events);
	}
	/*
	 * Examine each fd for the following things:
	 *	Is it already monitored?
	 *		if not, set it up for monitoring.
	 *	Do we have events for it?
	 *		if so, post events...
	 */

	for (j=0; j < nfds; ++j) {
		const int	fd = fds[j].fd;
		poll_info_t*	moni = monitorinfo+fd;
		short		nsig;
		int		badfd = FALSE;

		is_monitored[fd] = TRUE;

		if (moni->nsig <= 0) {
			nsig = cl_poll_assignsig(fd);
			if (nsig < 0) {
				RECORDFDEVENT(fd, POLLERR);
				badfd = TRUE;
			}else{
				/* Use real poll(2) to get initial
				 * event status
				 */
				moni->nsig = nsig;
				cl_real_poll_fd(fd);
			}
		}else if (fcntl(fd, F_GETFD) < 0) {
			cl_log(LOG_ERR, "bad fd(%d)", fd);
			RECORDFDEVENT(fd, POLLNVAL);
			badfd = TRUE;
		}

		/* Look for pending events... */

		fds[j].revents = (moni->pendevents
		&	(fds[j].events|CONSTEVENTS));

		if (fds[j].revents) {
			++nmatch;
			moni->pendevents &= ~(fds[j].revents);
			if (debug) {
				cl_log(LOG_DEBUG
				,	"revents for fd %d: 0x%x"
				,	fds[j].fd, fds[j].revents);
				cl_log(LOG_DEBUG
				,	"events for fd %d: 0x%x"
				,	fds[j].fd, fds[j].events);
			}
		}else if (fds[j].events && debug) {
			cl_log(LOG_DEBUG
			,	"pendevents for fd %d: 0x%x"
			,	fds[j].fd, moni->pendevents);
		}
		if (badfd) {
			cl_poll_ignore(fd);
		}
	}
	if (nmatch != 0 && debug) {
		cl_log(LOG_DEBUG, "Returning %d events from cl_init_poll_sig()"
		,	nmatch);
	}
	return nmatch;
}

/*
 * Initialize our current state of the world with info from the
 * real poll(2) call.
 *
 * We call this when we first see a particular fd, and after a signal
 * queue overflow.
 */
static void
cl_real_poll_fd(int fd)
{
	struct pollfd	pfd[1];

	if (fd >= max_allocated || !is_monitored[fd]) {
		return;
	}

	if (debug) {
		cl_log(LOG_DEBUG
		,	"Calling poll(2) on fd %d", fd);
	}
	/* Get the current state of affaris from poll(2) */
	pfd[0].fd = fd;
	pfd[0].revents = 0;
	pfd[0].events = ~0;
	if (poll(pfd, 1, 0) >= 0) {
		RECORDFDEVENT(fd, pfd[0].revents);
		if (pfd[0].revents & (POLLNVAL|POLLERR)) {
			cl_log(LOG_INFO, "cl_poll_real_fd(%d): error in revents [%d]"
			,	fd, pfd[0].revents);
		}
		if (debug) {
			cl_log(LOG_DEBUG
			,	"Old news from poll(2) for fd %d: 0x%x"
			,	fd, pfd[0].revents);
		}
	}else{
		if (fcntl(fd, F_GETFL) < 0) {
			cl_perror("cl_poll_real_fd(%d): F_GETFL failure"
			,	fd);
			RECORDFDEVENT(fd, POLLNVAL);
		}else{
			RECORDFDEVENT(fd, POLLERR);
		}
	}
}

/*
 * Assign a signal for monitoring the given file descriptor
 */

static short
cl_poll_assignsig(int fd)
{
	int		flags;


	if (debug) {
		cl_log(LOG_DEBUG
		,	"Signal %d monitors fd %d...", cl_nsig, fd);
	}

	/* Test to see if the file descriptor is good */
	if ((flags = fcntl(fd, F_GETFL)) < 0) {
		cl_perror("cl_poll_assignsig(%d) F_GETFL failure"
		,	fd);
		return -1;
	}

	/* Associate the right signal with the fd */

	if (fcntl(fd, F_SETSIG, cl_nsig) < 0) {
		cl_perror("cl_poll_assignsig(%d) F_SETSIG failure"
		,	fd);
		return -1;
	}

	/* Direct the signals to us */
	if (fcntl(fd, F_SETOWN, getpid()) < 0) {
		cl_perror("cl_poll_assignsig(%d) F_SETOWN failure", fd);
		return -1;
	}

	/* OK... Go ahead and send us signals! */

	if (fcntl(fd, F_SETFL, flags|O_ASYNC) < 0) {
		cl_perror("cl_poll_assignsig(%d) F_SETFL(O_ASYNC) failure"
		,	fd);
		return -1;
	}

	return cl_nsig;
}


/*
 *	This is a function we call as a (fake) signal handler.
 *
 *	It records events to our "monitorinfo" structure.
 *
 *	Except for the cl_log() call, it could be called in a signal
 *	context.
 */

static void
cl_poll_sigaction(int nsig, siginfo_t* info, void* v)
{
	int	fd;

	/* What do you suppose all the various si_code values mean? */

	fd = info->si_fd;
	if (debug) {
		cl_log(LOG_DEBUG
		,	"cl_poll_sigaction(nsig=%d fd=%d"
		", si_code=%d si_band=0x%lx)"
		,	nsig, fd, info->si_code
		,	(unsigned long)info->si_band);
	}

	if (fd <= 0) {
		return;
	}


	if (fd >= max_allocated || !is_monitored[fd]) {
		return;
	}

	/* We should not call logging functions in (real) signal handlers */
	if (nsig != monitorinfo[fd].nsig) {
		cl_log(LOG_ERR, "cl_poll_sigaction called with signal %d/%d"
		,	nsig, monitorinfo[fd].nsig);
	}

	/* Record everything as a pending event. */
	RECORDFDEVENT(fd, info->si_band);
}



/*
 *	This is called whenever a file descriptor shouldn't be
 *	monitored any more.
 */
int
cl_poll_ignore(int fd)
{
	int	flags;

	if (debug) {
		cl_log(LOG_DEBUG
		,	"cl_poll_ignore(%d)", fd);
	}
	if (fd <  0 || fd >= max_allocated) {
		errno = EINVAL;
		return -1;
	}
	if (!is_monitored[fd]) {
		return 0;
	}

	is_monitored[fd] = FALSE;
	memset(monitorinfo+fd, 0, sizeof(monitorinfo[0]));

	if ((flags = fcntl(fd, F_GETFL)) >= 0) {
		flags &= ~O_ASYNC;
		if (fcntl(fd, F_SETFL, flags) < 0) {
			return -1;
		}
	}else{
		return flags;
	}
	return 0;
}


/*
 * cl_poll: fake poll routine based on POSIX realtime signals.
 *
 * We want to emulate poll as exactly as possible, but poll has a couple
 * of problems:  scaleability, and it tends to sleep in the kernel
 * because the first argument is an argument of arbitrary size, and
 * generally requires allocating memory.
 *
 * The challenge is that poll is level-triggered, but the POSIX
 * signals (and sigtimedwait(2)) are edge triggered.  This is
 * one of the reasons why we have the cl_real_poll_fd() function
 * - to get the current "level" before we start.
 * Once we have this level we can compute something like the current
 * level
 */

int
cl_poll(struct pollfd *fds, unsigned int nfds, int timeoutms)
{
	int				nready;
	struct	timespec		ts;
	static const struct timespec	zerotime = {0L, 0L};
	const struct timespec*		itertime = &ts;
	siginfo_t			info;
	int				eventcount = 0;
	unsigned int			j;
	int				savederrno = errno;
	int				stw_errno;
	int				rc;
	longclock_t			starttime;
	longclock_t			endtime;
	const int			msfudge
	=				2* 1000/hz_longclock();
	int				mselapsed = 0;

	/* Do we have any old news to report? */
	if ((nready=cl_init_poll_sig(fds, nfds)) != 0) {
		/* Return error or old news to report */
		if (debug) {
			cl_log(LOG_DEBUG, "cl_poll: early return(%d)", nready);
		}
		return nready;
	}

	/* Nothing to report yet... */

	/* So, we'll do a sigtimedwait(2) to wait for signals 
	 * and see if we can find something to report...
	 *
	 * cl_init_poll() prepared a set of file signals to watch...
	 */

recalcandwaitagain:
	if (timeoutms >= 0) {
		ts.tv_sec = timeoutms / 1000;
		ts.tv_nsec = (((unsigned long)timeoutms) % 1000UL)*1000000UL;
	}else{
		ts.tv_sec = G_MAXLONG;
		ts.tv_nsec = 99999999UL;
	}

	/*
	 * Perform a timed wait for any of our signals...
	 *
	 * We shouldn't sleep for any call but (possibly) the first one.
	 * Subsequent calls should just pick up other events without
	 * sleeping.
	 */

	starttime = time_longclock();
	/*
	 * Wait up to the prescribed time for a signal.
	 * If we get a signal, then loop grabbing all other
	 * pending signals. Note that subsequent iterations will
	 * use &zerotime to get the minimum wait time.
	 */
	if (debug) {
		check_fd_info(fds, nfds);
		dump_fd_info(fds, nfds, timeoutms);
	}
waitagain:
	while (sigtimedwait(&SignalSet, &info, itertime) >= 0) {
		int		nsig = info.si_signo;

		/* Call signal handler to simulate signal reception */

		cl_poll_sigaction(nsig, &info, NULL);
		itertime = &zerotime;
	}
	stw_errno=errno; /* Save errno for later use */
	endtime = time_longclock();
	mselapsed = longclockto_ms(sub_longclock(endtime, starttime));

#ifdef TIME_CALLS
	if (timeoutms >= 0 && mselapsed > timeoutms + msfudge) {
		/* We slept too long... */
		cl_log(LOG_WARNING
		,	"sigtimedwait() sequence for %d ms took %d ms"
		,	timeoutms, mselapsed);
	}
#endif

	if (SigQOverflow) {
		/* OOPS!  Better recover from this! */
		/* This will use poll(2) to correct our current status */
		cl_poll_sigpoll_overflow();
	}

	/* Post observed events and count them... */
	
	for (j=0; j < nfds; ++j) {
		int	fd = fds[j].fd;
		poll_info_t*	moni = monitorinfo+fd;
		fds[j].revents = (moni->pendevents
		&	(fds[j].events|CONSTEVENTS));
		if (fds[j].revents) {
			++eventcount;
			moni->pendevents &= ~(fds[j].revents);
			/* Make POLLHUP persistent */
			if (fds[j].revents & POLLHUP) {
				moni->pendevents |= POLLHUP;
				/* Don't lose input events at EOF */
				if (fds[j].events & POLLIN) {
					cl_real_poll_fd(fds[j].fd);
				}
			}
		}
	}
	if (eventcount == 0 && stw_errno == EAGAIN && timeoutms != 0) {
		/* We probably saw an event the user didn't ask to see. */
		/* Consquently, we may have more waiting to do */
		if (timeoutms < 0) {
			/* Restore our infinite wait time */
			itertime = &ts;
			goto waitagain;
		}else if (timeoutms > 0) {
			if (mselapsed < timeoutms) {
				timeoutms -= mselapsed;
				goto recalcandwaitagain;
			}
		}
	}
	rc = (eventcount > 0 ? eventcount : (stw_errno == EAGAIN ? 0 : -1));

	if (rc >= 0) {
		errno = savederrno;
	}
	return rc;
}
/*
 * Debugging routine for printing current poll arguments, etc.
 */
static void
dump_fd_info(struct pollfd *fds, unsigned int nfds, int timeoutms)
{
	unsigned	j;

	cl_log(LOG_DEBUG, "timeout: %d milliseconds", timeoutms);
	for (j=0; j < nfds; ++j) {
		int	fd = fds[j].fd;
		poll_info_t*	moni = monitorinfo+fd;

		cl_log(LOG_DEBUG, "fd %d flags: 0%o, signal: %d, events: 0x%x"
		", revents: 0x%x, pendevents: 0x%x"
		,	fd, fcntl(fd, F_GETFL), moni->nsig
		,	fds[j].events, fds[j].revents, moni->pendevents);
	}
	for (j=SIGRTMIN; j < (unsigned)SIGRTMAX; ++j) {
		if (!sigismember(&SignalSet, j)) {
			continue;
		}
		cl_log(LOG_DEBUG, "Currently monitoring RT signal %d", j);
	}
}

/*
 * Debugging routine for auditing our file descriptors, etc.
 */
static void
check_fd_info(struct pollfd *fds, unsigned int nfds)
{
	unsigned	j;

	for (j=0; j < nfds; ++j) {
		int	fd = fds[j].fd;
		poll_info_t*	moni = monitorinfo+fd;

		if (!sigismember(&SignalSet, moni->nsig)) {
			cl_log(LOG_ERR, "SIGNAL %d not in monitored SignalSet"
			,	moni->nsig);
		}
	}
	for (j=0; j < 10; ++j) {
		int	sig;
		int	flags;
		int	pid;
		if ((flags = fcntl(j, F_GETFL)) < 0 || (flags & O_ASYNC) ==0){
			continue;
		}
		sig = fcntl(j, F_GETSIG);
		if (sig == 0) {
			cl_log(LOG_ERR, "FD %d will get SIGIO", j);
		}
		if (!sigismember(&SignalSet, sig)) {
			cl_log(LOG_ERR, "FD %d (signal %d) is not in SignalSet"
			,	j, sig);
		}
		if (sig < SIGRTMIN || sig >= SIGRTMAX) {
			cl_log(LOG_ERR, "FD %d (signal %d) is not RealTime"
			,	j, sig);
		}
		pid = fcntl(j, F_GETOWN);
		if (pid != getpid()) {
			cl_log(LOG_ERR, "FD %d (signal %d) owner is pid %d"
			,	j, sig, pid);
		}
	}
}

/* Note that the kernel signalled an event queue overflow */
static void
cl_poll_sigpoll_overflow_sigaction(int nsig, siginfo_t* info, void* v)
{
	SigQOverflow = TRUE;
}

#define	MAXQNAME	"rtsig-max"
/*
 * Called when signal queue overflow is suspected.
 * We then use poll(2) to get the current data.  It's slow, but it
 * should work quite nicely.
 */
static void
cl_poll_sigpoll_overflow(void)
{
	int	fd;
	int	limit;

	if (!SigQOverflow) {
		return;
	}
	cl_log(LOG_WARNING, "System signal queue overflow.");
	limit = cl_poll_get_sigqlimit();
	if (limit > 0) {
		cl_log(LOG_WARNING, "Increase '%s'. Current limit is %d"
		" (see sysctl(8)).", MAXQNAME, limit);
	}

	SigQOverflow = FALSE;

	for (fd = 0; fd < max_allocated; ++fd) {
		if (is_monitored[fd]) {
			cl_real_poll_fd(fd);
		}
	}
}

#define	PSK	"/proc/sys/kernel/"

/* Get current kernel signal queue limit */
/* This only works on Linux - but that's not a big problem... */
static int
cl_poll_get_sigqlimit(void)
{
	int	limit = -1;
	int	pfd;
	char	result[32];

	pfd = open(PSK MAXQNAME, O_RDONLY);
	if (pfd >= 0 && read(pfd, result, sizeof(result)) > 1) {
		limit = atoi(result);
		if (limit < 1) {
			limit = -1;
		}
	}
	if (pfd >= 0) {
		close(pfd);
	}
	return limit;
}
#endif /* HAVE_FCNTL_F_SETSIG */
