#include <portability.h>
#include <stdlib.h>
#include <unistd.h>

#define	__USE_GNU	1
#	include <fcntl.h>
#undef	__USE_GNU

#include <errno.h>
#include <string.h>
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_poll.h>
#include <clplumbing/cl_signal.h>
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

int
cl_poll(struct pollfd *fds, unsigned int nfds, int timeout)
{
	return poll(fds, nfds, timeout);
}

int
cl_poll_ignore(int fd)
{
	return 0;
}


#else /* HAVE_FCNTL_F_SETSIG */
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
 *	to you in your poll call.
 *
 *	If you want to stop monitoring a particular file descriptor, use
 *	cl_poll_ignore() for that purpose.
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

static int cl_init_poll_sig(struct pollfd *fds, unsigned int nfds);
static short cl_poll_assignsig(int fd);
static void cl_poll_sigaction(int nsig, siginfo_t* info, void* v);
static int cl_poll_prepsig(int nsig);


/*
 *	SignalSet is the set of all file descriptors we're monitoring.
 *
 *	We monitor a file descriptor forever, unless you tell us not to
 *	by calling cl_poll_ignore(), or you (mistakenly) give it to
 *	us to look at in another poll call after you've closed it.
 */

static sigset_t	SignalSet;
static int	setinityet=FALSE;

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
static
int cl_poll_prepsig(int nsig)
{
	sigset_t		singlemask;
	
	if (CL_SIGINTERRUPT(nsig, FALSE) < 0) {
		return -1;
	}
	if (CL_SIGEMPTYSET(&singlemask) < 0) {
		return -1;
	}
	if (CL_SIGADDSET(&singlemask, nsig) < 0) {
		return -1;
	}
	if (CL_SIGADDSET(&SignalSet, nsig) < 0) {
		return -1;
	}
	if (CL_SIGPROCMASK(SIG_BLOCK, &singlemask, NULL) < 0) {
		return -1;
	}

	if (cl_signal_set_action(nsig, cl_poll_sigaction, &SignalSet,
				SA_SIGINFO, NULL) < 0) {
		return -1;
	}
	return 0;
}

#define	FD_CHUNKSIZE	64

/* Set of events everyone must monitor */
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

	/*
	 * Examine each fd for the following things:
	 *	Is it already monitored?
	 *		if not, set it up for monitoring.
	 *	Do we have events for it?
	 *		if so, post events...
	 */

	for (j=0; j < nfds; ++j) {
		const int fd = fds[j].fd;
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
				struct pollfd	fdl[1];
				moni->nsig = nsig;
				
				/* Get "old news" from poll(2) */
				fdl[0].fd = fd;
				fdl[0].revents = 0;
				fdl[0].events = ~0;
				if (poll(fdl, 1,-1) > 0) {
					RECORDFDEVENT(fd, fdl[0].revents);
				}
			}
		}else if (fcntl(fd, F_GETFD) < 0) {
			RECORDFDEVENT(fd, POLLERR);
			badfd = TRUE;
		}

		/* Look for pending events... */

		fds[j].revents = (moni->pendevents
		&	(fds[j].events|CONSTEVENTS));

		if (fds[j].revents) {
			++nmatch;
			moni->pendevents &= ~(fds[j].revents);
		}
		if (badfd) {
			cl_poll_ignore(fd);
		}
	}
	return nmatch;
}


/*
 * Assign a signal for monitoring the given file descriptor
 */

static short
cl_poll_assignsig(int fd)
{
	int		flags;


	if (!setinityet) {
		CL_SIGEMPTYSET(&SignalSet);
		if (cl_nsig == 0) {
			cl_nsig = ((SIGRTMIN+SIGRTMAX)/2);
			cl_poll_prepsig(cl_nsig);
		}
		setinityet = TRUE;
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

	/* I never could figure out what si_code I should get... */

	fd = info->si_fd;

	if (fd <= 0) {
		return;
	}


	if (fd >= max_allocated || !is_monitored[fd]) {
		return;
	}

	/* We should not call logging functions within signal handlers */
	/*
	if (nsig != monitorinfo[fd].nsig) {
		cl_log(LOG_ERR, "cl_poll_sigaction called with signal %d/%d\n"
		,	nsig, monitorinfo[fd].nsig);
	}
	*/

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
	short	nsig;
	int	flags;

	if (fd <  0 || fd >= max_allocated) {
		errno = EINVAL;
		return -1;
	}
	if (!is_monitored[fd]) {
		return 0;
	}
	nsig = monitorinfo[fd].nsig;

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
 * By contrast, we can monitor up to 1024 file descriptors with a
 * fixed-size structure of only 128 bytes. 
 * 
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
	int				j;
#ifdef TIME_CALLS
	longclock_t			starttime;
	int				maxsleep = timeoutms;
	const int			msfudge
	=				2* 1000/hz_longclock();
#endif

	/* Do we have any old news to report? */
	if ((nready=cl_init_poll_sig(fds, nfds)) != 0) {
		/* Return error or old news to report */
		return nready;
	}

	/* Nothing to report yet... */

	/* So, we'll do a sigtimedwait(2) to wait for signals 
	 * and see if we can find something to report...
	 *
	 * cl_init_poll() prepared a set of file signals to watch...
	 */

	if (timeoutms >= 0) {
		ts.tv_sec = timeoutms / 1000;
		ts.tv_nsec = (((unsigned long)timeoutms) % 1000UL)*1000000UL;
	}else{
		ts.tv_sec = G_MAXLONG;
		ts.tv_nsec = 99999999UL;
#ifdef TIME_CALLS
		maxsleep = G_MAXINT;
#endif
	}


	/*
	 * Perform a timed wait for any of our signals...
	 *
	 * We should wait only for the first call.
	 * Subsequent calls should just pick up other events without
	 * waiting.
	 */

	if (debug) {
		cl_log(LOG_DEBUG, "sigtimedwait() for (%ld, %ld) time"
		,	(long)itertime->tv_sec, itertime->tv_nsec);
	}

#ifdef TIME_CALLS
	starttime = time_longclock();
#endif
	while (sigtimedwait(&SignalSet, &info, itertime) >= 0) {
		int	nsig;
#ifdef TIME_CALLS
		int		mselapsed;
		longclock_t	endtime = time_longclock();


		mselapsed = longclockto_ms(sub_longclock(endtime, starttime));

		if (maxsleep != G_MAXINT && mselapsed > maxsleep + msfudge) {
			/* We slept too long... */
			cl_log(LOG_WARNING
			,	"sigtimedwait() for %d ms took %d ms"
			,	maxsleep, mselapsed);
		}
#endif

		itertime = &zerotime;
		nsig = info.si_signo;

		/* Simulated signal reception */
		cl_poll_sigaction(nsig, &info, NULL);
#ifdef TIME_CALLS
		maxsleep = 0;
		starttime = time_longclock();
#endif
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
		}
	}
	return (eventcount > 0 ? eventcount : -1);
}
#endif /* HAVE_FCNTL_F_SETSIG */
