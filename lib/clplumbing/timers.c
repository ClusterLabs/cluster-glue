#include <linux-ha/portability.h>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <clplumbing/timers.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>

int
setmsrepeattimer(long	ms)
{
	long			secs = ms / 1000L;
	long			usecs = (ms % 1000L)*1000L;
	struct itimerval	nexttime =
	{	{secs, usecs}	/* Repeat Interval */
	,	{secs, usecs}	/* Timer Value */
	};

	cl_log(LOG_DEBUG, "Setting repeating timer for %ld ms"
	,	ms);

	CL_IGNORE_SIG(SIGALRM);
	return setitimer(ITIMER_REAL, &nexttime, NULL);
}

int
setmsalarm(long	ms)
{
	long			secs = ms / 1000L;
	long			usecs = (ms % 1000L)*1000L;
	struct itimerval	nexttime =
	{	{0L, 0L}	/* Repeat Interval */
	,	{secs, usecs}	/* Timer Value */
	};

	return setitimer(ITIMER_REAL, &nexttime, NULL);
}

int
cancelmstimer(void)
{
	struct itimerval	nexttime =
	{	{0L, 0L}	/* Repeat Interval */
	,	{0L, 0L}	/* Timer Value */
	};
	return setitimer(ITIMER_REAL, &nexttime, NULL);
}
