/* $Id: timers.c,v 1.10 2005/06/19 02:59:30 alan Exp $ */
#include <portability.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <clplumbing/timers.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/longclock.h>

int
setmsrepeattimer(long	ms)
{
	long			secs = ms / 1000L;
	long			usecs = (ms % 1000L)*1000L;
	struct itimerval	nexttime =
	{	{secs, usecs}	/* Repeat Interval */
	,	{secs, usecs}	/* Timer Value */
	};

#if 0
        cl_log(LOG_DEBUG, "Setting repeating timer for %ld ms"   
         ,       ms); 
#endif


	/* Is this right??? */
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


static int alarmpopped = 0;

static void
st_timer_handler(int nsig)
{
	++alarmpopped;
}

/*
 * Pretty simple:
 * 1) Set up SIGALRM signal handler
 * 2) set alarmpopped to FALSE;
 * 2) Record current time
 * 3) Call setmsalarm(ms)
 * 4) Call pause(2)
 * 5) Call cancelmstimer()
 * 6) Reset signal handler
 * 7) See if SIGALRM happened
 *    if so:  return zero
 *    if not: get current time, and compute milliseconds left 'til signal
 *	should arrive, and return that...
 */
long
mssleep(long ms)
{
	struct sigaction	saveaction;
	longclock_t		start;
	longclock_t		finish;
	unsigned long		elapsedms;

	memset(&saveaction, 0, sizeof(saveaction));

	cl_signal_set_simple_handler(SIGALRM, st_timer_handler, &saveaction);
	alarmpopped = 0;
	start = time_longclock();
	setmsalarm(ms);
	pause();
	cancelmstimer();
	cl_signal_set_simple_handler(SIGALRM, saveaction.sa_handler, &saveaction);
	if (alarmpopped) {
		return 0;
	}
	
	finish = time_longclock();
	elapsedms = longclockto_ms(sub_longclock(finish, start));
	return ms - elapsedms;
}
