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

#include <lha_internal.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stddef.h>
/* The BSD's do not use malloc.h directly. */
/* They use stdlib.h instead */
#ifndef BSD
#ifdef HAVE_MALLOC_H
#	include <malloc.h>
#endif
#endif
#include <unistd.h>
#ifdef _POSIX_MEMLOCK
#	include <sys/mman.h>
#	include <sys/time.h>
#	include <sys/resource.h>
#endif
#ifdef _POSIX_PRIORITY_SCHEDULING
#	include <sched.h>
#endif
#include <string.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/realtime.h>
#include <clplumbing/uids.h>
#include <time.h>
#include <errno.h>

static gboolean	cl_realtimepermitted = TRUE;
static void cl_rtmalloc_setup(void);

#define HOGRET	0xff
/*
 * Slightly wacko recursive function to touch requested amount
 * of stack so we have it pre-allocated inside our realtime code
 * as per suggestion from mlockall(2)
 */
#ifdef _POSIX_MEMLOCK
static unsigned char
cl_stack_hogger(unsigned char * inbuf, int kbytes)
{
	unsigned char	buf[1024];
	
	if (inbuf == NULL) {
		memset(buf, HOGRET, sizeof(buf));
	}else{
		memcpy(buf, inbuf, sizeof(buf));
	}

	if (kbytes > 0) {
		return cl_stack_hogger(buf, kbytes-1);
	}else{
		return buf[sizeof(buf)-1];
	}
/* #else
	return HOGRET;
*/
}
#endif
/*
 * We do things this way to hopefully defeat "smart" malloc code which
 * handles large mallocs as special cases using mmap().
 */
static void
cl_malloc_hogger(int kbytes)
{
	long	size		= kbytes * 1024;
	int	chunksize	= 1024;
	long	nchunks		= (int)(size / chunksize);
	int	chunkbytes 	= nchunks * sizeof(void *);
	void**	chunks;
	int	j;

#ifdef HAVE_MALLOPT
#	ifdef M_MMAP_MAX
	/* Keep malloc from using mmap */
	mallopt(M_MMAP_MAX, 0);
#endif
#	ifdef M_TRIM_THRESHOLD
	/* Keep malloc from giving memory back to the system */
	mallopt(M_TRIM_THRESHOLD, -1);
#	endif
#endif
	chunks=malloc(chunkbytes);
	if (chunks == NULL) {
		cl_log(LOG_INFO, "Could not preallocate (%d) bytes" 
		,	chunkbytes);
		return;
	}
	memset(chunks, 0, chunkbytes);

	for (j=0; j < nchunks; ++j) {
		chunks[j] = malloc(chunksize);
		if (chunks[j] == NULL) {
			cl_log(LOG_INFO, "Could not preallocate (%d) bytes" 
		,	chunksize);
		}else{
			memset(chunks[j], 0, chunksize);
		}
	}
	for (j=0; j < nchunks; ++j) {
		if (chunks[j]) {
			free(chunks[j]);
			chunks[j] = NULL;
		}
	}
	free(chunks);
	chunks = NULL;
}

/*
 *	Make us behave like a soft real-time process.
 *	We need scheduling priority and being locked in memory.
 *	If you ask us nicely, we'll even grow the stack and heap
 *	for you before locking you into memory ;-).
 */
void
cl_make_realtime(int spolicy, int priority,  int stackgrowK, int heapgrowK)
{
#ifdef DEFAULT_REALTIME_POLICY
	struct sched_param	sp;
	int			staticp;
#endif

	if (heapgrowK > 0) {
		cl_malloc_hogger(heapgrowK);
	}

#ifdef _POSIX_MEMLOCK
	if (stackgrowK > 0) {
		unsigned char ret;
		if ((ret=cl_stack_hogger(NULL, stackgrowK)) != HOGRET) {
			cl_log(LOG_INFO, "Stack hogger failed 0x%x"
			,	ret);
		}
	}
#endif
	cl_rtmalloc_setup();

	if (!cl_realtimepermitted) {
		cl_log(LOG_INFO
		,	"Request to set pid %ld to realtime ignored."
		,	(long)getpid());
		return;
	}

#ifdef DEFAULT_REALTIME_POLICY
	if (spolicy < 0) {
		spolicy = DEFAULT_REALTIME_POLICY;
	}

	if (priority <= 0) {
		priority = sched_get_priority_min(spolicy);
	}

	if (priority > sched_get_priority_max(spolicy)) {
		priority = sched_get_priority_max(spolicy);
	}


	if ((staticp=sched_getscheduler(0)) < 0) {
		cl_perror("unable to get scheduler parameters.");
	}else{
		memset(&sp, 0, sizeof(sp));
		sp.sched_priority = priority;

		if (sched_setscheduler(0, spolicy, &sp) < 0) {
			cl_perror("Unable to set scheduler parameters.");
		}
	}
#endif

#if defined _POSIX_MEMLOCK
#	ifdef RLIMIT_MEMLOCK
#	define	THRESHOLD(lim)	(((lim))/2)
	{
		unsigned long		growsize = ((stackgrowK+heapgrowK)*1024);
		struct rlimit		memlocklim;

		getrlimit(RLIMIT_MEMLOCK, &memlocklim);	/* Allow for future added fields */
		memlocklim.rlim_max = RLIM_INFINITY;
		memlocklim.rlim_cur = RLIM_INFINITY;
		/* Try and remove memory locking limits -- if we can */
		if (setrlimit(RLIMIT_MEMLOCK, &memlocklim) < 0) {
			/* Didn't work - get what we can */
			getrlimit(RLIMIT_MEMLOCK, &memlocklim);
			memlocklim.rlim_cur = memlocklim.rlim_max;
			setrlimit(RLIMIT_MEMLOCK, &memlocklim);
		}

		/* Could we get 'enough' ? */
		/* (this is a guess - might not be right if we're not root) */
		if (getrlimit(RLIMIT_MEMLOCK, &memlocklim) >= 0
		&&	memlocklim.rlim_cur != RLIM_INFINITY
		&&	(growsize >= THRESHOLD(memlocklim.rlim_cur))) {
			cl_log(LOG_ERR
			,	"Cannot lock ourselves into memory:  System limits"
			" on locked-in memory are too small.");
				return;
		}
	}
#	endif	/*RLIMIT_MEMLOCK*/
	if (mlockall(MCL_CURRENT|MCL_FUTURE) >= 0) {
		if (ANYDEBUG) {
			cl_log(LOG_DEBUG, "pid %d locked in memory.", (int) getpid());
		}

	} else if(errno == ENOSYS) {
		const char *err = strerror(errno);
		cl_log(LOG_WARNING, "Unable to lock pid %d in memory: %s",
		       (int) getpid(), err);

	} else {
		cl_perror("Unable to lock pid %d in memory", (int) getpid());
	}
#endif
}

void
cl_make_normaltime(void)
{
#ifdef DEFAULT_REALTIME_POLICY
	struct sched_param	sp;

	memset(&sp, 0, sizeof(sp));
	sp.sched_priority = sched_get_priority_min(SCHED_OTHER);
	if (sched_setscheduler(0, SCHED_OTHER, &sp) < 0) {
		cl_perror("unable to (re)set scheduler parameters.");
	}
#endif
#ifdef _POSIX_MEMLOCK
	/* Not strictly necessary. */
	munlockall();
#endif
}

void
cl_disable_realtime(void)
{
	cl_realtimepermitted = FALSE;
}

void
cl_enable_realtime(void)
{
	cl_realtimepermitted = TRUE;
}

/* Give up the CPU for a little bit */
/* This is similar to sched_yield() but allows lower prio processes to run */
int
cl_shortsleep(void)
{
	static const struct timespec	req = {0,2000001L};

	return nanosleep(&req, NULL);
}


static int		post_rt_morecore_count = 0;
static unsigned long	init_malloc_arena = 0L;

#ifdef HAVE_MALLINFO
#	define	MALLOC_TOTALSIZE()	(((unsigned long)mallinfo().arena)+((unsigned long)mallinfo().hblkhd))
#else
#	define	MALLOC_TOTALSIZE()	(0L)
#endif



/* Return the number of times we went after more core */
int
cl_nonrealtime_malloc_count(void)
{
	return post_rt_morecore_count;
}
unsigned long
cl_nonrealtime_malloc_size(void)
{
		return (MALLOC_TOTALSIZE() - init_malloc_arena);
}
/* Log the number of times we went after more core */
void
cl_realtime_malloc_check(void)
{
	static	int		lastcount = 0;
	static unsigned long	oldarena = 0UL;

	if (oldarena == 0UL) {
		oldarena = init_malloc_arena;
	}

	if (post_rt_morecore_count > lastcount) {

		if (MALLOC_TOTALSIZE() > oldarena) {

			cl_log(LOG_WARNING,
			       "Performed %d more non-realtime malloc calls.",
			       post_rt_morecore_count - lastcount);
			
			cl_log(LOG_INFO,
			       "Total non-realtime malloc bytes: %ld",
			       MALLOC_TOTALSIZE() - init_malloc_arena);
			oldarena = MALLOC_TOTALSIZE();			
			
		}
		
		lastcount = post_rt_morecore_count;
	}
}
	
#ifdef HAVE___DEFAULT_MORECORE

static void	(*our_save_morecore_hook)(void) = NULL;
static void	cl_rtmalloc_morecore_fun(void);

static void
cl_rtmalloc_morecore_fun(void)
{
	post_rt_morecore_count++;
	if (our_save_morecore_hook) {
		our_save_morecore_hook();
	}
}
#endif

static void
cl_rtmalloc_setup(void)
{
	static gboolean	inityet = FALSE;
	if (!inityet) {
		init_malloc_arena = MALLOC_TOTALSIZE();
#ifdef HAVE___DEFAULT_MORECORE
		our_save_morecore_hook = __after_morecore_hook;
	 	__after_morecore_hook = cl_rtmalloc_morecore_fun;
		inityet = TRUE;
#endif
	}
 }
