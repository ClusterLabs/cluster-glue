#include <portability.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#ifdef _POSIX_MEMLOCK
#	include <sys/mman.h>
#endif
#ifdef _POSIX_PRIORITY_SCHEDULING
#	include <sched.h>
#endif
#include <string.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/realtime.h>
#include <time.h>

static gboolean	cl_realtimepermitted = TRUE;

#if defined(SCHED_RR) && defined(_POSIX_PRIORITY_SCHEDULING)
#	define DEFAULT_REALTIME	SCHED_RR
#endif

#define HOGRET	0xff
/*
 * Slightly wacko recursive function to touch requested amount
 * of stack so we have it pre-allocated inside our realtime code
 * as per suggestion from mlockall(2)
 */
static int
cl_stack_hogger(char * inbuf, int kbytes)
{
#ifdef _POSIX_MEMLOCK
	/* Needs to be volatile so it really can't be optimised away */
	char	buf[1024];
	
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
#else
	return HOGRET;
#endif
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


#ifdef DEFAULT_REALTIME
	struct sched_param	sp;
	int			staticp;

	if (!cl_realtimepermitted) {
		cl_log(LOG_INFO
		,	"Request to set pid %ld to realtime ignored."
		,	(long)getpid());
		return;
	}

	if (spolicy <= 0) {
		spolicy = DEFAULT_REALTIME;
	}

	if (priority <= 0) {
		priority = sched_get_priority_min(spolicy);
	}

	if (priority > sched_get_priority_max(spolicy)) {
		priority = sched_get_priority_max(spolicy);
	}

	if (heapgrowK < 0) {
		heapgrowK = 0;
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

#ifdef _POSIX_MEMLOCK
	
	if (heapgrowK > 0) {
	/*
	 *	Try and pre-allocate a little memory before locking
	 *	ourselves into memory...
	 */
		void*	mval = malloc(heapgrowK*1024);

		if (mval != NULL) {
			memset(mval, 0, heapgrowK*1024);
			free(mval);
		}else{
			cl_log(LOG_INFO, "Could not preallocate (%d) bytes" 
			,	heapgrowK);
		}
		if (cl_stack_hogger(NULL, stackgrowK) != HOGRET) {
			cl_log(LOG_INFO, "Stack hogger failed");
		}
	}

	if (mlockall(MCL_CURRENT|MCL_FUTURE) < 0) {
		cl_perror("Unable to lock pid %d in memory", (int) getpid());
	}else{
		cl_log(LOG_INFO, "pid %d locked in memory.", (int) getpid());
	}
#endif
}

void
cl_make_normaltime()
{
#ifdef DEFAULT_REALTIME
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

int
cl_shortsleep(void)
{
	static const struct timespec	req = {0,0};

	return nanosleep(&req, NULL);
}
