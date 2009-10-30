#include <lha_internal.h>
#include <clplumbing/cl_reboot.h>
#ifdef HAVE_UNISTD_H
#	include <unistd.h>
#endif
#ifdef HAVE_SYS_REBOOT_H
#	include <sys/reboot.h>
#endif
#ifdef HAVE_STDLIB_H
#	include <stdlib.h>
#endif
#include <clplumbing/cl_log.h>
#include <clplumbing/timers.h>

enum rebootopt {
	REBOOT_DEFAULT = 0,
	REBOOT_NOCOREDUMP = 1,
	REBOOT_COREDUMP = 2,
};
static enum rebootopt	coredump = REBOOT_DEFAULT;

void
cl_enable_coredump_before_reboot(gboolean yesno)
{
	coredump = (yesno ? REBOOT_COREDUMP : REBOOT_NOCOREDUMP);
}


void cl_reboot(int msdelaybeforereboot, const char * reason)
{
	int	rebootflag = 0;
	int	systemrc = 0;
#ifdef RB_AUTOBOOT
	rebootflag = RB_AUTOBOOT;
#endif
#ifdef RB_NOSYNC
	rebootflag = RB_NOSYNC;
#endif
#ifdef RB_DUMP
	if (coredump == REBOOT_COREDUMP) {
		rebootflag = RB_DUMP;
	}
#endif
	cl_log(LOG_EMERG, "Rebooting system.  Reason: %s", reason);
	sync();
	mssleep(msdelaybeforereboot);
#if REBOOT_ARGS == 1
	reboot(rebootflag);
#elif REBOOT_ARGS == 2
	reboot(rebootflag, NULL);
#else
#error "reboot() call needs to take one or two args"
#endif
	/* Shouldn't ever get here, but just in case... */
	systemrc=system(REBOOT " " REBOOT_OPTIONS);
	cl_log(LOG_EMERG, "ALL REBOOT OPTIONS FAILED: %s returned %d"
	,	REBOOT " " REBOOT_OPTIONS, systemrc);
	exit(1);
}
