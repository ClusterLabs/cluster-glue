#ifndef CLPLUMBING_CL_REBOOT_H
#define CLPLUMBING_CL_REBOOT_H 1
#include <glib.h>
void cl_enable_coredump_before_reboot(gboolean yesno); /* not implemented in all OSes */
void cl_reboot(int msdelaybeforereboot, const char * reason);
#endif
