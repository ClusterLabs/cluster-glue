/*
 * Basic Core dump control functions.
 *
 * Author:	Alan Robertson
 *
 * Copyright (C) 2004 IBM Corporation
 *
 * This software licensed under the GNU LGPL.
 *
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#include <portability.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>
#include <pwd.h>
#include <clplumbing/cl_malloc.h>
#include <clplumbing/coredumps.h>
#include <clplumbing/cl_log.h>

static char *	coreroot = NULL;

/* Set the root directory of our core directory hierarchy */
int
cl_set_corerootdir(const char * dir)
{
	if (dir == NULL || *dir != '/') {
		cl_perror("Invalid dir in cl_set_corerootdir() [%s]"
		,	dir ? dir : "<NULL>");
		errno = EINVAL;
		return -1;
	}
	if (coreroot != NULL) {
		cl_free(coreroot);
		coreroot = NULL;
	}
	coreroot = cl_strdup(dir);
	if (coreroot == NULL) {
		return -1;
	}
	return 0;
}

/*
 * Change directory to the directory our core file needs to go in
 * Call after you establish the userid you're running under.
 */
int
cl_cdtocoredir(void)
{
	const char *	dir = coreroot;
	int		rc;
	struct passwd*	pwent;
	
	if (dir == NULL) {
		dir = HA_COREDIR;
	}
	if ((rc=chdir(dir)) < 0) {
		int errsave = errno;
		cl_perror("Cannot chdir to [%s]", dir);
		errno = errsave;
		return rc;
	}
	pwent = getpwuid(geteuid());
	if (pwent == NULL) {
		int errsave = errno;
		cl_perror("Cannot get name for uid [%d]", geteuid());
		errno = errsave;
		return -1;
	}
	if ((rc=chdir(pwent->pw_name)) < 0) {
		int errsave = errno;
		cl_perror("Cannot chdir to [%s/%s]", dir, pwent->pw_name);
		errno = errsave;
	}
	return rc;
}


/* Enable/disable core dumps for ourselves and our child processes */
int
cl_enable_coredumps(int doenable)
{
	int		rc;
	struct rlimit	rlim;

	if ((rc = getrlimit(RLIMIT_CORE, &rlim)) < 0) {
		int errsave = errno;
		cl_perror("Cannot get current core limit value.");
		errno = errsave;
		return rc;
	}
	if (rlim.rlim_max == 0 && geteuid() == 0) {
		rlim.rlim_max = RLIM_INFINITY;
	}

	rlim.rlim_cur = (doenable ? rlim.rlim_max : 0);

	if (doenable && rlim.rlim_max == 0) {
		cl_log(LOG_WARNING
		,	"Not possible to enable core dumps (rlim_max is 0)");
	}

	if ((rc = getrlimit(RLIMIT_CORE, &rlim)) < 0) {
		int errsave = errno;
		cl_perror("Unable to %s core dumps"
		,	 doenable ? "enable" : "disable");
		errno = errsave;
		return rc;
	}
	return 0;
}
