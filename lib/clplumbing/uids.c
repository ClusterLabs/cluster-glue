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
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <clplumbing/uids.h>
#include <clplumbing/coredumps.h>
#define	NOBODY	"nobody"

#if defined(HAVE_SETEUID) && defined(HAVE_SETEGID) &&	\
		 defined(_POSIX_SAVED_IDS)
#	define	CAN_DROP_PRIVS	1

#endif




#ifndef CAN_DROP_PRIVS
	int drop_privs(uid_t uid, gid_t gid)	{	return 0;	}
	int return_to_orig_privs(void)		{	return 0;	}
	int return_to_dropped_privs(void)	{	return 0;	}
	int cl_have_full_privs(void)		{	return 0;	}
#else

static int	anysaveduid = 0;
static uid_t	nobodyuid=-1;
static gid_t	nobodygid=-1;
static uid_t	poweruid=-1;
static gid_t	powergid=-1;
static int	privileged_state = 1;

/*	WARNING: uids are unsigned! */
#define	WANT_NOBODY(uid)	((uid) == 0)

int	/* Become nobody - and remember our original privileges */
drop_privs(uid_t uid, gid_t gid)
{
	int	rc;
	gid_t	curgid = getgid();

	if (!anysaveduid) {
		poweruid=getuid();
		powergid=curgid;
	}

	if (WANT_NOBODY(uid)) {
		struct passwd*	p;

		p = getpwnam(NOBODY);

		if (p == NULL) {
			return -1;
		}
		uid = p->pw_uid;
		gid = p->pw_gid;
	}
	if (setegid(gid) < 0) {
		return -1;
	}
	rc = seteuid(uid);

	if (rc >= 0) {
		anysaveduid = 1;
		nobodyuid=uid;
		nobodygid=gid;
		privileged_state = 0;
	}else{
		/* Attempt to recover original privileges */
		int	err = errno;
		setegid(curgid);
		errno = err;
	}
	cl_untaint_coredumps();
	return rc;
}

int	/* Return to our original privileges (if any) */
return_to_orig_privs(void)
{
	int	rc;
	if (!anysaveduid) {
		return 0;
	}
	if (seteuid(poweruid) < 0) {
		return -1;
	}
	privileged_state = 1;
	rc = setegid(powergid);
	/*
	 * Sad but true, for security reasons we can't call
	 * cl_untaint_coredumps() here - because it might cause an
	 * leak of confidential information for some applications.
	 * So, the applications need to use either cl_untaint_coredumps()
	 * when they change privileges, or they need to call
	 * cl_set_all_coredump_signal_handlers() to handle core dump
	 * signals and set their privileges to maximum before core
	 * dumping.  See the comments in coredumps.c for more details.
	 */
	return rc;
}

int	/* Return to "nobody" level of privs (if any) */
return_to_dropped_privs(void)
{
	int rc;

	if (!anysaveduid) {
		return 0;
	}
	setegid(nobodygid);
	privileged_state = 0;
	rc =  seteuid(nobodyuid);
	/* See note above about dumping core */
	return rc;
}

/* Return TRUE if we have full privileges at the moment */
int
cl_have_full_privs(void)
{
	return privileged_state != 0;
}
#endif
