#include <portability.h>
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <clplumbing/uids.h>
#define	NOBODY	"nobody"

#if defined(HAVE_SETEUID) && defined(HAVE_SETEGID) &&	\
		 defined(_POSIX_SAVED_IDS)
#	define	CAN_DROP_PRIVS	1

#endif




#ifndef CAN_DROP_PRIVS
	int drop_privs(uid_t uid, gid_t gid)	{	return 0;	}
	int return_to_orig_privs(void)		{	return 0;	}
	int return_to_dropped_privs(void)	{	return 0;	}
#else

static int	anysaveduid = 0;
static uid_t	nobodyuid=-1;
static gid_t	nobodygid=-1;
static uid_t	poweruid=-1;
static gid_t	powergid=-1;

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
	}else{
		/* Attempt to recover original privileges */
		int	err = errno;
		setegid(curgid);
		errno = err;
	}
	return rc;
}

int	/* Return to our original privileges (if any) */
return_to_orig_privs()
{
	if (!anysaveduid) {
		return 0;
	}
	if (seteuid(poweruid) < 0) {
		return -1;
	}
	return setegid(powergid);
}

int	/* Return to "nobody" level of privs (if any) */
return_to_dropped_privs(void)
{
	if (!anysaveduid) {
		return 0;
	}
	setegid(nobodygid);
	return seteuid(nobodyuid);
}
#endif
