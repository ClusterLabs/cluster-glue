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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <clplumbing/cl_signal.h>
#include <stonith/st_ttylock.h>

/*
 * The following information is from the Filesystem Hierarchy Standard
 * version 2.1 dated 12 April, 2000.
 *
 * 5.6 /var/lock : Lock files
 * Lock files should be stored within the /var/lock directory structure.
 * Device lock files, such as the serial device lock files that were originally
 * found in either /usr/spool/locks or /usr/spool/uucp, must now be stored in
 * /var/lock. The naming convention which must be used is LCK.. followed by
 * the base name of the device file. For example, to lock /dev/cua0 the file
 * LCK..cua0 would be created.
 * 
 * The format used for device lock files must be the HDB UUCP lock file format.
 * The HDB format is to store the process identifier (PID) as a ten byte
 * ASCII decimal number, with a trailing newline. For example, if process 1230
 * holds a lock file, it would contain the eleven characters: space, space,
 * space, space, space, space, one, two, three, zero, and newline.
 * Then, anything wishing to use /dev/cua0 can read the lock file and act
 * accordingly (all locks in /var/lock should be world-readable).
 *
 *
 * PERMISSIONS NOTE:
 * Different linux distributions set the mode of the lock directory differently
 * Any process which wants to create lock files must have write permissions
 * on HA_VARLOCKDIR (probably /var/lock).  For things like the heartbeat API
 * code, this may mean allowing the uid of the processes that use this API
 * to join group uucp, or making the binaries setgid to uucp.
 */

#define	DEVDIR	"/dev/"
#define	DEVLEN	(sizeof(DEVDIR)-1)

static void raw_device (const char *dev, char *dest_name, size_t size);
static int DoLock(const char * prefix, const char *lockname);
static int DoUnlock(const char * prefix, const char *lockname);

/* The code in this file originally written by Guenther Thomsen */
/* Somewhat mangled by Alan Robertson */

/*
 * Lock a tty (using lock files, see linux `man 2 open` close to O_EXCL) 
 * serial_device has to be _the complete path_, i.e. including '/dev/' to the
 * special file, which denotes the tty to lock -tho
 * return 0 on success, 
 * -1 if device is locked (lockfile exists and isn't stale),
 * -2 for temporarily failure, try again,
 * other negative value, if something unexpected happend (failure anyway)
 */

static void
raw_device (const char *serial_device, char *dest_name, size_t size)
{
	char*		dp	= dest_name;
	const char*	sp	= serial_device+DEVLEN;
	const char* 	dpend	= dp + size - 1;

	while (*sp != '\0' && dp < dpend) {
		if (isalnum((unsigned int)*sp))
			*dp++ = *sp;
		sp++;
	}
	*dp = EOS;
}

int
st_ttylock(const char *serial_device)
{
	char rawname[64];

	if (serial_device == NULL) {
		errno = EFAULT;
		return -3;
	}
	raw_device (serial_device, rawname, sizeof(rawname));
	return(DoLock("LCK..", rawname));
}

/*
 * Unlock a tty (remove its lockfile) 
 * do we need to check, if its (still) ours? No, IMHO, if someone else
 * locked our line, it's his fault  -tho
 * returns 0 on success
 * <0 if some failure occured
 */ 

int
st_ttyunlock(const char *serial_device)
{
	char rawname[64];

	if (serial_device == NULL) {
		errno = EFAULT;
		return -3;
	}

	raw_device (serial_device, rawname, sizeof(rawname));
	return(DoUnlock("LCK..", rawname));
}

/* This is what the FHS standard specifies for the size of our lock file */
#define	LOCKSTRLEN	11

static int
DoLock(const char * prefix, const char *lockname)
{
	char lf_name[256], tf_name[256], buf[LOCKSTRLEN+1];
	int fd;
	long pid, mypid;
	int rc;
	struct stat sbuf;

	mypid = (unsigned long) getpid();

	snprintf(lf_name, sizeof(lf_name), "%s/%s%s"
	,	HA_VARLOCKDIR, prefix, lockname);

	snprintf(tf_name, sizeof(tf_name), "%s/tmp%lu-%s"
	,	HA_VARLOCKDIR, mypid, lockname);

	if ((fd = open(lf_name, O_RDONLY)) >= 0) {
		if (fstat(fd, &sbuf) >= 0 && sbuf.st_size < LOCKSTRLEN) {
			sleep(1); /* if someone was about to create one,
			   	   * give'm a sec to do so
				   * Though if they follow our protocol,
				   * this won't happen.  They should really
				   * put the pid in, then link, not the
				   * other way around.
				   */
		}
		if (read(fd, buf, sizeof(buf)) < 1) {
			/* lockfile empty -> rm it and go on */;
		} else {
			if (sscanf(buf, "%lu", &pid) < 1) {
				/* lockfile screwed up -> rm it and go on */
			} else {
				if (pid > 1 && ((long)getpid() != pid)
				    &&	((CL_KILL((pid_t)pid, 0) >= 0)
					 ||	errno != ESRCH)) {
					/* tty is locked by existing (not
					 * necessarily running) process
					 * -> give up */
					close(fd);
					return -1;
				} else {
					/* stale lockfile -> rm it and go on */
				}
			}
		}
		unlink(lf_name);
	}
	if ((fd = open(tf_name, O_CREAT | O_WRONLY | O_EXCL, 0644)) < 0) {
		/* Hmmh, why did we fail? Anyway, nothing we can do about it */
		return -3;
	}

	/* Slight overkill with the %*d format ;-) */
	snprintf(buf, sizeof(buf), "%*lu\n", LOCKSTRLEN-1, mypid);

	if (write(fd, buf, LOCKSTRLEN) != LOCKSTRLEN) {
		/* Again, nothing we can do about this */
		return -3;
	}
	close(fd);

	switch (link(tf_name, lf_name)) {
	case 0:
		if (stat(tf_name, &sbuf) < 0) {
			/* something weird happened */
			rc = -3;
			break;
		}
		if (sbuf.st_nlink < 2) {
			/* somehow, it didn't get through - NFS trouble? */
			rc = -2;
			break;
		}
		rc = 0;
		break;
	case EEXIST:
		rc = -1;
		break;
	default:
		rc = -3;
	}
	unlink(tf_name);
	return rc;
}

static int
DoUnlock(const char * prefix, const char *lockname)
{
	char lf_name[256];
	
	snprintf(lf_name, sizeof(lf_name), "%s/%s%s", HA_VARLOCKDIR
	,	prefix, lockname);
	return unlink(lf_name);
}
