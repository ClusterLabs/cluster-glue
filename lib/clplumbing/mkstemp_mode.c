#include <portability.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <clplumbing/mkstemp_mode.h>


/*
 * A slightly safer version of mkstemp(3)
 *
 * In this version, the file is initially created mode 0, and then chmod-ed
 * to the requested permissions.  This guarantees that the file is never
 * open to others beyond the specified permissions at any time.
 */
int
mkstemp_mode(char* template, mode_t filemode)
{

	mode_t	maskval;
	int	fd;

	maskval = umask(0777);

	/* created file should now be mode 0000 */
	fd = mkstemp(template);

	umask(maskval);	/* cannot fail :-) */

	if (fd >= 0) {
		if (chmod(template, filemode) < 0) {
			int	save = errno;
			close(fd);
			errno = save;
			fd = -1;
		}
	}
	return fd;
}
