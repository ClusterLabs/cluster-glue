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
