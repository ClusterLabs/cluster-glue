/*
 * Functions to support syslog.
 *	David Lee (c) 2005
 */
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

/*
 * Some OSes already have tables to convert names into corresponding numbers.
 * For instance Linux makes these available if SYSLOG_NAMES is defined.
 */
#define SYSLOG_NAMES
#include <stdlib.h>
#include <clplumbing/cl_syslog.h>

#include <syslog.h>
#include <string.h>

struct _syslog_code {
	const char *c_name;
	int c_val;
};

#if defined(HAVE_SYSLOG_FACILITYNAMES)

/*
 * <cl_syslog.h> will have included a table called "facilitynames" structured
 * as a "struct _syslog_code" but the tag "_syslog_code" may be something else.
 */

#else

struct _syslog_code facilitynames[] =
{
#ifdef LOG_AUTH
	{ "auth", LOG_AUTH },
	{ "security", LOG_AUTH },           /* DEPRECATED */
#endif
#ifdef LOG_AUTHPRIV
	{ "authpriv", LOG_AUTHPRIV },
#endif
#ifdef LOG_CRON
	{ "cron", LOG_CRON },
#endif
#ifdef LOG_DAEMON
	{ "daemon", LOG_DAEMON },
#endif
#ifdef LOG_FTP
	{ "ftp", LOG_FTP },
#endif
#ifdef LOG_KERN
	{ "kern", LOG_KERN },
#endif
#ifdef LOG_LPR
	{ "lpr", LOG_LPR },
#endif
#ifdef LOG_MAIL
	{ "mail", LOG_MAIL },
#endif

/*	{ "mark", INTERNAL_MARK },           * INTERNAL */

#ifdef LOG_NEWS
	{ "news", LOG_NEWS },
#endif
#ifdef LOG_SYSLOG
	{ "syslog", LOG_SYSLOG },
#endif
#ifdef LOG_USER
	{ "user", LOG_USER },
#endif
#ifdef LOG_UUCP
	{ "uucp", LOG_UUCP },
#endif
#ifdef LOG_LOCAL0
	{ "local0", LOG_LOCAL0 },
#endif
#ifdef LOG_LOCAL1
	{ "local1", LOG_LOCAL1 },
#endif
#ifdef LOG_LOCAL2
	{ "local2", LOG_LOCAL2 },
#endif
#ifdef LOG_LOCAL3
	{ "local3", LOG_LOCAL3 },
#endif
#ifdef LOG_LOCAL4
	{ "local4", LOG_LOCAL4 },
#endif
#ifdef LOG_LOCAL5
	{ "local5", LOG_LOCAL5 },
#endif
#ifdef LOG_LOCAL6
	{ "local6", LOG_LOCAL6 },
#endif
#ifdef LOG_LOCAL7
	{ "local7", LOG_LOCAL7 },
#endif
	{ NULL, -1 }
};

#endif /* HAVE_SYSLOG_FACILITYNAMES */

/* Convert string "auth" to equivalent number "LOG_AUTH" etc. */
int
cl_syslogfac_str2int(const char *fname)
{
	int i;

	if(fname == NULL || strcmp("none", fname) == 0) {
		return 0;
	}
	
	for (i = 0; facilitynames[i].c_name != NULL; i++) {
		if (strcmp(fname, facilitynames[i].c_name) == 0) {
			return facilitynames[i].c_val;
		}
	}
	return -1;
}

/* Convert number "LOG_AUTH" to equivalent string "auth" etc. */
const char *
cl_syslogfac_int2str(int fnum)
{
	int i;

	for (i = 0; facilitynames[i].c_name != NULL; i++) {
		if (facilitynames[i].c_val == fnum) {
			return facilitynames[i].c_name;
		}
	}
	return NULL;
}
