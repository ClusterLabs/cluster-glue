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

/*
 * Functions to support syslog.
 * 	David Lee (c) 2005
 */

#ifndef _CLPLUMBING_CL_SYSLOG_H
#define _CLPLUMBING_CL_SYSLOG_H

/* Convert string "auth" to equivalent number "LOG_AUTH" etc. */
int cl_syslogfac_str2int(const char *);

/* Convert number "LOG_AUTH" to equivalent string "auth" etc. */
/* Returns static string; caller must NOT free. */
const char *cl_syslogfac_int2str(int);

#endif /* _CLPLUMBING_CL_SYSLOG_H */
