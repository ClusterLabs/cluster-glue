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

#ifndef CLPLUMBING_UIDS_H
#	define CLPLUMBING_UIDS_H
#include <sys/types.h>

/* Tell us who you want to be - or zero for nobody */
int drop_privs(uid_t uid, gid_t gid);

/* Return to original privileged state */
int return_to_orig_privs(void);

/* Drop down to (probably nobody) privileges again */
int return_to_dropped_privs(void);

/* Return TRUE if we have full privileges at the moment */
int cl_have_full_privs(void);
#endif
