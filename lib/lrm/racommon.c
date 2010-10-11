/*
 * Common functions for LRM interface to resource agents
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
 * File: racommon.c
 * Author: Sun Jiang Dong <sunjd@cn.ibm.com>
 * Copyright (c) 2004 International Business Machines
 *
 */


#include <lha_internal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>  /* Add it for compiling on OSX */
#include <glib.h>
#include <sys/stat.h>
#include <clplumbing/cl_log.h>
#include <lrm/raexec.h>
#include <lrm/racommon.h>

void
get_ra_pathname(const char* class_path, const char* type, const char* provider,
		char pathname[])
{
	char* type_dup;
	char* base_name;

	type_dup = g_strndup(type, RA_MAX_NAME_LENGTH);
	if (type_dup == NULL) {
		cl_log(LOG_ERR, "No enough memory to allocate.");
		pathname[0] = '\0';
		return;
	}

	base_name = basename(type_dup);

	if ( strncmp(type, base_name, RA_MAX_NAME_LENGTH) == 0 ) {
		/*the type does not include path*/
		if (provider) {
			snprintf(pathname, RA_MAX_NAME_LENGTH, "%s/%s/%s",
				class_path, provider, type);
		}else{
			snprintf(pathname, RA_MAX_NAME_LENGTH, "%s/%s",
				class_path,type);
		}
	}else{
		/*the type includes path, just copy it to pathname*/
		if ( *type == '/' ) {
			g_strlcpy(pathname, type, RA_MAX_NAME_LENGTH);
		} else {
			*pathname = '\0';
			cl_log(LOG_ERR, "%s: relative paths not allowed: %s",
			__FUNCTION__, type);
		}
	}

	g_free(type_dup);
}

/*
 *    Description:   Filter a file.
 *    Return Value:
 *		     TRUE:  the file is qualified.
 *		     FALSE: the file is unqualified.
 *    Notes: A qualifed file is a regular file with execute bits
 *           which does not start with '.'
 */
gboolean
filtered(char * file_name)
{
	struct stat buf;
	char *s;

	if ( stat(file_name, &buf) != 0 ) {
		return FALSE;
	}
	if ( ((s = strrchr(file_name,'/')) && *(s+1) == '.')
			|| *file_name == '.' ) {
		return FALSE;
	}

	if (   S_ISREG(buf.st_mode)
            && (   ( buf.st_mode & S_IXUSR ) || ( buf.st_mode & S_IXGRP )
		|| ( buf.st_mode & S_IXOTH ) ) ) {
		return TRUE;
	}
	return FALSE;
}

int
get_runnable_list(const char* class_path, GList ** rsc_info)
{
	struct dirent **namelist;
	int file_num;

	if ( rsc_info == NULL ) {
		cl_log(LOG_ERR, "Parameter error: get_resource_list");
		return -2;
	}

	if ( *rsc_info != NULL ) {
		cl_log(LOG_ERR, "Parameter error: get_resource_list."\
			"will cause memory leak.");
		*rsc_info = NULL;
	}

	file_num = scandir(class_path, &namelist, NULL, alphasort);
	if (file_num < 0) {
		cl_log(LOG_ERR, "scandir failed in RA plugin");
		return -2;
	} else{
		while (file_num--) {
			char tmp_buffer[FILENAME_MAX+1];

			tmp_buffer[0] = '\0';
			tmp_buffer[FILENAME_MAX] = '\0';
			snprintf(tmp_buffer, FILENAME_MAX, "%s/%s",
				 class_path, namelist[file_num]->d_name );
			if ( filtered(tmp_buffer) == TRUE ) {
				*rsc_info = g_list_append(*rsc_info,
						g_strdup(namelist[file_num]->d_name));
			}
			free(namelist[file_num]);
		}
		free(namelist);
	}
	return g_list_length(*rsc_info);
}

int
get_failed_exec_rc(void)
{
	int rc;

	switch (errno) { /* see execve(2) */
		case ENOENT:  /* No such file or directory */
		case EISDIR:   /* Is a directory */
			rc = EXECRA_NOT_INSTALLED;
			break;
		case EACCES:   /* permission denied (various errors) */
			rc = EXECRA_INSUFFICIENT_PRIV;
			break;
		default:
			rc = EXECRA_EXEC_UNKNOWN_ERROR;
			break;
	}
	return rc;
}

void
closefiles(void)
{
	int fd;

	/* close all descriptors except stdin/out/err and channels to logd */
	for (fd = getdtablesize() - 1; fd > STDERR_FILENO; fd--) {
		/*if (!cl_log_is_logd_fd(fd))*/
			close(fd);
	}
}
