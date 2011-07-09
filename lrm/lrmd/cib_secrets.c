/*
 * cib_secrets.c
 *
 * Author: Dejan Muhamedagic <dejan@suse.de>
 * Copyright (c) 2011 SUSE, Attachmate
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <lha_internal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include <glib.h>
#include <pils/plugin.h>
#include <pils/generic.h>
#include <clplumbing/GSource.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/cl_signal.h>
#include <clplumbing/proctrack.h>
#include <clplumbing/coredumps.h>
#include <clplumbing/uids.h>
#include <clplumbing/Gmain_timeout.h>
#include <clplumbing/cl_pidfile.h>
#include <clplumbing/realtime.h>
#include <clplumbing/md5.h>
#include <ha_msg.h>

#include <lrm/lrm_api.h>
#include <lrm/lrm_msg.h>

#include <lrmd.h>

int replace_secret_params(char *rsc_id, GHashTable* params);
static int is_magic_value(char *p);
static int check_md5_hash(char *hash, char *value);
static void add_secret_params(gpointer key, gpointer value, gpointer user_data);
static char *read_local_file(char *local_file);

#define MAGIC "lrm://"

static int
is_magic_value(char *p)
{
	return !strcmp(p, MAGIC);
}

#define MD5LEN 16
static int
check_md5_hash(char *hash, char *value)
{
	int i;
	char hash2[2*MD5LEN+1];
	unsigned char binary[MD5LEN+1];

	MD5((unsigned char *)value, strlen(value), binary);
	for (i = 0; i < MD5LEN; i++)
		sprintf(hash2+2*i, "%02x", binary[i]);
	hash2[2*i] = '\0';
	lrmd_debug2(LOG_DEBUG
		, "%s:%d: hash: %s, calculated hash: %s"
		, __FUNCTION__, __LINE__, hash, hash2);
	return !strcmp(hash, hash2);
}

static char *
read_local_file(char *local_file)
{
	FILE *fp = fopen(local_file, "r");
	char buf[MAX_VALUE_LEN+1];
	char *p;

	if (!fp) {
		if (errno != ENOENT) {
			cl_perror("%s:%d: cannot open %s"
			, __FUNCTION__, __LINE__, local_file);
		}
		return NULL;
	}
	if (!fgets(buf, MAX_VALUE_LEN, fp)) {
		cl_perror("%s:%d: cannot read %s"
		, __FUNCTION__, __LINE__, local_file);
		return NULL;
	}
	/* strip white space */
	for (p = buf+strlen(buf)-1; p >= buf && isspace(*p); p--)
		;
	*(p+1) = '\0';
	return g_strdup(buf);
}

/*
 * returns 0 on success or no replacements necessary
 * returns -1 if replacement failed for whatever reasone
 */

int
replace_secret_params(char *rsc_id, GHashTable* params)
{
	char local_file[FILENAME_MAX+1], *start_pname;
	char hash_file[FILENAME_MAX+1], *hash;
	GList *secret_params = NULL, *l;
	char *key, *pvalue, *secret_value;
	int rc = 0;

	/* secret_params could be cached with the resource;
	 * there are also parameters sent with operations
	 * which cannot be cached
	*/
	g_hash_table_foreach(params, add_secret_params, &secret_params);
	if (!secret_params) /* none found? */
		return 0;

	lrmd_debug(LOG_DEBUG
		, "%s:%d: replace secret parameters for resource %s"
		, __FUNCTION__, __LINE__, rsc_id);
	if (snprintf(local_file, FILENAME_MAX,
			LRM_CIBSECRETS "/%s/", rsc_id) > FILENAME_MAX) {
		lrmd_log(LOG_ERR
			, "%s:%d: filename size exceeded for resource %s"
			, __FUNCTION__, __LINE__, rsc_id);
		return -1;
	}
	start_pname = local_file + strlen(local_file);

	for (l = g_list_first(secret_params); l; l = g_list_next(l)) {
		key = (char *)(l->data);
		pvalue = g_hash_table_lookup(params, key);
		if (!pvalue) { /* this cannot really happen */
			lrmd_log(LOG_ERR
				, "%s:%d: odd, no parameter %s for rsc %s found now"
				, __FUNCTION__, __LINE__, key, rsc_id);
			continue;
		}
		if ((strlen(key) + strlen(local_file)) >= FILENAME_MAX-2) {
			lrmd_log(LOG_ERR
				, "%s:%d: parameter name %s too big"
				, __FUNCTION__, __LINE__, key);
			rc = -1;
			continue;
		}
		strcpy(start_pname, key);
		secret_value = read_local_file(local_file);
		if (!secret_value) {
			lrmd_log(LOG_ERR
				, "%s:%d: secret for rsc %s parameter %s "
				"not found in " LRM_CIBSECRETS
				, __FUNCTION__, __LINE__, rsc_id, key);
			rc = -1;
			continue;
		}
		strcpy(hash_file, local_file);
		if (strlen(hash_file) + 5 > FILENAME_MAX) {
			lrmd_log(LOG_ERR
				, "%s:%d: cannot build such a long name "
				"for the sign file: %s.sign"
				, __FUNCTION__, __LINE__, hash_file);
		} else {
			strncat(hash_file, ".sign", 5);
			hash = read_local_file(hash_file);
			if (!check_md5_hash(hash, secret_value)) {
				lrmd_log(LOG_ERR
					, "%s:%d: md5 sum for rsc %s parameter %s "
					"does not match"
					, __FUNCTION__, __LINE__, rsc_id, key);
				g_free(secret_value);
				g_free(hash);
				rc = -1;
				continue;
			}
			g_free(hash);
		}
		g_hash_table_replace(params, g_strdup(key), secret_value);
	}
	g_list_free(secret_params);
	return rc;
}

static void
add_secret_params(gpointer key, gpointer value, gpointer user_data)
{
	GList **lp = (GList **)user_data;

	if (is_magic_value((char *)value))
		*lp = g_list_append(*lp, (char *)key);
}
