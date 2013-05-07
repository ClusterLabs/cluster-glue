/*
 * Stonith module for EXTERNAL Stonith device
 *
 * Copyright (c) 2001 SuSE Linux AG
 * Portions Copyright (c) 2004, tummy.com, ltd.
 *
 * Based on ssh.c, Authors: Joachim Gleissner <jg@suse.de>,
 *                          Lars Marowsky-Bree <lmb@suse.de>
 * Modified for external.c: Scott Kleihege <scott@tummy.com>
 * Reviewed, tested, and config parsing: Sean Reifschneider <jafo@tummy.com>
 * And overhauled by Lars Marowsky-Bree <lmb@suse.de>, so the circle
 *   closes...
 * Mangled by Zhaokai <zhaokai@cn.ibm.com>, IBM, 2005
 * Changed to allow full-featured external plugins by Dave Blaschke 
 *   <debltc@us.ibm.com>
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
 */

#include <lha_internal.h>

#include <dirent.h>

#include "stonith_plugin_common.h"

#define PIL_PLUGIN              external
#define PIL_PLUGIN_S            "external"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL

#include <pils/plugin.h>

static StonithPlugin *	external_new(const char *);
static void		external_destroy(StonithPlugin *);
static int		external_set_config(StonithPlugin *, StonithNVpair *);
static const char * const *	external_get_confignames(StonithPlugin *);
static const char *	external_getinfo(StonithPlugin * s, int InfoType);
static int		external_status(StonithPlugin * );
static int		external_reset_req(StonithPlugin * s, int request, const char * host);
static char **		external_hostlist(StonithPlugin  *);

static struct stonith_ops externalOps ={
	external_new,			/* Create new STONITH object	  */
	external_destroy,		/* Destroy STONITH object	  */
	external_getinfo,		/* Return STONITH info string	  */
	external_get_confignames,	/* Return STONITH info string	  */
	external_set_config,		/* Get configuration from NVpairs */
	external_status,		/* Return STONITH device status	  */
	external_reset_req,		/* Request a reset 		  */
	external_hostlist,		/* Return list of supported hosts */
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug)
static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static StonithImports*		OurImports;
static void*			interfprivate;

PIL_rc
PIL_PLUGIN_INIT(PILPlugin*us, const PILPluginImports* imports);

PIL_rc
PIL_PLUGIN_INIT(PILPlugin*us, const PILPluginImports* imports)
{
	/* Force the compiler to do a little type checking */
	(void)(PILPluginInitFun)PIL_PLUGIN_INIT;

	PluginImports = imports;
	OurPlugin = us;

	/* Register ourself as a plugin */
	imports->register_plugin(us, &OurPIExports);  

	/*  Register our interface implementation */
 	return imports->register_interface(us, PIL_PLUGINTYPE_S
	,	PIL_PLUGIN_S
	,	&externalOps
	,	NULL			/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*
 *    EXTERNAL STONITH device
 */

struct pluginDevice {
	StonithPlugin	sp;
	const char *	pluginid;
	GHashTable *	cmd_opts;
	char *		subplugin;
	char **		confignames;
	char *		outputbuf;
};

static const char * pluginid = "ExternalDevice-Stonith";
static const char * NOTpluginID = "External device has been destroyed";

/* Prototypes */

/* Run the command with op and return the exit status + the output 
 * (NULL -> discard output) */
static int external_run_cmd(struct pluginDevice *sd, const char *op, 
		char **output);
/* Just free up the configuration and the memory, if any */
static void external_unconfig(struct pluginDevice *sd);

static int
external_status(StonithPlugin  *s)
{
	struct pluginDevice *	sd;
	const char *		op = "status";
	int			rc;
	
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,S_OOPS);

	sd = (struct pluginDevice*) s;
	if (sd->subplugin == NULL) {
		LOG(PIL_CRIT, "%s: invoked without subplugin", __FUNCTION__);
		return(S_OOPS);
	}
	
	rc = external_run_cmd(sd, op, NULL);
	if (rc != 0) {
		LOG(PIL_WARN, "%s: '%s %s' failed with rc %d",
			__FUNCTION__, sd->subplugin, op, rc);
	}
	else {
		if (Debug) {
			LOG(PIL_DEBUG, "%s: running '%s %s' returned %d",
				__FUNCTION__, sd->subplugin, op, rc);
		}
	}
	return rc;
}

static int
get_num_tokens(char *str)
{
	int namecount = 0;

	while (*str != EOS) {
		str += strspn(str, WHITESPACE);
		if (*str == EOS)
			break;
		str += strcspn(str, WHITESPACE);
		namecount++;
	}
	return namecount;
}

static char **
external_hostlist(StonithPlugin  *s)
{
	struct pluginDevice*	sd;
	const char *		op = "gethosts";
	int			rc, i, namecount;
	char **			ret;
	char *			output = NULL;
	char *			tmp;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	ERRIFNOTCONFIGED(s,NULL);

	sd = (struct pluginDevice*) s;
	if (sd->subplugin == NULL) {
		LOG(PIL_CRIT, "%s: invoked without subplugin", __FUNCTION__);
		return(NULL);
	}

	rc = external_run_cmd(sd, op, &output);
	if (rc != 0) {
		LOG(PIL_CRIT, "%s: '%s %s' failed with rc %d",
			__FUNCTION__, sd->subplugin, op, rc);
		if (output) {
			LOG(PIL_CRIT, "plugin output: %s", output);
			FREE(output);
		}
		return NULL;
	}
	if (Debug) {
		LOG(PIL_DEBUG, "%s: running '%s %s' returned %d",
			__FUNCTION__, sd->subplugin, op, rc);
	}

	if (!output) {
		LOG(PIL_CRIT, "%s: '%s %s' returned an empty hostlist",
			__FUNCTION__, sd->subplugin, op);
		return NULL;
	}
	
	namecount = get_num_tokens(output);	
	ret = MALLOC((namecount+1)*sizeof(char *));
	if (!ret) {
		LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
		FREE(output);
		return NULL;
	}
	memset(ret, 0, (namecount+1)*sizeof(char *));

	/* White-space split the output here */
	i = 0;
	tmp = strtok(output, WHITESPACE);
	while (tmp != NULL) {
		if (Debug) {
			LOG(PIL_DEBUG, "%s: %s host %s",
				__FUNCTION__, sd->subplugin, tmp);
		}
		ret[i] = STRDUP(tmp);
		if (!ret[i]) {
			LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
			FREE(output);
			stonith_free_hostlist(ret);
			return NULL;
		}
		i++;
		tmp = strtok(NULL, WHITESPACE);
	}

	FREE(output);

	if (i == 0) {
		LOG(PIL_CRIT, "%s: '%s %s' returned an empty hostlist",
			__FUNCTION__, sd->subplugin, op);
		stonith_free_hostlist(ret);
		ret = NULL;
	}

	return(ret);
}

static int
external_reset_req(StonithPlugin * s, int request, const char * host)
{
	struct pluginDevice *	sd;
	const char *		op;
	int			rc;
	char *			args1and2;
	int			argslen;
	
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	ERRIFNOTCONFIGED(s,S_OOPS);
	
	if (Debug) {
		LOG(PIL_DEBUG, "Host external-reset initiating on %s", host);
	}

	sd = (struct pluginDevice*) s;
	if (sd->subplugin == NULL) {
		LOG(PIL_CRIT, "%s: invoked without subplugin", __FUNCTION__);
		return(S_OOPS);
	}

	switch (request) {
		case ST_GENERIC_RESET:
			op = "reset";
			break;

		case ST_POWEROFF:
			op = "off";
			break;
			
		case ST_POWERON:
			op = "on";
			break;
			
		default:
			LOG(PIL_CRIT, "%s: Unknown stonith request %d",
				__FUNCTION__, request);
			return S_OOPS;
			break;
	}
	
	argslen = strlen(op) + strlen(host) + 2 /* 1 for blank, 1 for EOS */;
	args1and2 = (char *)MALLOC(argslen);
	if (args1and2 == NULL) {
		LOG(PIL_CRIT, "%s: out of memory!", __FUNCTION__);
		return S_OOPS;
	}
	rc = snprintf(args1and2, argslen, "%s %s", op, host);
	if (rc <= 0 || rc >= argslen) {
		FREE(args1and2);
		return S_OOPS;
	}
	
	rc = external_run_cmd(sd, args1and2, NULL);
	FREE(args1and2);
	if (rc != 0) {
		LOG(PIL_CRIT, "%s: '%s %s' for host %s failed with rc %d",
			__FUNCTION__, sd->subplugin, op, host, rc);
		return S_RESETFAIL;
	}
	else {
		if (Debug) {
			LOG(PIL_DEBUG, "%s: running '%s %s' returned %d",
				__FUNCTION__, sd->subplugin, op, rc);
		}
		return S_OK;
	}
	
}

static int
external_parse_config_info(struct pluginDevice* sd, StonithNVpair * info)
{
	char * 		key;
	char *		value;
	StonithNVpair *	nv;
	
	sd->cmd_opts = g_hash_table_new(g_str_hash, g_str_equal);

	/* TODO: Maybe treat "" as delimeters too so
	 * whitespace can be passed to the plugins... */
	for (nv = info; nv->s_name; nv++) {
		if (!nv->s_name || !nv->s_value) {
			continue;
		}

		key = STRDUP(nv->s_name);
		if (!key) {
			goto err_mem;
		}
		value = STRDUP(nv->s_value);
		if (!value) {
			FREE(key);
			goto err_mem;
		}
		g_hash_table_insert(sd->cmd_opts, key, value);
	}
		
	return(S_OK);

err_mem:
	LOG(PIL_CRIT, "%s: out of memory!", __FUNCTION__);
	external_unconfig(sd);
	
	return(S_OOPS);
}

static gboolean
let_remove_eachitem(gpointer key, gpointer value, gpointer user_data)
{
	if (key) {
		FREE(key);
	}
	if (value) {
		FREE(value);
	}
        return TRUE;
}

static void
external_unconfig(struct pluginDevice *sd) {
	if (sd->cmd_opts) {
		g_hash_table_foreach_remove(sd->cmd_opts, 
				let_remove_eachitem, NULL);
		g_hash_table_destroy(sd->cmd_opts);	
		sd->cmd_opts = NULL;
	}
}

/*
 *	Parse the information in the given string 
 *	and stash it away...
 */
static int
external_set_config(StonithPlugin* s, StonithNVpair *list)
{
	struct pluginDevice *	sd;
	char **			p;
	
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,S_OOPS);

	/*  make sure that command has not already been set  */
	if (s->isconfigured) {
		return(S_OOPS);
	}

	sd = (struct pluginDevice*) s;
	if (sd->subplugin == NULL) {
		LOG(PIL_CRIT, "%s: invoked without subplugin", __FUNCTION__);
		return(S_OOPS);
	}

	if (sd->confignames == NULL) {
		/* specified by name=value pairs, check required parms */
		if (external_get_confignames(s) == NULL) {
			return(S_OOPS);
		}

		for (p = sd->confignames; *p; p++) {
			if (OurImports->GetValue(list, *p) == NULL) {
				LOG(PIL_DEBUG, "Cannot get parameter %s from "
					"StonithNVpair", *p);
			}
		}
	}

	return external_parse_config_info(sd, list);
}


/* Only interested in regular files that are also executable */
static int
exec_select(const struct dirent *dire)
{
	struct stat	statf;
	char		filename[FILENAME_MAX];
	int		rc;

	rc = snprintf(filename, FILENAME_MAX, "%s/%s", 
		STONITH_EXT_PLUGINDIR, dire->d_name);
	if (rc <= 0 || rc >= FILENAME_MAX) {
		return 0;
	}
	
	if ((stat(filename, &statf) == 0) &&
	    (S_ISREG(statf.st_mode)) &&
            (statf.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH))) {
		if (statf.st_mode & (S_IWGRP|S_IWOTH)) {
			LOG(PIL_WARN, "Executable file %s ignored "
				"(writable by group/others)", filename);
			return 0;
		}else{
			return 1;
		}
	}

	return 0;
}

/*
 * Return STONITH config vars
 */
static const char * const *
external_get_confignames(StonithPlugin* p)
{
  	struct pluginDevice *	sd;
	const char *		op = "getconfignames";
	int 			i, rc;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	sd = (struct pluginDevice *)p;

	if (sd->subplugin != NULL) {
		/* return list of subplugin's required parameters */
		char	*output = NULL, *pch;
		int	namecount;

		rc = external_run_cmd(sd, op, &output);
		if (rc != 0) {
			LOG(PIL_CRIT, "%s: '%s %s' failed with rc %d",
				__FUNCTION__, sd->subplugin, op, rc);
			if (output) {
				LOG(PIL_CRIT, "plugin output: %s", output);
				FREE(output);
			}
			return NULL;
		}
		if (Debug) {
			LOG(PIL_DEBUG, "%s: '%s %s' returned %d",
				__FUNCTION__, sd->subplugin, op, rc);
			if (output) {
				LOG(PIL_DEBUG, "plugin output: %s", output);
			}
		}
		
		namecount = get_num_tokens(output);
		sd->confignames = (char **)MALLOC((namecount+1)*sizeof(char *));
		if (sd->confignames == NULL) {
			LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
			if (output) { FREE(output); }
			return NULL;
		}

		/* now copy over confignames */
		pch = strtok(output, WHITESPACE);		
		for (i = 0; i < namecount; i++) {
			if (Debug) {
				LOG(PIL_DEBUG, "%s: %s configname %s",
					__FUNCTION__, sd->subplugin, pch);
			}
			sd->confignames[i] = STRDUP(pch);
			pch = strtok(NULL, WHITESPACE);
		}
		FREE(output);
		sd->confignames[namecount] = NULL;
	}else{
		/* return list of subplugins in external directory */
		struct dirent **	files = NULL;
		int			dircount;

		/* get the external plugin's confignames (list of subplugins) */
		dircount = scandir(STONITH_EXT_PLUGINDIR, &files,
				SCANSEL_CAST exec_select, NULL);
		if (dircount < 0) {
			return NULL;
		}
	
		sd->confignames = (char **)MALLOC((dircount+1)*sizeof(char *));
		if (!sd->confignames) {
			LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
			return NULL;
		}

		for (i = 0; i < dircount; i++) {
			sd->confignames[i] = STRDUP(files[i]->d_name);
			free(files[i]);
			files[i] = NULL;
		}
		free(files);
		sd->confignames[dircount] = NULL;
	}

	return (const char * const *)sd->confignames;
}

/*
 * Return STONITH info string
 */
static const char *
external_getinfo(StonithPlugin * s, int reqtype)
{
	struct pluginDevice* sd;
	char *		output = NULL;
	const char *	op;
	int rc;
  
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,NULL);

	sd = (struct pluginDevice *)s;
	if (sd->subplugin == NULL) {
		LOG(PIL_CRIT, "%s: invoked without subplugin", __FUNCTION__);
		return(NULL);
	}

	switch (reqtype) {
		case ST_DEVICEID:
			op = "getinfo-devid";
			break;

		case ST_DEVICENAME:
			op = "getinfo-devname";
			break;

		case ST_DEVICEDESCR:
			op = "getinfo-devdescr";
			break;

		case ST_DEVICEURL:
			op = "getinfo-devurl";
			break;

		case ST_CONF_XML:
			op = "getinfo-xml";
			break;

		default:
			return NULL;
	}

	rc = external_run_cmd(sd, op, &output);
	if (rc != 0) {
		LOG(PIL_CRIT, "%s: '%s %s' failed with rc %d",
			__FUNCTION__, sd->subplugin, op, rc);
		if (output) {
			LOG(PIL_CRIT, "plugin output: %s", output);
			FREE(output);
		}
	}
	else {
		if (Debug) {
			LOG(PIL_DEBUG, "%s: '%s %s' returned %d",
				__FUNCTION__, sd->subplugin, op, rc);
		}
		if (sd->outputbuf != NULL) {
			FREE(sd->outputbuf);
		}
		sd->outputbuf =  output;
		return(output);
	}
	return(NULL);
}

/*
 *	EXTERNAL Stonith destructor...
 */
static void
external_destroy(StonithPlugin *s)
{
	struct pluginDevice *	sd;
	char **			p;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	VOIDERRIFWRONGDEV(s);

	sd = (struct pluginDevice *)s;

	sd->pluginid = NOTpluginID;
	external_unconfig(sd);
	if (sd->confignames != NULL) {
		for (p = sd->confignames; *p; p++) {
			FREE(*p);
		}
		FREE(sd->confignames);
		sd->confignames = NULL;
	}
	if (sd->subplugin != NULL) {
		FREE(sd->subplugin);
		sd->subplugin = NULL;
	}
	if (sd->outputbuf != NULL) {
		FREE(sd->outputbuf);
		sd->outputbuf = NULL;
	}
	FREE(sd);
}

/* Create a new external Stonith device */
static StonithPlugin *
external_new(const char *subplugin)
{
	struct pluginDevice*	sd = ST_MALLOCT(struct pluginDevice);

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	if (sd == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(sd, 0, sizeof(*sd));
	sd->pluginid = pluginid;
	if (subplugin != NULL) {
		sd->subplugin = STRDUP(subplugin);
		if (sd->subplugin == NULL) {
			FREE(sd);
			return(NULL);
		}
	}
	sd->sp.s_ops = &externalOps;
	return &(sd->sp);
}

static void
ext_add_to_env(gpointer key, gpointer value, gpointer user_data)
{
	if (setenv((char *)key, (char *)value, 1) != 0) {
		LOG(PIL_CRIT, "%s: setenv failed.", __FUNCTION__);
	}
}

static void
ext_del_from_env(gpointer key, gpointer value, gpointer user_data)
{
	unsetenv((char *)key);
}

#define LOGTAG_VAR "HA_LOGTAG"

/* Run the command with op as command line argument(s) and return the exit
 * status + the output */
static int 
external_run_cmd(struct pluginDevice *sd, const char *op, char **output)
{
	const int		BUFF_LEN=4096;
	char			buff[BUFF_LEN];
	int			read_len = 0;
	int			status, rc;
	char * 			data = NULL;
	FILE *			file;
	char			cmd[FILENAME_MAX+64];
	struct stat		buf;
	int			slen;
	char *path, *new_path, *logtag, *savevar = NULL;
	int new_path_len, logtag_len;
	gboolean		nodata;

	rc = snprintf(cmd, FILENAME_MAX, "%s/%s", 
		STONITH_EXT_PLUGINDIR, sd->subplugin);
	if (rc <= 0 || rc >= FILENAME_MAX) {
		LOG(PIL_CRIT, "%s: external command too long.", __FUNCTION__);
		return -1;
	}
	
	if (stat(cmd, &buf) != 0) {
		LOG(PIL_CRIT, "%s: stat(2) of %s failed: %s",
			__FUNCTION__, cmd, strerror(errno));
                return -1;
        }

        if (!S_ISREG(buf.st_mode) 
	    || (!(buf.st_mode & (S_IXUSR|S_IXGRP|S_IXOTH)))) {
		LOG(PIL_CRIT, "%s: %s found NOT to be executable.",
			__FUNCTION__, cmd);
		return -1;
	}

	if (buf.st_mode & (S_IWGRP|S_IWOTH)) {
		LOG(PIL_CRIT, "%s: %s found to be writable by group/others, "
			"NOT executing for security purposes.",
			__FUNCTION__, cmd);
		return -1;
	}

	strcat(cmd, " ");
	strcat(cmd, op);

	/* We only have a global environment to use here. So we add our
	 * options to it, and then later remove them again. */
	if (sd->cmd_opts) {
		g_hash_table_foreach(sd->cmd_opts, ext_add_to_env, NULL);
	}

	/* external plugins need path to ha_log.sh */
	path = getenv("PATH");
	if (strncmp(GLUE_SHARED_DIR,path,strlen(GLUE_SHARED_DIR))) {
		new_path_len = strlen(path)+strlen(GLUE_SHARED_DIR)+2;
		new_path = (char *)g_malloc(new_path_len);
		snprintf(new_path, new_path_len, "%s:%s", GLUE_SHARED_DIR, path);
		setenv("PATH", new_path, 1);
		g_free(new_path);
	}

	/* set the logtag appropriately */
	logtag_len = strlen(PIL_PLUGIN_S)+strlen(sd->subplugin)+2;
	logtag = (char *)g_malloc(logtag_len);
	snprintf(logtag, logtag_len, "%s/%s", PIL_PLUGIN_S, sd->subplugin);
	if (getenv(LOGTAG_VAR)) {
		savevar = g_strdup(getenv(LOGTAG_VAR));
	}
	setenv(LOGTAG_VAR, logtag, 1);
	g_free(logtag);

	if (Debug) {
		LOG(PIL_DEBUG, "%s: Calling '%s'", __FUNCTION__, cmd );
	}
	file = popen(cmd, "r");
	if (NULL==file) {
		LOG(PIL_CRIT, "%s: Calling '%s' failed",
			__FUNCTION__, cmd);
		rc = -1;
		goto out;
	}

	if (output) {
		slen=0;
		data = MALLOC(1);
		data[slen] = EOS;
	}
	while (!feof(file)) {
		nodata = TRUE;
		if (output) {
			read_len = fread(buff, 1, BUFF_LEN, file);
			if (read_len > 0) {
				data = REALLOC(data, slen+read_len+1);
				if (data == NULL) {
					break;
				}
				memcpy(data + slen, buff, read_len);
				slen += read_len;
				data[slen] = EOS;
				nodata = FALSE;
			}
		} else {
			if (fgets(buff, BUFF_LEN, file)) {	
				LOG(PIL_INFO, "%s: '%s' output: %s", __FUNCTION__, cmd, buff);
				nodata = FALSE;
			}
		}
		if (nodata) {
			sleep(1);
		}
	}
	if (output && !data) {
		LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
		rc = -1;
		goto out;
	}

	status = pclose(file);
	if (WIFEXITED(status)) {
		rc = WEXITSTATUS(status);
		if (rc != 0 && Debug) {
			LOG(PIL_DEBUG,
				"%s: Calling '%s' returned %d", __FUNCTION__, cmd, rc);
		}
	} else {
		if (WIFSIGNALED(status)) {
			LOG(PIL_CRIT, "%s: '%s' got signal %d",
				__FUNCTION__, cmd, WTERMSIG(status));
		} else if (WIFSTOPPED(status)) {
			LOG(PIL_INFO, "%s: '%s' stopped with signal %d",
				__FUNCTION__, cmd, WSTOPSIG(status));
		} else {
			LOG(PIL_CRIT, "%s: '%s' exited abnormally (core dumped?)",
				__FUNCTION__, cmd);
		}
		rc = -1;
	}
	if (Debug && output && data) {
		LOG(PIL_DEBUG, "%s: '%s' output: %s", __FUNCTION__, cmd, data);
	}

out:
	if (savevar) {
		setenv(LOGTAG_VAR, savevar, 1);
		g_free(savevar);
	} else {
		unsetenv(LOGTAG_VAR);
	}
	if (sd->cmd_opts)  {
		g_hash_table_foreach(sd->cmd_opts, ext_del_from_env, NULL);
	}
	if (!rc) {
		if (output) {
			*output = data;
		}
	} else {
		if (data) {
			FREE(data);
		}
		if (output) {
			*output = NULL;
		}
	}
	return rc;
}
