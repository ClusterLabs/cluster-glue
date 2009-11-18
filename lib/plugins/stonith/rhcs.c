/*
 * Stonith module for RedHat Cluster Suite fencing plugins
 *
 * Copyright (c) 2001 SuSE Linux AG
 * Portions Copyright (c) 2004, tummy.com, ltd.
 *
 * Based on ssh.c, Authors: Joachim Gleissner <jg@suse.de>,
 *                          Lars Marowsky-Bree <lmb@suse.de>
 * Modified for external.c: Scott Kleihege <scott@tummy.com>
 * Modified for rhcs.c: Dejan Muhamedagic <dejan@suse.de>
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

#define PIL_PLUGIN              rhcs
#define PIL_PLUGIN_S            "rhcs"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL

#include <pils/plugin.h>

static StonithPlugin *	rhcs_new(const char *);
static void		rhcs_destroy(StonithPlugin *);
static int		rhcs_set_config(StonithPlugin *, StonithNVpair *);
static const char**	rhcs_get_confignames(StonithPlugin *);
static const char *	rhcs_getinfo(StonithPlugin * s, int InfoType);
static int		rhcs_status(StonithPlugin * );
static int		rhcs_reset_req(StonithPlugin * s, int request, const char * host);
static char **		rhcs_hostlist(StonithPlugin  *);

static struct stonith_ops rhcsOps ={
	rhcs_new,			/* Create new STONITH object	  */
	rhcs_destroy,		/* Destroy STONITH object	  */
	rhcs_getinfo,		/* Return STONITH info string	  */
	rhcs_get_confignames,	/* Return STONITH info string	  */
	rhcs_set_config,		/* Get configuration from NVpairs */
	rhcs_status,		/* Return STONITH device status	  */
	rhcs_reset_req,		/* Request a reset 		  */
	rhcs_hostlist,		/* Return list of supported hosts */
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
	,	&rhcsOps
	,	NULL			/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*
 *    RHCS STONITH device
 */

struct pluginDevice {
	StonithPlugin	sp;
	const char *	pluginid;
	GHashTable *	cmd_opts;
	char *		subplugin;
	char **		confignames;
	char *		hostlist;
	char *		outputbuf;
};

static const char * pluginid = "RHCSDevice-Stonith";
static const char * NOTpluginID = "RHCS device has been destroyed";

/* Prototypes */

/* Run the command with op and return the exit status + the output 
 * (NULL -> discard output) */
static int rhcs_run_cmd(struct pluginDevice *sd, const char *op, 
		char **output);
/* Just free up the configuration and the memory, if any */
static void rhcs_unconfig(struct pluginDevice *sd);

static int
rhcs_status(StonithPlugin  *s)
{
	struct pluginDevice *	sd;
	const char *		op = "monitor";
	int			rc;
	char *			output = NULL;
	
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,S_OOPS);

	sd = (struct pluginDevice*) s;
	if (sd->subplugin == NULL) {
		LOG(PIL_CRIT, "%s: invoked without subplugin", __FUNCTION__);
		return(S_OOPS);
	}
	
	rc = rhcs_run_cmd(sd, op, &output);
	if (rc != 0) {
		LOG(PIL_CRIT, "%s: '%s %s' failed with rc %d",
			__FUNCTION__, sd->subplugin, op, rc);
		if (output) {
			LOG(PIL_CRIT, "plugin output: %s", output);
		}
	}
	else {
		if (Debug) {
			LOG(PIL_DEBUG, "%s: running '%s %s' returned %d",
				__FUNCTION__, sd->subplugin, op, rc);
		}
	}
	if (output) {
		FREE(output);
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
rhcs_hostlist(StonithPlugin  *s)
{
	struct pluginDevice*	sd;
	const char *		op = "gethosts";
	int			i, namecount;
	char **			ret;
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

	namecount = get_num_tokens(sd->hostlist);
	ret = MALLOC((namecount+1)*sizeof(char *));
	if (!ret) {
		LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
		return NULL;
	}
	memset(ret, 0, (namecount+1)*sizeof(char *));

	/* White-space split the sd->hostlist here */
	i = 0;
	tmp = strtok(sd->hostlist, WHITESPACE);
	while (tmp != NULL) {
		if (Debug) {
			LOG(PIL_DEBUG, "%s: %s host %s",
				__FUNCTION__, sd->subplugin, tmp);
		}
		ret[i] = STRDUP(tmp);
		if (!ret[i]) {
			LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
			stonith_free_hostlist(ret);
			return NULL;
		}
		i++;
		tmp = strtok(NULL, WHITESPACE);
	}

	if (i == 0) {
		LOG(PIL_CRIT, "%s: '%s %s' returned an empty hostlist",
			__FUNCTION__, sd->subplugin, op);
		stonith_free_hostlist(ret);
		ret = NULL;
	}

	return(ret);
}

static int
rhcs_reset_req(StonithPlugin * s, int request, const char * host)
{
	struct pluginDevice *	sd;
	const char *		op;
	int			rc;
	char *			output = NULL;
	char *k, *v;
	
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	ERRIFNOTCONFIGED(s,S_OOPS);
	
	if (Debug) {
		LOG(PIL_DEBUG, "Host rhcs-reset initiating on %s", host);
	}

	sd = (struct pluginDevice*) s;
	if (sd->subplugin == NULL) {
		LOG(PIL_CRIT, "%s: invoked without subplugin", __FUNCTION__);
		return(S_OOPS);
	}

	switch (request) {
		case ST_GENERIC_RESET:
			op = "reboot";
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
	
	k = g_strdup("nodename");
	v = g_strdup(host);
	g_hash_table_insert(sd->cmd_opts, k, v);
	rc = rhcs_run_cmd(sd, op, &output);
	g_hash_table_remove(sd->cmd_opts, k);
	g_free(k);
	g_free(v);
	if (rc != 0) {
		LOG(PIL_CRIT, "%s: '%s %s' for host %s failed with rc %d",
			__FUNCTION__, sd->subplugin, op, host, rc);
		if (output) {
			LOG(PIL_CRIT, "plugin output: %s", output);
			FREE(output);
		}
		return S_RESETFAIL;
	}
	else {
		if (Debug) {
			LOG(PIL_DEBUG, "%s: running '%s %s' returned %d",
				__FUNCTION__, sd->subplugin, op, rc);
		}
		if (output) {
			LOG(PIL_INFO, "plugin output: %s", output);
			FREE(output);
		}
		return S_OK;
	}
	
}

static int
rhcs_parse_config_info(struct pluginDevice* sd, StonithNVpair * info)
{
	char * 		key;
	char *		value;
	StonithNVpair *	nv;
	
	sd->hostlist = NULL;
	sd->cmd_opts = g_hash_table_new(g_str_hash, g_str_equal);

	/* TODO: Maybe treat "" as delimeters too so
	 * whitespace can be passed to the plugins... */
	for (nv = info; nv->s_name; nv++) {
		key = STRDUP(nv->s_name);
		if (!key) {
			goto err_mem;
		}
		value = STRDUP(nv->s_value);
		if (!value) {
			FREE(key);
			goto err_mem;
		}
		if (!strcmp(key,"hostlist")) {
			sd->hostlist = value;
			FREE(key);
		} else {
			g_hash_table_insert(sd->cmd_opts, key, value);
		}
	}
		
	return(S_OK);

err_mem:
	LOG(PIL_CRIT, "%s: out of memory!", __FUNCTION__);
	rhcs_unconfig(sd);
	
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
rhcs_unconfig(struct pluginDevice *sd) {
	if (sd->cmd_opts) {
		g_hash_table_foreach_remove(sd->cmd_opts, 
				let_remove_eachitem, NULL);
		g_hash_table_destroy(sd->cmd_opts);	
		sd->cmd_opts = NULL;
	}
	if (sd->hostlist) {
		FREE(sd->hostlist);
		sd->hostlist = NULL;
	}
}

/*
 *	Parse the information in the given string 
 *	and stash it away...
 */
static int
rhcs_set_config(StonithPlugin* s, StonithNVpair *list)
{
	struct pluginDevice *	sd;
	
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

#if 0
	/* the required parameters may be acquired from the metadata
	 * */
	if (sd->confignames == NULL) {
		/* specified by name=value pairs, check required parms */
		if (rhcs_get_confignames(s) == NULL) {
			return(S_OOPS);
		}

		for (p = sd->confignames; *p; p++) {
			if (OurImports->GetValue(list, *p) == NULL) {
				LOG(PIL_INFO, "Cannot get parameter %s from "
					"StonithNVpair", *p);
			}
		}
	}
#endif

	return rhcs_parse_config_info(sd, list);
}


/* Only interested in regular files starting with fence_ that are also executable */
static int
rhcs_exec_select(const struct dirent *dire)
{
	struct stat	statf;
	char		filename[FILENAME_MAX];
	int		rc;

	rc = snprintf(filename, FILENAME_MAX, "%s/%s", 
		STONITH_RHCS_PLUGINDIR, dire->d_name);
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
static const char**
rhcs_get_confignames(StonithPlugin* p)
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
		/* (unused) */
		char	*output = NULL, *pch;
		int	namecount;

		LOG(PIL_WARN, "%s not supported for rhcs", op);
		return NULL;

		rc = rhcs_run_cmd(sd, op, &output);
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
		/* return list of subplugins in rhcs directory */
		struct dirent **	files = NULL;
		int			dircount;

		/* get the rhcs plugin's confignames (list of subplugins) */
		dircount = scandir(STONITH_RHCS_PLUGINDIR, &files,
				SCANSEL_CAST rhcs_exec_select, NULL);
		if (dircount < 0) {
			return NULL;
		}
	
		sd->confignames = (char **)MALLOC((dircount+1)*sizeof(char *));
		if (!sd->confignames) {
			LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
			return NULL;
		}

		for (i = 0; i < dircount; i++) {
			sd->confignames[i] = STRDUP(files[i]->d_name+strlen("fence_"));
			free(files[i]);
			files[i] = NULL;
		}
		free(files);
		sd->confignames[dircount] = NULL;
	}

	return (const char **)sd->confignames;
}

/*
 * Return STONITH info string
 */
static const char *
fake_op(struct pluginDevice * sd, const char *op)
{
	const char *pfx = "RHCS plugin ";
	char *ret = NULL;

	LOG(PIL_INFO, "rhcs plugins don't really support %s", op);
	ret = MALLOC(strlen(pfx) + strlen(op) + 1);
	strcpy(ret, pfx);
	strcat(ret, op);
	sd->outputbuf = ret;
	return(ret);
}

static const char *
rhcs_getinfo(StonithPlugin * s, int reqtype)
{
	struct pluginDevice* sd;
	char *		ret = NULL;
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
			return fake_op(sd, op);
			break;

		case ST_DEVICENAME:
			op = "getinfo-devname";
			return fake_op(sd, op);
			break;

		case ST_DEVICEDESCR:
			op = "getinfo-devdescr";
			return fake_op(sd, op);
			break;

		case ST_DEVICEURL:
			op = "getinfo-devurl";
			return fake_op(sd, op);
			break;

		case ST_CONF_XML:
			op = "metadata";
			break;

		default:
			return NULL;
	}

	rc = rhcs_run_cmd(sd, op, &ret);
	if (rc != 0) {
		LOG(PIL_CRIT, "%s: '%s %s' failed with rc %d",
			__FUNCTION__, sd->subplugin, op, rc);
		if (ret) {
			LOG(PIL_CRIT, "plugin output: %s", ret);
			FREE(ret);
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
		sd->outputbuf =  ret;
		return(ret);
	}
	return(NULL);
}

/*
 *	RHCS Stonith destructor...
 */
static void
rhcs_destroy(StonithPlugin *s)
{
	struct pluginDevice *	sd;
	char **			p;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	VOIDERRIFWRONGDEV(s);

	sd = (struct pluginDevice *)s;

	sd->pluginid = NOTpluginID;
	rhcs_unconfig(sd);
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

/* Create a new rhcs Stonith device */
static StonithPlugin *
rhcs_new(const char *subplugin)
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
	sd->sp.s_ops = &rhcsOps;
	return &(sd->sp);
}

static void
rhcs_print_var(gpointer key, gpointer value, gpointer user_data)
{
	int fd = GPOINTER_TO_UINT(user_data);

	if (Debug) {
		LOG(PIL_DEBUG, "set rhcs plugin param '%s=%s'", (char *)key, (char *)value);
	}
	write(fd, (char *)key, strlen((char *)key));
	write(fd, "=", 1);
	write(fd, (char *)value, strlen((char *)value));
	write(fd, "\n", 1);
}

/* Run the command with op as command line argument(s) and return the exit
 * status + the output */

static int 
rhcs_run_cmd(struct pluginDevice *sd, const char *op, char **output)
{
	const int		BUFF_LEN=4096;
	char			buff[BUFF_LEN];
	int			read_len = 0;
	int			rc;
	char * 			data = NULL;
	char			cmd[FILENAME_MAX+64];
	struct stat		buf;
	int			slen;
	int pid, status;
	int fd1[2]; /* our stdout/their stdin */
	int fd2[2]; /* our stdin/their stdout and stderr */

	rc = snprintf(cmd, FILENAME_MAX, "%s/fence_%s", 
		STONITH_RHCS_PLUGINDIR, sd->subplugin);
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

	if (Debug) {
		LOG(PIL_DEBUG, "%s: Calling '%s'", __FUNCTION__, cmd );
	}

	if (pipe(fd1) || pipe(fd2))
		goto err;

	pid = fork();
	if (pid < 0) {
		LOG(PIL_CRIT, "%s: fork: %m", __FUNCTION__);
		goto err;
	}
	if (pid) { /* parent */
		close(fd1[0]);
		close(fd2[1]);

		if (sd->cmd_opts) {
			g_hash_table_foreach(sd->cmd_opts, rhcs_print_var,
				GUINT_TO_POINTER(fd1[1]));
		}
		close(fd1[1]); /* we have nothing more to say */

		fcntl(fd2[0], F_SETFL, fcntl(fd2[0], F_GETFL, 0) | O_NONBLOCK);
		data = NULL;
		slen=0;
		data = MALLOC(1);
		/* read stdout/stderr from the fence agent */
		do {
			data[slen]=EOS;
			read_len = read(fd2[0], buff, BUFF_LEN);
			if (read_len > 0) {
				data=REALLOC(data, slen+read_len+1);
				if (data == NULL) {
					goto err;
				}
				memcpy(data+slen, buff, read_len);
				slen += read_len;
				data[slen] = EOS;
			} else if (read_len < 0) {
				if (errno == EAGAIN)
					continue;
				LOG(PIL_CRIT, "%s: read from pipe: %m", __FUNCTION__);
				goto err;
			}
		} while (read_len);

		if (!data) {
			LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
			goto err;
		}
		close(fd2[0]);
		waitpid(pid, &status, 0);
		if (!WIFEXITED(status)) {
			LOG(PIL_CRIT, "%s: fence agent failed: %m", __FUNCTION__);
			goto err;
		} else {
			rc = WEXITSTATUS(status);
			if (rc) {
				LOG(PIL_CRIT, "%s: fence agent exit code: %d",
					__FUNCTION__, rc);
				goto err;
			}
		}
	} else { /* child */
		close(fd1[1]);
		close(fd2[0]);
		close(STDIN_FILENO);
		if (dup(fd1[0]) < 0)
			goto err;
		close(fd1[0]);
		close(STDOUT_FILENO);
		if (dup(fd2[1]) < 0)
			goto err;
		close(STDERR_FILENO);
		if (dup(fd2[1]) < 0)
			goto err;
		close(fd2[1]);
		if (execlp(cmd, cmd, "-o", op, NULL) < 0) {
			LOG(PIL_CRIT, "%s: Calling '%s' failed: %m",
				__FUNCTION__, cmd);
		}
		goto err;
	}

	if (Debug && data) {
		LOG(PIL_DEBUG, "%s: '%s' output: %s", __FUNCTION__, cmd, data);
	}

	if (output) {
		*output = data;
	} else {
		FREE(data);
	}

	return 0;

err:
	if (data) {
		FREE(data);
	}
	if (output) {
		*output = NULL;
	}
	
	return(-1);

}
