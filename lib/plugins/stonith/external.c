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
 * closes...
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

#include "stonith_plugin_common.h"

#define PIL_PLUGIN              external
#define PIL_PLUGIN_S            "external"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

static void *		external_new(void);
static void		external_destroy(Stonith *);
static int		external_set_config_file(Stonith *, const char * cfgname);
static int		external_set_config_info(Stonith *, const char * info);
static const char *	external_getinfo(Stonith * s, int InfoType);
static int		external_status(Stonith * );
static int		external_reset_req(Stonith * s, int request, const char * host);
static char **		external_hostlist(Stonith  *);

static struct stonith_ops externalOps ={
	external_new,		/* Create new STONITH object	*/
	external_destroy,		/* Destroy STONITH object	*/
	external_set_config_file,	/* set configuration from file	*/
	external_set_config_info,	/* Get configuration from file	*/
	external_getinfo,		/* Return STONITH info string	*/
	external_status,		/* Return STONITH device status	*/
	external_reset_req,		/* Request a reset */
	external_hostlist,		/* Return list of supported hosts */
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug);
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
  const char *	pluginid;
  int		config;
  char *	command;
  GHashTable *	cmd_opts;
};

static const char * pluginid = "EXTERNALDevice-Stonith";
static const char * NOTpluginID = "EXTERNAL device has been destroyed";

/* Prototypes */

/* Run the command with op as a single command line argument and return
 * the exit status + the output (NULL -> discard output) */
static int external_run_cmd(struct pluginDevice *sd, const char *op, 
		char **output);
/* Just free up the configuration and the memory, if any */
static void external_unconfig(struct pluginDevice *sd);

static int
external_status(Stonith  *s)
{
	int rc = 0;
	struct pluginDevice *sd = NULL;
	
	ERRIFWRONGDEV(s,S_OOPS);

	sd = (struct pluginDevice*) s->pinfo;
	
	rc = external_run_cmd(sd, "status", NULL);
	if (rc == 0) {
		LOG(PIL_DEBUG, "%s: running %s status returned %d",
			__FUNCTION__, sd->command, rc);
	} else {	
		LOG(PIL_INFO, "%s: running %s status returned %d",
			__FUNCTION__, sd->command, rc);
	}
	
	return rc;
}

static char **
external_hostlist(Stonith  *s)
{
	char **	ret = NULL;
	char *	output;
	char *	tmp;
	struct pluginDevice*	sd;
	int rc, i;

	ERRIFNOTCONFIGED(s,NULL);

	sd = (struct pluginDevice*) s->pinfo;

	rc = external_run_cmd(sd, "hostlist", &output);
	if (rc == 0) {
		LOG(PIL_DEBUG, "%s: '%s hostlist' succeeded",
			__FUNCTION__, sd->command);
		return NULL;
	} else {	
		LOG(PIL_CRIT, "%s: '%s hostlist' failed with rc %d",
			__FUNCTION__, sd->command, rc);
		if (output) { FREE(output); }
		return NULL;
	}

	if (!output) {
		LOG(PIL_CRIT, "%s: '%s hostlist' returned an empty hostlist",
			__FUNCTION__, sd->command);
		return NULL;
	}
	
	ret = MALLOC(sizeof(char *) * 64);
	if (!ret) {
		LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
		return NULL;
	}
	
	/* White-space split the output here */
	i = 0;
	while ((tmp = strtok(output, WHITESPACE))) {
		ret[i] = STRDUP(tmp);
		if (!ret[i]) {
			LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
			stonith_free_hostlist(ret);
			return NULL;
		}

		/* External scripts should be treated with care... 
		 * Arbitary limits are bad, but who knows? 
		 * XXX: Up this if it ever becomes a problem.
		 * Though power switches driving >=32 nodes really
		 * should be implemented as proper STONITH plug-ins.
		 */
		i++;
		if (i > 32) {
			LOG(PIL_CRIT, "%s: run away hostlist? >= 32 nodes", 
					__FUNCTION__);
			stonith_free_hostlist(ret);
			return NULL;
		}
		
	}

	if (output) { FREE(output); }

	if (i == 0) {
		LOG(PIL_CRIT, "%s: '%s hostlist' returned an empty hostlist",
			__FUNCTION__, sd->command);
		stonith_free_hostlist(ret);
		ret = NULL;
	}

	return(ret);
}

static int
external_reset_req(Stonith * s, int request, const char * host)
{
	struct pluginDevice *sd = NULL;
	const char *op;
	int rc;
	
	ERRIFNOTCONFIGED(s,S_OOPS);
	
	LOG(PIL_INFO, "%s %s", _("Host external-reset initiating on "), host);

	sd = (struct pluginDevice*) s->pinfo;

	switch (request) {
		case ST_GENERIC_RESET:
			op = "reset";
			break;

		case ST_POWEROFF:
			op = "poweroff";
			break;
			
		case ST_POWERON:
			op = "poweron";
			break;
			
		default:
			LOG(PIL_CRIT, "%s: Unknown stonith request %d",
				__FUNCTION__, request);
			return S_OOPS;
			break;
	}
	
	g_hash_table_insert(sd->cmd_opts, g_strdup("ST_HOST"),
			g_strdup(host));
	
	rc = external_run_cmd(sd, op, NULL);

	g_hash_table_remove(sd->cmd_opts, "ST_HOST");

	if (rc == 0) {
		LOG(PIL_INFO, "%s: '%s %s' for host %s succeeded",
			__FUNCTION__, sd->command, op, host);
		return S_OK;
	} else {	
		LOG(PIL_CRIT, "%s: '%s %s' for host %s failed with rc %d",
			__FUNCTION__, sd->command, op, host, rc);
		return(S_RESETFAIL);
	}
	
	/* notreached */
	return S_OOPS;
}

static int
external_parse_config_info(struct pluginDevice* sd, const char * info)
{
	int i;
	int j;
	char *command = NULL;
	char *tmp, *key, *value, *tmp_val;
	struct stat buf;
	
	/*  make sure that command has not already been set  */
	if (sd->config) {
		return(S_OOPS);
	}

	tmp = STRDUP(info);
	if (!tmp) {
		goto err_mem;
	}
	
	command = strtok(tmp, WHITESPACE);		
	if (!command) {
		LOG(PIL_CRIT, "%s: cannot find command to call.", __FUNCTION__);
		goto err;
	}
	
	if (command[0] != '/') {
		/* Not an absolute pathname. */
		j = strlen(command) + strlen(STONITH_EXT_PLUGINDIR) + 2;
		
		sd->command = MALLOC(j);
		if (!sd->command) {
			goto err_mem;
		}
		if (snprintf(sd->command, j, "%s/%s", sd->command,
			STONITH_EXT_PLUGINDIR) == j) {
			goto err_mem;
		}
	} else {
		sd->command = STRDUP(command);
	}
	
	if (!sd->command) {
		goto err_mem;
	}

        if (stat(sd->command, &buf) != 0) {
		LOG(PIL_CRIT, "%s: stating %s failed.",
			__FUNCTION__, sd->command);
                goto err;
        }

        if (S_ISREG(buf.st_mode) 
	  && (buf.st_mode & (S_IXUSR|S_IXOTH|S_IXGRP))) {
		LOG(PIL_INFO, "%s: %s found to be executable.",
			__FUNCTION__, sd->command);
        } else {
		LOG(PIL_CRIT, "%s: %s found NOT to be executable.",
			__FUNCTION__, sd->command);
		goto err;
	}

	sd->cmd_opts = g_hash_table_new(g_str_hash, g_str_equal);

	/* white-space split the option string and put it into the
	 * hashtable. TODO: Maybe treat "" as delimeters too so
	 * whitespace can be passed to the plugins... */
	i = 0;
	while ((tmp_val = strtok(tmp, WHITESPACE))) {
		key = MALLOC(10);
		if (!key) {
			goto err_mem;
		}
		if (snprintf(key, 10, "ST_OPT_%d", i) == 10) {
			FREE(key);
			goto err_mem;
		}
		value = STRDUP(tmp_val);
		if (!value) {
			FREE(key);
			goto err_mem;
		}
		g_hash_table_insert(sd->cmd_opts, key, value);
		i++;
	}
	FREE(tmp);
		
	sd->config = 1;
	
	return(S_OK);

err_mem:
	LOG(PIL_CRIT, "%s: out of memory!", __FUNCTION__);
err:
	if (tmp) {
		FREE(tmp);
	}
	external_unconfig(sd);
	
	return(S_OOPS);
}

static gboolean
let_remove_eachitem(gpointer key, gpointer value, gpointer user_data)
{
	if (key) { FREE(key); }
	if (value) { FREE(value); }
        return TRUE;
}

static void
external_unconfig(struct pluginDevice *sd) {
	sd->config = 0;
	if (sd->cmd_opts) {
		g_hash_table_foreach_remove(sd->cmd_opts, 
				let_remove_eachitem, NULL);
		g_hash_table_destroy(sd->cmd_opts);	
		sd->cmd_opts = NULL;
	}
	if (sd->command) {
		FREE(sd->command);
		sd->command = NULL;
	}
}

/*
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */
static int
external_set_config_file(Stonith* s, const char * configname)
{
  FILE *	cfgfile;
  char	line[256];
  struct pluginDevice*	sd;

  ERRIFWRONGDEV(s,S_OOPS);

  sd = (struct pluginDevice*) s->pinfo;

  if ((cfgfile = fopen(configname, "r")) == NULL)  {
    LOG(PIL_CRIT, "Cannot open %s", configname);
    return(S_BADCONFIG);
  }
  while (fgets(line, sizeof(line), cfgfile) != NULL){
    if (*line == '#' || *line == '\n' || *line == EOS) {
      continue;
    }
    return(external_parse_config_info(sd, line));
  }
  return(S_BADCONFIG);
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
external_set_config_info(Stonith* s, const char * info)
{
  struct pluginDevice* sd;

  ERRIFWRONGDEV(s,S_OOPS);

  sd = (struct pluginDevice *)s->pinfo;

  return(external_parse_config_info(sd, info));
}

static const char *
external_getinfo(Stonith * s, int reqtype)
{
  struct pluginDevice* sd;
  char *		ret;
  
  ERRIFWRONGDEV(s,NULL);

  /* TODO: Retrieve from plugin...? */

  /*
   *	We look in the ST_TEXTDOMAIN catalog for our messages
   */
  sd = (struct pluginDevice *)s->pinfo;

  switch (reqtype) {
  case ST_DEVICEID:
    ret = _("External STONITH plugin");
    break;

  case ST_CONF_INFO_SYNTAX:
    ret = _("<command> options...\n"
	    "The command is the external command we will run.\n"
	    "Any options will be passed on to it.\n");
    break;

  case ST_CONF_FILE_SYNTAX:
    ret = _("<command> options...\n"
	    "The command is the external command we will run.\n"
	    "Any options will be passed on to it.\n"
	    "All options must be on one line.\n"
	    "Blank lines and lines beginning with # are ignored");
    break;

    case ST_DEVICEDESCR:		/* Description of device type */
	ret = _("EXTERNAL-program based STONITH plugin\n");
	break;

  default:
    ret = NULL;
    break;
  }
  return ret;
}

/*
 *	EXTERNAL Stonith destructor...
 */
static void
external_destroy(Stonith *s)
{
	struct pluginDevice* sd;

	VOIDERRIFWRONGDEV(s);

	sd = (struct pluginDevice *)s->pinfo;

	sd->pluginid = NOTpluginID;
	external_unconfig(sd);
	FREE(sd);
}

/* Create a new external Stonith device */
static void *
external_new(void)
{
	struct pluginDevice*	sd = MALLOCT(struct pluginDevice);

	if (sd == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(sd, 0, sizeof(*sd));
	sd->pluginid = pluginid;
	external_unconfig(sd);
	return((void *)sd);
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

/* Run the command with op as a single command line argument and return
 * the exit status + the output */
static int 
external_run_cmd(struct pluginDevice *sd, const char *op, 
		char **output)
{
	const int BUFF_LEN=4096;
	char buff[BUFF_LEN];
	int read_len = 0;
	int rc;
	char* data = NULL;
	FILE* file;
	char cmd[BUFF_LEN];
	GString* g_str_tmp = NULL;

	if (snprintf(cmd, BUFF_LEN, "%s %s", sd->command, op) == BUFF_LEN) {
		LOG(PIL_CRIT, "%s: out of memory or command too long",
				__FUNCTION__);
		goto err;
	}
	
	/* We only have a global environment to use here. So we add our
	 * options to it, and then later remove them again. */
	g_hash_table_foreach(sd->cmd_opts, 
			ext_add_to_env, NULL);

	file = popen(cmd, "r");
	if (NULL==file) {
		LOG(PIL_CRIT, "%s: Calling '%s' failed",
			__FUNCTION__, cmd);
		goto err;
	}

	g_str_tmp = g_string_new("");
	while(!feof(file)) {
		memset(buff, 0, BUFF_LEN);
		read_len = fread(buff, 1, BUFF_LEN, file);
		if (0<read_len) {
			g_string_append(g_str_tmp, buff);
		}
		else {
			sleep(1);
		}
	}
	data = (char*)MALLOC(g_str_tmp->len+1);
	if (!data) {
		LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
		goto err;
	}
	
	data[0] = data[g_str_tmp->len] = 0;
	strncpy(data, g_str_tmp->str, g_str_tmp->len);
	g_string_free(g_str_tmp, TRUE);

	rc = pclose(file);
	if (output) {
		*output = data;
	} else {
		FREE(data);
	}
	
	g_hash_table_foreach(sd->cmd_opts, 
			ext_del_from_env, NULL);
	
	return(rc);

err:
	g_hash_table_foreach(sd->cmd_opts, 
			ext_del_from_env, NULL);
	if (data) {
		FREE(data);
	}
	if (output) {
		*output = NULL;
	}
	
	return(-1);

}


