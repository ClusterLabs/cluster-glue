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

PIL_PLUGIN_BOILERPLATE("1.0", Debug, NULL);
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
 *
 * ssh device used as template, so I guess there is missing
 * some functionality.
 *
 */

struct pluginDevice {
  const char *	pluginid;
  char **	hostlist;
  char *	command;
  int		hostcount;
};

static const char * pluginid = "EXTERNALDevice-Stonith";
static const char * NOTpluginID = "EXTERNAL device has been destroyed";

static int
external_status(Stonith  *s)
{
  ERRIFWRONGDEV(s,S_OOPS);

  return S_OK;
}

/*
 *	Return the list of hosts configured for this EXTERNAL device
 */

static char **
external_hostlist(Stonith  *s)
{
  int		numnames = 0;
  char **		ret = NULL;
  struct pluginDevice*	sd;
  int		j;

  ERRIFWRONGDEV(s,NULL);

  sd = (struct pluginDevice*) s->pinfo;
  if (sd->hostcount < 0) {
    LOG(PIL_CRIT
	   ,	"unconfigured stonith object in EXTERNAL_list_hosts");
    return(NULL);
  }
  numnames = sd->hostcount;

  ret = (char **)MALLOC(numnames*sizeof(char*));
  if (ret == NULL) {
    LOG(PIL_CRIT, "out of memory");
    return ret;
  }

  memset(ret, 0, numnames*sizeof(char*));

  for (j=0; j < numnames-1; ++j) {
    ret[j] = STRDUP(sd->hostlist[j]);
    if (ret[j] == NULL) {
      stonith_free_hostlist(ret);
      ret = NULL;
      return ret;
    }
  }
  return(ret);
}

/*
 *	Parse the config information, and stash it away...
 */

static int
external_parse_config_info(struct pluginDevice* sd, const char * info)
{
	int i, end;
	char *command = NULL;


	/*  make sure that command has not already been set  */
	if (sd->command) {
		return(S_OOPS);
	}

	/*  skip the system name  */
	i = 0;
	while (info[i] != '\0' && !isspace(info[i])) i++;
	if (info[i] == '\0') {
		return(S_BADCONFIG);
	}
	
	/*  skip past the white space after system name  */
	while (info[i] != '\0' && isspace(info[i])) i++;
	if (info[i] == '\0') {
		return(S_BADCONFIG);
	}
	
	/*  find the last non-whitespace character in the name  */
	for (end = strlen(info + i) - 1; end > 0 && isspace(info[i + end]); end--)
		;

	if ((command = STRDUP(info + i)) == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(S_OOPS);
		}
	if (command[end] != '\0' && !isspace(command[end])) {
		command[end + 1] = '\0';
	} else {
		command[end] = '\0';
	}
	
	sd->command = command;
	return(S_OK);
}


/*
 *	Reset the given host on this Stonith device.
 */
static int
external_reset_req(Stonith * s, int request, const char * host)
{
	struct pluginDevice *sd = NULL;

	ERRIFWRONGDEV(s,S_OOPS);
	
	LOG(PIL_INFO, "%s %s", _("Host external-reset initiating on "), host);

	sd = (struct pluginDevice*) s->pinfo;
	if (sd->command == NULL) {
		return(S_OOPS);
		}

	if (system(sd->command) == 0) 
		return S_OK;
	else {
		LOG(PIL_CRIT, "command '%s' failed", sd->command);
		return(S_RESETFAIL);
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
  /*
   *	We look in the ST_TEXTDOMAIN catalog for our messages
   */
  sd = (struct pluginDevice *)s->pinfo;

  switch (reqtype) {
  case ST_DEVICEID:
    ret = _("External STONITH plugin");
    break;

  case ST_CONF_INFO_SYNTAX:
    ret = _("hostname ...\n"
	    "host names are white-space delimited.");
    break;

  case ST_CONF_FILE_SYNTAX:
    ret = _("hostname...\n"
	    "host names are white-space delimited.  "
	    "All host names must be on one line.  "
	    "Blank lines and lines beginning with # are ignored");
    break;

    case ST_DEVICEDESCR:		/* Description of device type */
	ret = _("EXTERNAL-program based host reset\n"
	"Set environment variable $EXTERNAL to the proper reset script.");
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
  if (sd->hostlist) {
    stonith_free_hostlist(sd->hostlist);
    sd->hostlist = NULL;
  }
  if (sd->command) {
	  FREE(sd->command);
	  sd->command = NULL;
	  }
  sd->hostcount = -1;
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
  sd->hostlist = NULL;
  sd->command = NULL;
  sd->hostcount = -1;
  return((void *)sd);
}
