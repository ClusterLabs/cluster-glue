/* $Id: ssh.c,v 1.14 2004/10/06 10:55:18 lars Exp $ */
/*
 * Stonith module for SSH Stonith device
 *
 * Copyright (c) 2001 SuSE Linux AG
 *
 * Authors: Joachim Gleissner <jg@suse.de>, Lars Marowsky-Brée <lmb@suse.de>
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

#define	DEVICE	"SSH STONITH device"
#include "stonith_plugin_common.h"

#define PIL_PLUGIN              ssh
#define PIL_PLUGIN_S            "ssh"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

static void *		ssh_new(void);
static void		ssh_destroy(Stonith *);
static int		ssh_set_config_file(Stonith *, const char * cfgname);
static int		ssh_set_config_info(Stonith *, const char * info);
static const char *	ssh_getinfo(Stonith * s, int InfoType);
static int		ssh_status(Stonith * );
static int		ssh_reset_req(Stonith * s, int request, const char * host);
static char **		ssh_hostlist(Stonith  *);

static struct stonith_ops sshOps ={
	ssh_new,		/* Create new STONITH object	*/
	ssh_destroy,		/* Destroy STONITH object	*/
	ssh_set_config_file,	/* set configuration from file	*/
	ssh_set_config_info,	/* Get configuration from file	*/
	ssh_getinfo,		/* Return STONITH info string	*/
	ssh_status,		/* Return STONITH device status	*/
	ssh_reset_req,		/* Request a reset */
	ssh_hostlist,		/* Return list of supported hosts */
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
	,	&sshOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/* uncomment this if you have an ssh that can do what it claims
#define SSH_COMMAND "ssh -q -x -o PasswordAuthentication=no StrictHostKeyChecking=no" 
*/
/* use this if you have the (broken) OpenSSH 2.1.1 */
#define SSH_COMMAND "ssh -q -x -n -l root"

/* We need to do a real hard reboot without syncing anything to simulate a
 * power cut. 
 * We have to do it in the background, otherwise this command will not
 * return.
 */
#define REBOOT_COMMAND "nohup sh -c '(sleep 2; nohup /sbin/reboot -nf) </dev/null >/dev/null 2>&1' &"
#undef REBOOT_COMMAND
#define REBOOT_COMMAND	"echo 'sleep 2; /sbin/reboot -nf' | at now"

/*
 *    SSH STONITH device
 *
 * I used the null device as template, so I guess there is missing
 * some functionality.
 *
 */

struct pluginDevice {
  const char *	pluginid;
  char **		hostlist;
  int		hostcount;
};

static const char * pluginid = "SSHDevice-Stonith";
static const char * NOTpluginid = "SSH device has been destroyed";

static int
ssh_status(Stonith  *s)
{
  ERRIFWRONGDEV(s,S_OOPS);

  return S_OK;
}


/*
 *	Return the list of hosts configured for this SSH device
 */

static char **
ssh_hostlist(Stonith  *s)
{
  int		numnames = 0;
  char **		ret = NULL;
  struct pluginDevice*	sd;
  int		j;

  ERRIFWRONGDEV(s,NULL);
  sd = (struct pluginDevice*) s->pinfo;
  if (sd->hostcount < 0) {
    LOG(PIL_CRIT
	   ,	"unconfigured stonith object in SSH_list_hosts");
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

static int
WordCount(const char * s)
{
  int	wc = 0;
  if (!s) {
    return wc;
  }
  do {
    s += strspn(s, WHITESPACE);
    if (*s)  {
      ++wc;
      s += strcspn(s, WHITESPACE);
    }
  }while (*s);

  return(wc);
}

/*
 *	Parse the config information, and stash it away...
 */

static int
ssh_parse_config_info(struct pluginDevice* sd, const char * info)
{
  char **			ret;
  int			wc;
  int			numnames;
  const char *		s = info;
  int			j;

  if (sd->hostcount >= 0) {
    return(S_OOPS);
  }

  wc = WordCount(info);
  numnames = wc + 1;

  ret = (char **)MALLOC(numnames*sizeof(char*));
  if (ret == NULL) {
    LOG(PIL_CRIT, "out of memory");
    return S_OOPS;
  }

  memset(ret, 0, numnames*sizeof(char*));

  for (j=0; j < wc; ++j) {
    s += strspn(s, WHITESPACE);
    if (*s)  {
      const char *	start = s;
      s += strcspn(s, WHITESPACE);
      ret[j] = MALLOC((1+(s-start))*sizeof(char));
      if (ret[j] == NULL) {
	stonith_free_hostlist(ret);
	ret = NULL;
	return S_OOPS;
      }
      strncpy(ret[j], start, (s-start));
      g_strdown(ret[j]);
    }
  }
  sd->hostlist = ret;
  sd->hostcount = numnames;
  return(S_OK);
}


/*
 *	Reset the given host on this Stonith device.
 */
static int
ssh_reset_req(Stonith * s, int request, const char * host)
{
  char cmd[4096];

  ERRIFWRONGDEV(s,S_OOPS);
  LOG(PIL_INFO, "%s: %s", _("Initiating ssh-reset on host"), host);

  snprintf(cmd, 4096, "%s \"%s\" \"%s\"", SSH_COMMAND, host, REBOOT_COMMAND);
  
  if (system(cmd) == 0) 
    return S_OK;
  else {
    LOG(PIL_CRIT, "command %s failed", cmd);
    return(S_RESETFAIL);
  }
}

/*
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */
static int
ssh_set_config_file(Stonith* s, const char * configname)
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
    return(ssh_parse_config_info(sd, line));
  }
  return(S_BADCONFIG);
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
ssh_set_config_info(Stonith* s, const char * info)
{
  struct pluginDevice* sd;

  ERRIFWRONGDEV(s,S_OOPS);
  sd = (struct pluginDevice *)s->pinfo;

  return(ssh_parse_config_info(sd, info));
}

static const char *
ssh_getinfo(Stonith * s, int reqtype)
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
    ret = _("ssh STONITH device");
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
	ret = _("SSH-based Linux host reset\n"
	"Fine for testing, but not suitable for production!");
	break;


  default:
    ret = NULL;
    break;
  }
  return ret;
}

/*
 *	SSH Stonith destructor...
 */
static void
ssh_destroy(Stonith *s)
{
  struct pluginDevice* sd;

  VOIDERRIFWRONGDEV(s);

  sd = (struct pluginDevice *)s->pinfo;

  sd->pluginid = NOTpluginid;
  if (sd->hostlist) {
    stonith_free_hostlist(sd->hostlist);
    sd->hostlist = NULL;
  }
  sd->hostcount = -1;
  FREE(sd);
}

/* Create a new ssh Stonith device */
static void *
ssh_new(void)
{
  struct pluginDevice*	sd = MALLOCT(struct pluginDevice);

  if (sd == NULL) {
    LOG(PIL_CRIT, "out of memory");
    return(NULL);
  }
  memset(sd, 0, sizeof(*sd));
  sd->pluginid = pluginid;
  sd->hostlist = NULL;
  sd->hostcount = -1;
  return((void *)sd);
}
