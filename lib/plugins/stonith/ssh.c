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

#include <lha_internal.h>

#include <config.h>

#define	DEVICE	"SSH STONITH device"
#include "stonith_plugin_common.h"

#define PIL_PLUGIN              ssh
#define PIL_PLUGIN_S            "ssh"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

static StonithPlugin *	ssh_new(const char *);
static void		ssh_destroy(StonithPlugin *);
static const char * const *	ssh_get_confignames(StonithPlugin *);
static int		ssh_set_config(StonithPlugin *, StonithNVpair*);
static const char *	ssh_get_info(StonithPlugin * s, int InfoType);
static int		ssh_status(StonithPlugin * );
static int		ssh_reset_req(StonithPlugin * s, int request
,				const char * host);
static char **		ssh_hostlist(StonithPlugin  *);

static struct stonith_ops sshOps ={
	ssh_new,		/* Create new STONITH object	*/
	ssh_destroy,		/* Destroy STONITH object	*/
	ssh_get_info,		/* Return STONITH info string	*/
	ssh_get_confignames,	/* Return configuration parameters */
	ssh_set_config,		/* set configuration */
	ssh_status,		/* Return STONITH device status	*/
	ssh_reset_req,		/* Request a reset */
	ssh_hostlist,		/* Return list of supported hosts */
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
/* sunjd@cn.ibm.com added the option -f to temporily work around the block issue
 * in which the child process always stay in 'system' call. Please FIX this.
 * Additonally, this issue seems related to both of 2.6 kernel and stonithd.
 */
#define SSH_COMMAND "ssh -q -x -n -l root"

/* We need to do a real hard reboot without syncing anything to simulate a
 * power cut. 
 * We have to do it in the background, otherwise this command will not
 * return.
 */
#define REBOOT_COMMAND "nohup sh -c '(sleep 2; nohup " REBOOT " " REBOOT_OPTIONS ") </dev/null >/dev/null 2>&1' &"
#undef REBOOT_COMMAND
#define REBOOT_COMMAND "echo 'sleep 2; " REBOOT " " REBOOT_OPTIONS "' | SHELL=/bin/sh at now >/dev/null 2>&1"
#define POWEROFF_COMMAND "echo 'sleep 2; " POWEROFF_CMD " " POWEROFF_OPTIONS "' | SHELL=/bin/sh at now >/dev/null 2>&1"

#define MAX_PING_ATTEMPTS	15

/*
 *    SSH STONITH device
 *
 * I used the null device as template, so I guess there is missing
 * some functionality.
 *
 */

struct pluginDevice {
	StonithPlugin	sp;
	const char *	pluginid;
	const char *	idinfo;
	char **		hostlist;
	int		hostcount;
};

static const char * pluginid = "SSHDevice-Stonith";
static const char * NOTpluginid = "SSH device has been destroyed";

#include "stonith_config_xml.h"

static const char *sshXML = 
  XML_PARAMETERS_BEGIN
    XML_HOSTLIST_PARM
  XML_PARAMETERS_END;

static int
ssh_status(StonithPlugin  *s)
{
	ERRIFWRONGDEV(s, S_OOPS);

	return system(NULL) ? S_OK : S_OOPS;
}


/*
 *	Return the list of hosts configured for this SSH device
 */

static char **
ssh_hostlist(StonithPlugin  *s)
{
	struct pluginDevice* sd = (struct pluginDevice*)s;

	ERRIFWRONGDEV(s, NULL);

	if (sd->hostcount < 0) {
		LOG(PIL_CRIT
		,	"unconfigured stonith object in %s", __FUNCTION__);
		return(NULL);
	}

	return OurImports->CopyHostList((const char * const *)sd->hostlist);
}


/*
 *	Reset the given host on this Stonith device.
 */
static int
ssh_reset_req(StonithPlugin * s, int request, const char * host)
{
	struct pluginDevice*	sd = (struct pluginDevice *)s;
	char			cmd[4096];
	int			i, status = -1;

	ERRIFWRONGDEV(s, S_OOPS);

	if (request == ST_POWERON) {
		LOG(PIL_CRIT, "%s not capable of power-on operation", DEVICE);
		return S_INVAL;
	} else if (request != ST_POWEROFF && request != ST_GENERIC_RESET) {
		return S_INVAL;
	}

	for (i = 0; i < sd->hostcount; i++) {
		if (strcasecmp(host, sd->hostlist[i]) == 0) {
			break;
		}
	}

	if (i >= sd->hostcount) {
		LOG(PIL_CRIT, "%s doesn't control host [%s]"
		,	sd->idinfo, host);
		return(S_BADHOST);
	}

	LOG(PIL_INFO, "Initiating ssh-%s on host: %s"
	,	request == ST_POWEROFF ? "poweroff" : "reset", host);

	snprintf(cmd, sizeof(cmd)-1, "%s \"%s\" \"%s\"", SSH_COMMAND
	,	host
	, request == ST_POWEROFF ? POWEROFF_COMMAND : REBOOT_COMMAND);
  
	status = system(cmd);
	if (WIFEXITED(status) && 0 == WEXITSTATUS(status)) {
		if (Debug) {
			LOG(PIL_DEBUG, "checking whether %s stonith'd", host);
		}

		snprintf(cmd, sizeof(cmd)-1
		,	"ping -w1 -c1 %s >/dev/null 2>&1", host);

		for (i = 0; i < MAX_PING_ATTEMPTS; i++) {
			status = system(cmd);
			if (WIFEXITED(status) && 1 == WEXITSTATUS(status)) {
				if (Debug) {
					LOG(PIL_DEBUG, "unable to ping %s"
					" after %d tries, stonith did work"
					, host, i);
				}
				return S_OK;
			}
			sleep(1);
		}

		LOG(PIL_CRIT, "still able to ping %s after %d tries, stonith"
			" did not work", host, MAX_PING_ATTEMPTS);
		return S_RESETFAIL;
	}else{
		LOG(PIL_CRIT, "command %s failed", cmd);
		return S_RESETFAIL;
	}
}

static const char * const *
ssh_get_confignames(StonithPlugin* p)
{
	static const char *	SshParams[] = {ST_HOSTLIST, NULL };
	return SshParams;
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
ssh_set_config(StonithPlugin* s, StonithNVpair* list)
{
	struct pluginDevice* sd = (struct pluginDevice *)s;
	const char *	hlist;

	ERRIFWRONGDEV(s,S_OOPS);

	if ((hlist = OurImports->GetValue(list, ST_HOSTLIST)) == NULL) {
		return S_OOPS;
	}
	sd->hostlist = OurImports->StringToHostList(hlist);
	if (sd->hostlist == NULL) {
		LOG(PIL_CRIT, "out of memory");
		sd->hostcount = 0;
	}else{
		for (sd->hostcount = 0; sd->hostlist[sd->hostcount]
		;	sd->hostcount++) {
			strdown(sd->hostlist[sd->hostcount]);
		}
	}
	
	return sd->hostcount ? S_OK : S_OOPS;
}


static const char *
ssh_get_info(StonithPlugin * s, int reqtype)
{
	struct pluginDevice*	sd = (struct pluginDevice *)s;
	const char *		ret;

	ERRIFWRONGDEV(s, NULL);

	switch (reqtype) {
	case ST_DEVICEID:
		ret = sd->idinfo;
		break;


	case ST_DEVICENAME:
		ret = "ssh STONITH device";
		break;


	case ST_DEVICEDESCR:	/* Description of device type */
		ret = "SSH-based host reset\n"
		"Fine for testing, but not suitable for production!";
		break;


	case ST_DEVICEURL:
		ret = "http://openssh.org";
		break;


	case ST_CONF_XML:		/* XML metadata */
		ret = sshXML;
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
ssh_destroy(StonithPlugin *s)
{
	struct pluginDevice* sd = (struct pluginDevice *)s;

	VOIDERRIFWRONGDEV(s);

	sd->pluginid = NOTpluginid;
	if (sd->hostlist) {
		stonith_free_hostlist(sd->hostlist);
		sd->hostlist = NULL;
	}
	sd->hostcount = -1;
	FREE(sd);
}

/* Create a new ssh Stonith device */
static StonithPlugin*
ssh_new(const char *subplugin)
{
	struct pluginDevice*	sd = ST_MALLOCT(struct pluginDevice);

	if (sd == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(sd, 0, sizeof(*sd));
	sd->pluginid = pluginid;
	sd->hostlist = NULL;
	sd->hostcount = -1;
	sd->idinfo = DEVICE;
	sd->sp.s_ops = &sshOps;
	return &(sd->sp);
}
