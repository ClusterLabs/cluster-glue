/* $Id: ssh.c,v 1.21 2005/03/25 10:02:44 sunjd Exp $ */
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

static StonithPlugin *	ssh_new(void);
static void		ssh_destroy(StonithPlugin *);
static const char**	ssh_get_confignames(StonithPlugin *);
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
#define REBOOT_COMMAND "nohup sh -c '(sleep 2; nohup /sbin/reboot -nf) </dev/null >/dev/null 2>&1' &"
#undef REBOOT_COMMAND
#define REBOOT_COMMAND	"echo 'sleep 2; /bin/ls -l / > /tmp/TEST' | SHELL=/bin/sh at now >/dev/null 2>&1"

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
	char **		hostlist;
	int		hostcount;
};

static const char * pluginid = "SSHDevice-Stonith";
static const char * NOTpluginid = "SSH device has been destroyed";

static int
ssh_status(StonithPlugin  *s)
{
	ERRIFWRONGDEV(s, S_OOPS);

	return S_OK;
}


/*
 *	Return the list of hosts configured for this SSH device
 */

static char **
ssh_hostlist(StonithPlugin  *s)
{
	int		numnames = 0;
	char **		ret = NULL;
	struct pluginDevice*	sd;
	int		j;

	ERRIFWRONGDEV(s, NULL);
	sd = (struct pluginDevice*) s;
	if (sd->hostcount < 0) {
		LOG(PIL_CRIT
		,	"unconfigured stonith object in SSH_list_hosts");
		return(NULL);
	}
	numnames = sd->hostcount;

	ret = (char **)malloc((numnames+1)*sizeof(char*));
	if (ret == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return ret;
	}

	memset(ret, 0, (numnames+1)*sizeof(char*));

	for (j=0; j < numnames; ++j) {
		ret[j] = strdup(sd->hostlist[j]);
		if (ret[j] == NULL) {
			stonith_free_hostlist(ret);
			ret = NULL;
			return ret;
		}
	}
	return(ret);
}


/*
 *	Reset the given host on this Stonith device.
 */
static int
ssh_reset_req(StonithPlugin * s, int request, const char * host)
{
	char cmd[4096];

	ERRIFWRONGDEV(s, S_OOPS);
	LOG(PIL_INFO, "%s: %s", "Initiating ssh-reset on host", host);

	snprintf(cmd, sizeof(cmd)-1, "%s \"%s\" \"%s\"", SSH_COMMAND
	,	host, REBOOT_COMMAND);
  
	if (system(cmd) == 0)  {
    		return S_OK;
	}else{
		LOG(PIL_CRIT, "command %s failed", cmd);
		return S_RESETFAIL ;
	}
}

static const char**
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
	for (sd->hostcount = 0; sd->hostlist[sd->hostcount]
	;	sd->hostcount++) {
		/* Just count */
	}
	
	return sd->hostcount ? S_OK : S_OOPS;
}


static const char *
ssh_get_info(StonithPlugin * s, int reqtype)
{
	struct pluginDevice*	sd = (struct pluginDevice *)s;
	const char *		ret;

	ERRIFWRONGDEV(s, NULL);
	sd = (struct pluginDevice *)s;

	switch (reqtype) {
	case ST_DEVICEID:
		ret = "ssh STONITH device";
		break;


	case ST_DEVICEDESCR:	/* Description of device type */
		ret = "SSH-based Linux host reset\n"
		"Fine for testing, but not suitable for production!";
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
	struct pluginDevice* sd;

	VOIDERRIFWRONGDEV(s);

	sd = (struct pluginDevice *)s;

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
	sd->sp.s_ops = &sshOps;
	return &(sd->sp);
}
