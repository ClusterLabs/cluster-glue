/*
 * Stonith module for IBM pSeries Hardware Management Console (HMC)
 *
 * Author: Huang Zhen <zhenh@cn.ibm.com>
 *
 * Copyright (c) 2004 International Business Machines
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

/*
 *
 * This code has been test in following environment
 *
 *	p630 7028-6C4 two LPAR partitions
 *	p650 7038-6M2 one LPAR partition and FullSystemPartition
 *
 *	Hardware Management Console (HMC): Release 3, Version 2.4
 *
 *	Both FullSystemPartition and LPAR Partition are tested.
 *
 *	Note:  Only SSH access to the HMC devices are supported.
 *
 *
 * This is a nice start on this STONITH plugin, but it's not quite done yet ;-)
 *
 * Current deficiencies:
 *
 *	- The user has to provide a list of partitions and/or system names
 *		on the command line, when we should grab this information
 *		from the HMC ourselves...
 *
 *	- The user has to tell us whether the system is partitioned or not
 *
 *	- All systems either have to be partitioned or none can be
 *
 *	- We don't have a "status" command that will verify that we're
 *		configured correctly.
 *
 *	- I don't think the on/off/reset commands are done quite right yet...
 *
 *	- We don't capture the firmware version of the HMC itself.
 *		We'll probably eventually need that...
 *
 *
 * This command would make a nice status command:
 *
 *	lshmc -r -F ssh
 *
 * The following command will get the list of systems we control and their mode
 *
 *	lssyscfg -r sys -F name:mode --all
 *
 *		0 indicates full system partition
 *	      255 indicates the system is partitioned
 *
 * The following command will get the list of partitions for a given
 * managed system running partitioned:
 *
 *	lssyscfg -m managed-system-name -r lpar -F name:boot_mode --all
 *
 *	Note that we should probably only consider partitions whose boot mode is 
 *	normal (1).  (that's my guess, anyway...)
 *
 *
 * ON/OFF/RESET COMMANDS:
 *
 *	FULL SYSTEM:
 *	  reset:	chsysstate -m managedsystem -r sys -o reset
 *	  on:	chsysstate -m managedsystem -r sys -o on
 *	  off:	chsysstate -m managedsystem -r sys -o off
 *
 *	Partitioned SYSTEM:
 *	  on:	chsysstate -m managedsystem -r lpar -p partition-name -o on
 *				(or maybe reset_partition -t hard)
 *	  off:	chsysstate -m managedsystem -r lpar -p partition-name -o off
 *				(or maybe start_partition)
 *	  reset:	do off action above, followed by "on" action...
 *
 *
 * Of course, to do all this, we need to track which partition name goes with which
 * managed system's name, and which systems on the HMC are partitioned and which
 * ones aren't...
 *
 * Note that the commands above are just reasonable guesses at the right commands.
 *
 */
 
#include <portability.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libintl.h>
#include <sys/wait.h>
#include <glib.h>
#include <stonith/stonith.h>
#include <pils/plugin.h>

#ifndef	SSH_CMD
#	define SSH_CMD	"ssh"
#endif
#ifndef	HMCROOT
#	define HMCROOT	"hscroot"
#endif

#define PIL_PLUGINTYPE          STONITH_TYPE
#define PIL_PLUGINTYPE_S        STONITH_TYPE_S
#define PIL_PLUGIN              ibmhmc
#define PIL_PLUGIN_S            "ibmhmc"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL

#define LOG			PluginImports->log
#define MALLOC			PluginImports->alloc
#define STRDUP  		PluginImports->mstrdup
#define FREE			PluginImports->mfree
#define EXPECT_TOK		OurImports->ExpectToken
#define STARTPROC		OurImports->StartProcess


#define MAX_HOST_NAME_LEN	(256*4)
#define MAX_CMD_NAME_LEN	1024
#define FULLSYSTEMPARTITION	"FullSystemPartition"
#define MAX_POWERON_RETRY	10

#define HMCURL	"http://publib-b.boulder.ibm.com/Redbooks.nsf/RedbookAbstracts/SG247038.html"

static void *		ibmhmc_new(void);
static void		ibmhmc_destroy(Stonith *);
static int		ibmhmc_set_config_file(Stonith *, const char * cfgname);
static int		ibmhmc_set_config_info(Stonith *, const char * info);
static const char *	ibmhmc_getinfo(Stonith * s, int InfoType);
static int		ibmhmc_status(Stonith * );
static int		ibmhmc_reset_req(Stonith* s,int request,const char* host);
static char **		ibmhmc_hostlist(Stonith  *);
static void		ibmhmc_free_hostlist(char **);
static void		ibmhmc_closepi(PILPlugin*pi);
static PIL_rc		ibmhmc_closeintf(PILInterface* pi, void* pd);

static struct stonith_ops ibmhmcOps ={
	ibmhmc_new,		/* Create new STONITH object	*/
	ibmhmc_destroy,		/* Destroy STONITH object	*/
	ibmhmc_set_config_file,	/* set configuration from file	*/
	ibmhmc_set_config_info,	/* Get configuration from file	*/
	ibmhmc_getinfo,		/* Return STONITH info string	*/
	ibmhmc_status,		/* Return STONITH device status	*/
	ibmhmc_reset_req,		/* Request a reset */
	ibmhmc_hostlist,		/* Return list of supported hosts */
	ibmhmc_free_hostlist	/* free above list */
};

PIL_PLUGIN_BOILERPLATE("1.0", Debug, ibmhmc_closepi);

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
	,	&ibmhmcOps
	,	ibmhmc_closeintf		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

struct HMCDevice {	
	const char *		HMCid;
	GList*		 	hostlist;
};

static const char * HMCid = 	"HMCDevice-Stonith";
static const char * NOTibmhmcID = 	"This has been destroyed (HMC Dev)";

#define	ISHMCDEV(i)	(((i) != NULL && (i)->pinfo != NULL)	\
	&& ((struct HMCDevice *)(i->pinfo))->HMCid == HMCid)


#ifndef MALLOCT
	#define MALLOCT(t)	((t *)(MALLOC(sizeof(t)))) 
#endif

#define N_(text)		(text)
#define _(text)			dgettext(ST_TEXTDOMAIN, text)


static void
ibmhmc_closepi(PILPlugin*pi)
{
}

static PIL_rc
ibmhmc_closeintf(PILInterface* pi, void* pd)
{
	return PIL_OK;
}

static int
ibmhmc_status(Stonith  *s)
{
	if (!ISHMCDEV(s)) {
		PILCallLog(LOG, PIL_CRIT, "invalid argument to ibmhmc_status");
		return(S_OOPS);
	}
	/* FIXME!!! REALLY NEED TO IMPLEMENT THIS!! */
	return S_OK;
}


/*
 *	Return the list of hosts configured for this HMC device
 */

static char **
ibmhmc_hostlist(Stonith  *s)
{
	int j;
	struct HMCDevice* dev;
	int numnames = 0;
	char** ret = NULL;
	GList* node = NULL;

	if (!ISHMCDEV(s)) {
		PILCallLog(LOG, PIL_CRIT, "invalid argument to ibmhmc_list_hosts");
		return(NULL);
	}
	dev = (struct HMCDevice*) s->pinfo;
	numnames = g_list_length(dev->hostlist);
	if (numnames<0) {
		PILCallLog(LOG, PIL_CRIT
		,	"unconfigured stonith object in ibmhmc_list_hosts");
		return(NULL);
	}

	ret = (char **)MALLOC((numnames+1)*sizeof(char*));
	if (ret == NULL) {
		PILCallLog(LOG, PIL_CRIT, "out of memory");
		return ret;
	}

	memset(ret, 0, (numnames+1)*sizeof(char*));
	for (node=g_list_first(dev->hostlist), j=0
	;	NULL != node
	;	j++, node = g_list_next(node))			{
		char* host = (char*)node->data;
		ret[j] = STRDUP(host);
	}
	return ret;
}

static void
ibmhmc_free_hostlist (char** hlist)
{
	char** hl = hlist;
	if (hl == NULL) {
		return;
	}
	while (*hl) {
		FREE(*hl);
		*hl = NULL;
		++hl;
	}
	FREE(hlist);
	hlist = NULL;
}

/*
 *	Parse the config information, and stash it away...
 */
static int
ibmhmc_parse_config_info(struct HMCDevice* dev, const char * info)
{
	char host[MAX_HOST_NAME_LEN];
	gchar** strarray = g_strsplit(info, "/", 4);

	if (NULL == strarray[0] || NULL == strarray[1]||
	    NULL == strarray[2] || NULL == strarray[3]) {
		g_strfreev(strarray);
		return S_BADCONFIG;
	}
	g_strfreev(strarray);

	/* You should get the lists of hosts from the adapter, not from a config string... */
	/* FIXME!! */
	memset(host, 0, MAX_HOST_NAME_LEN);
	while(1) {
		if (sscanf(info, "%s", host)<1) {
			break;
		}	
		dev->hostlist = g_list_append(dev->hostlist, STRDUP(host));
		info += strlen(host);
	}
	return S_OK;
}


/*
 *	Reset the given host, and obey the request type.
 *	We should reset without power cycle for the non-partitioned case
 *	(FIXME!)
 */
static int
ibmhmc_reset_req(Stonith * s, int request, const char * host)
{
	GList*			node = NULL;
	struct HMCDevice*	dev = NULL;
	char			off_cmd[MAX_CMD_NAME_LEN];
	char			on_cmd[MAX_CMD_NAME_LEN];
	gchar**			strarray = NULL;
	int			i;
	
	if (!ISHMCDEV(s) || (NULL == host)) {
		PILCallLog(LOG, PIL_CRIT, "invalid argument to %s", __FUNCTION__);
		return(S_OOPS);
	}
	
	dev = (struct HMCDevice*) s->pinfo;

	for (node=g_list_first(dev->hostlist)
	;	NULL != node
	;	node=g_list_next(node)) {
		
		if (strcasecmp((char*)node->data, host) == 0) {
			break;
		};
	}

	if (!node) {
		PILCallLog(LOG, PIL_CRIT,
			_("host %s is not configured in this STONITH module."
			 "Please check you configuration information."),
			host);
		return (S_OOPS);
	}

	strarray = g_strsplit((char*)node->data, "/", 4);

	if (0 == strcasecmp(strarray[2], FULLSYSTEMPARTITION)) {

		snprintf(off_cmd, MAX_CMD_NAME_LEN
		,	SSH_CMD " -l " HMCROOT " %s chsysstate"
		" -r sys -m %s -o off -n %s -c full"
		,	 strarray[0], strarray[1], strarray[1]);

		snprintf(on_cmd, MAX_CMD_NAME_LEN
		,	SSH_CMD " -l " HMCROOT " %s chsysstate"
		 " -r sys -m %s -o on -n %s -c full -b norm"
		,	 strarray[0], strarray[1], strarray[1]);
	} else {
		snprintf(off_cmd, MAX_CMD_NAME_LEN
		,	SSH_CMD " -l " HMCROOT " %s reset_partition"
			 " -m %s -p %s -t hard",
			 strarray[0], strarray[1], strarray[2]);
		snprintf(on_cmd, MAX_CMD_NAME_LEN,
			 SSH_CMD " -l hscroot %s start_partition"
			 " -p %s -f %s -m %s",
			 strarray[0], strarray[2], strarray[3], strarray[1]);

	}
	g_strfreev(strarray);

	if (request != ST_POWERON && 0 != system(off_cmd)) {
		PILCallLog(LOG, PIL_CRIT, "command %s failed", off_cmd);
	}
	for (i=0; i < MAX_POWERON_RETRY; i++) {	
		if (request != ST_POWEROFF && 0 != system(on_cmd)) {
			sleep(1);
		}else{
			break;
		}
	}
	if (MAX_POWERON_RETRY == i) {
		PILCallLog(LOG, PIL_CRIT, "command %s failed", on_cmd);
	}

	PILCallLog(LOG, PIL_INFO, _("Host %s ibmhmc-reset."), host);
	return S_OK;
}

/*
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */
static int
ibmhmc_set_config_file(Stonith* s, const char * configname)
{
	FILE* cfgfile = NULL;
	struct HMCDevice* dev = NULL;
	char hostline[MAX_HOST_NAME_LEN];
	
	if (!ISHMCDEV(s)) {
		PILCallLog(LOG, PIL_CRIT, "invalid argument to HMC_set_configfile");
		return(S_OOPS);
	}

	dev = (struct HMCDevice*) s->pinfo;

	cfgfile = fopen(configname, "r");
	if (cfgfile == NULL)  {
		PILCallLog(LOG, PIL_CRIT, "Cannot open %s", configname);
		return(S_BADCONFIG);
	}

	while (fgets(hostline, sizeof(hostline), cfgfile) != NULL){
		if (*hostline == '#' || *hostline == '\n' || *hostline == EOS){
			continue;
		}
		if (S_OK != ibmhmc_parse_config_info(dev, hostline)) {
			return S_BADCONFIG;
		}
	}
	return S_OK;
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
ibmhmc_set_config_info(Stonith* s, const char * info)
{
	struct HMCDevice* dev;

	if (!ISHMCDEV(s)) {
		PILCallLog(LOG, PIL_CRIT, "%s: invalid argument", __FUNCTION__);
		return(S_OOPS);
	}
	dev = (struct HMCDevice *)s->pinfo;

	return(ibmhmc_parse_config_info(dev, info));
}

static const char*
ibmhmc_getinfo(Stonith* s, int reqtype)
{
	struct HMCDevice* dev;
	char* ret;

	if (!ISHMCDEV(s)) {
		PILCallLog(LOG, PIL_CRIT, "HMC_idinfo: invalid argument");
		return NULL;
	}

	dev = (struct HMCDevice *)s->pinfo;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = _("IBM pSeries HMC");
			break;

		case ST_CONF_INFO_SYNTAX:
			/* FIXME!  hostnames should go away... */
			ret = _("HMC_NAME/SYS_NAME/PAR_NAME/PROFILE_NAME hostname ...");
			break;

		case ST_CONF_FILE_SYNTAX:
			/* FIXME!  hostnames should go away... */
			ret = _("HMC_NAME/SYS_NAME/PAR_NAME/PROFILE_NAME hostname ..."
			"Blank lines and lines beginning with # are ignored");
			break;

		case ST_DEVICEDESCR:
			/* FIXME! */
			ret = _("IBM pSeries Hardware Management Console (HMC)\n"
			"Use for HMC-equipped IBM pSeries Server\n"
			"Providing the list of hosts should go away (!)...\n"
			"This code probably only works on the POWER4 architecture systems\n"
			" See " HMCURL " for more information.");
			break;

		default:
			ret = NULL;
			break;
	}
	return ret;
}

/*
 *	HMC Stonith destructor...
 */
static void
ibmhmc_destroy(Stonith *s)
{
	struct HMCDevice* dev;

	if (!ISHMCDEV(s)) {
		PILCallLog(LOG, PIL_CRIT, "%s: invalid argument", __FUNCTION__);
		return;
	}
	dev = (struct HMCDevice *)s->pinfo;

	dev->HMCid = NOTibmhmcID;
	if (dev->hostlist) {
		GList* node;
		while (NULL != (node=g_list_first(dev->hostlist))) {
			dev->hostlist = g_list_remove_link(dev->hostlist, node);
			FREE(node->data);
			g_list_free(node);
		}
		dev->hostlist = NULL;
	}
	FREE(dev);
}

static void *
ibmhmc_new(void)
{
	struct HMCDevice* dev = MALLOCT(struct HMCDevice);

	if (dev == NULL) {
		PILCallLog(LOG, PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(dev, 0, sizeof(*dev));
	dev->HMCid = HMCid;
	dev->hostlist = NULL;
	return((void *)dev);
}
