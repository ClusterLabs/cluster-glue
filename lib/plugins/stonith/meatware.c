/*
 * Stonith module for Human Operator Stonith device
 *
 * Copyright (c) 2001 Gregor Binder <gbinder@sysfive.com>
 *
 *   This module is largely based on the "NULL Stonith device", written
 *   by Alan Robertson <alanr@unix.sh>, using code by David C. Teigland
 *   <teigland@sistina.com> originally appeared in the GFS stomith
 *   meatware agent.
 *
 * Mangled by Zhaokai <zhaokai@cn.ibm.com>, IBM, 2005
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

#define	DEVICE	"Meatware STONITH device"
#include "stonith_plugin_common.h"

#define PIL_PLUGIN              meatware
#define PIL_PLUGIN_S            "meatware"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

static StonithPlugin *	meatware_new(const char *);
static void		meatware_destroy(StonithPlugin *);
static int		meatware_set_config(StonithPlugin *, StonithNVpair *);
static const char * const *	meatware_get_confignames(StonithPlugin *);
static const char *	meatware_getinfo(StonithPlugin * s, int InfoType);
static int		meatware_status(StonithPlugin * );
static int		meatware_reset_req(StonithPlugin * s, int request, const char * host);
static char **		meatware_hostlist(StonithPlugin  *);

static struct stonith_ops meatwareOps ={
	meatware_new,		/* Create new STONITH object		*/
	meatware_destroy,	/* Destroy STONITH object		*/
	meatware_getinfo,	/* Return STONITH info string		*/
	meatware_get_confignames,/* Return STONITH info string		*/
	meatware_set_config,	/* Get configuration from NVpairs	*/
	meatware_status,	/* Return STONITH device status		*/
	meatware_reset_req,	/* Request a reset 			*/
	meatware_hostlist,	/* Return list of supported hosts 	*/
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
	,	&meatwareOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*
 *	Meatware STONITH device.
 */

struct pluginDevice {
	StonithPlugin   sp;
	const char *	pluginid;
	const char *	idinfo;
	char **		hostlist;
	int		hostcount;
};

static const char * pluginid = "MeatwareDevice-Stonith";
static const char * NOTpluginID = "Meatware device has been destroyed";

#include "stonith_config_xml.h"

static const char *meatwareXML = 
  XML_PARAMETERS_BEGIN
    XML_HOSTLIST_PARM
  XML_PARAMETERS_END;

static int
meatware_status(StonithPlugin  *s)
{
	ERRIFWRONGDEV(s,S_OOPS);
	return S_OK;
}


/*
 *	Return the list of hosts configured for this Meat device
 */

static char **
meatware_hostlist(StonithPlugin  *s)
{
	struct pluginDevice*	nd;

	ERRIFWRONGDEV(s,NULL);
	nd = (struct pluginDevice*) s;
	if (nd->hostcount < 0) {
		LOG(PIL_CRIT
		,	"unconfigured stonith object in Meatware_list_hosts");
		return(NULL);
	}

	return OurImports->CopyHostList((const char * const *)nd->hostlist);
}

/*
 *	Parse the config information, and stash it away...
 */

static int
Meat_parse_config_info(struct pluginDevice* nd, const char * info)
{
	LOG(PIL_INFO , "parse config info info=%s",info);
	if (nd->hostcount >= 0) {
		return(S_OOPS);
	}

	nd->hostlist = OurImports->StringToHostList(info);
	if (nd->hostlist == NULL) {
		LOG(PIL_CRIT,"StringToHostList() failed");
		return S_OOPS;
	}
	for (nd->hostcount = 0; nd->hostlist[nd->hostcount]; nd->hostcount++) {
		strdown(nd->hostlist[nd->hostcount]);
	}
	return(S_OK);
}


/*
 *	Indicate that host must be power cycled manually.
 */
static int
meatware_reset_req(StonithPlugin * s, int request, const char * host)
{
	int fd, rc;
	const char *	meatpipe_pr = HA_VARRUNDIR "/meatware"; /* if you intend to
							change this, modify
							meatclient.c as well */

	char		line[256], meatpipe[256];
	char		resp_addr[50], resp_mw[50], resp_result[50];

	
	ERRIFWRONGDEV(s,S_OOPS);
	
	snprintf(meatpipe, 256, "%s.%s", meatpipe_pr, host);
	umask(0);
	unlink(meatpipe);

	rc = mkfifo(meatpipe, (S_IRUSR | S_IWUSR));

	if (rc < 0) {
		LOG(PIL_CRIT, "cannot create FIFO for Meatware_reset_host");
		return S_OOPS;
	}

	LOG(PIL_CRIT, "OPERATOR INTERVENTION REQUIRED to reset %s.", host);
	LOG(PIL_CRIT, "Run \"meatclient -c %s\" AFTER power-cycling the "
	                 "machine.", host);

	fd = open(meatpipe, O_RDONLY);

	if (fd < 0) {
		LOG(PIL_CRIT, "cannot open FIFO for Meatware_reset_host");
		return S_OOPS;
	}

	alarm(600);
	memset(line, 0, 256);
	rc = read(fd, line, 256);
	alarm(0);

	if (rc < 0) {
		LOG(PIL_CRIT, "read error on FIFO for Meatware_reset_host");
		return S_OOPS;
	}

	memset(resp_mw, 0, 50);
	memset(resp_result, 0, 50);
	memset(resp_addr, 0, 50);

	if (sscanf(line, "%s %s %s", resp_mw, resp_result, resp_addr) < 3) {
		LOG(PIL_CRIT, "Format error - failed to Meatware-reset node %s",
				host);
		return S_RESETFAIL;
	}
	
	strdown(resp_addr);

	if (strncmp(resp_mw, "meatware", 8) ||
	    strncmp(resp_result, "reply", 5) ||
	    strncasecmp(resp_addr, host, strlen(resp_addr))) {
		LOG(PIL_CRIT, "failed to Meatware-reset node %s", host);
		return S_RESETFAIL;
	}else{
		LOG(PIL_INFO, "node Meatware-reset: %s", host);
		unlink(meatpipe);
		return S_OK;
	}
}

/*
 *	Parse the information in the given string 
 *	and stash it away...
 */
static int
meatware_set_config(StonithPlugin* s, StonithNVpair *list)
{

	struct pluginDevice*	nd;
	int	rc;
	StonithNamesToGet	namestocopy [] =
	{	{ST_HOSTLIST,	NULL}
	,	{NULL,		NULL}
	};

	ERRIFWRONGDEV(s,S_OOPS);
	nd = (struct pluginDevice*) s;
	
	if ((rc = OurImports->CopyAllValues(namestocopy, list)) != S_OK) {
		return rc;
	}
	rc = Meat_parse_config_info(nd, namestocopy[0].s_value);
	FREE(namestocopy[0].s_value);
	return rc;
}

/*
 * Return STONITH config vars
 */
static const char * const *
meatware_get_confignames(StonithPlugin* p)
{
	static const char *	MeatwareParams[] = {ST_HOSTLIST, NULL };
	return MeatwareParams;
}

/*
 * Return STONITH info string
 */
static const char *
meatware_getinfo(StonithPlugin * s, int reqtype)
{
	struct pluginDevice* nd;
	const char * ret;

	ERRIFWRONGDEV(s,NULL);
	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	nd = (struct pluginDevice *)s;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = nd->idinfo;
			break;
		case ST_DEVICENAME:
			ret = "Your Name Here";
			break;
		case ST_DEVICEDESCR:
			ret = "Human (meatware) intervention STONITH device.\n"
			"This STONITH agent prompts a human to reset a machine.\n"
			"The human tells it when the reset was completed.";
			break;
		case ST_CONF_XML:		/* XML metadata */
			ret = meatwareXML;
			break;
		default:
			ret = NULL;
			break;
	}
	return ret;
}

/*
 *	Meat Stonith destructor...
 */
static void
meatware_destroy(StonithPlugin *s)
{
	struct pluginDevice* nd;

	VOIDERRIFWRONGDEV(s);
	nd = (struct pluginDevice *)s;

	nd->pluginid = NOTpluginID;
	if (nd->hostlist) {
		stonith_free_hostlist(nd->hostlist);
		nd->hostlist = NULL;
	}
	nd->hostcount = -1;
	FREE(nd);
}

/* Create a new Meatware Stonith device. */

static StonithPlugin *
meatware_new(const char *subplugin)
{
	struct pluginDevice*	nd = ST_MALLOCT(struct pluginDevice);

	if (nd == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(nd, 0, sizeof(*nd));
	nd->pluginid = pluginid;
	nd->hostlist = NULL;
	nd->hostcount = -1;
	nd->idinfo = DEVICE;
	nd->sp.s_ops = &meatwareOps;

	return &(nd->sp);
}
