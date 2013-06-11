/*
 * Stonith module for RILOE Stonith device
 *
 * Copyright (c) 2004 Alain St-Denis <alain.st-denis@ec.gc.ca>
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

#define	DEVICE	"Compaq RILOE"
#include "stonith_plugin_common.h"

#define PIL_PLUGIN              riloe
#define PIL_PLUGIN_S            "riloe"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

static StonithPlugin *	riloe_new(const char *);
static void		riloe_destroy(StonithPlugin *);
static int		riloe_set_config(StonithPlugin *, StonithNVpair *);
static const char * const *	riloe_get_confignames(StonithPlugin * );
static const char *	riloe_getinfo(StonithPlugin * s, int InfoType);
static int		riloe_status(StonithPlugin * );
static int		riloe_reset_req(StonithPlugin * s, int request, const char * host);
static char **		riloe_hostlist(StonithPlugin  *);

static struct stonith_ops riloeOps ={
	riloe_new,		/* Create new STONITH object		*/
	riloe_destroy,		/* Destroy STONITH object		*/
	riloe_getinfo,		/* Return STONITH info string		*/
	riloe_get_confignames,	/* Return STONITH info string		*/
	riloe_set_config,	/* Get configuration from NVpairs	*/
	riloe_status,		/* Return STONITH device status		*/
	riloe_reset_req,	/* Request a reset 			*/
	riloe_hostlist,		/* Return list of supported hosts 	*/
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
	,	&riloeOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

#define RILOE_COMMAND   STONITH_MODULES "/ribcl.py"

/*
 *	Riloe STONITH device.  We are very agreeable, but don't do much :-)
 */

struct pluginDevice {
	StonithPlugin	sp;
	const char *	pluginid;
	const char *	idinfo;
	char **		hostlist;
	int		hostcount;
};

static const char * pluginid = "RiloeDevice-Stonith";
static const char * NOTriloeID = "Riloe device has been destroyed";

#include "stonith_config_xml.h"

static const char *riloeXML = 
  XML_PARAMETERS_BEGIN
    XML_HOSTLIST_PARM
  XML_PARAMETERS_END;

static int
riloe_status(StonithPlugin  *s)
{

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,S_OOPS);
	return S_OK;
}


/*
 *	Return the list of hosts configured for this RILOE device
 */

static char **
riloe_hostlist(StonithPlugin  *s)
{
	struct pluginDevice*	nd;

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,NULL);
	nd = (struct pluginDevice*) s;
	if (nd->hostcount < 0) {
		LOG(PIL_CRIT
		,	"unconfigured stonith object in %s", __FUNCTION__);
		return(NULL);
	}

	return OurImports->CopyHostList((const char * const*)nd->hostlist);
}

/*
 *	Parse the config information, and stash it away...
 */

static int
RILOE_parse_config_info(struct pluginDevice* nd, const char * info)
{
	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

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
 *	Pretend to reset the given host on this Stonith device.
 *	(we don't even error check the "request" type)
 */
static int
riloe_reset_req(StonithPlugin * s, int request, const char * host)
{
	char cmd[4096];

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,S_OOPS);
	
	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}
	
	snprintf(cmd, sizeof(cmd), "%s %s reset", RILOE_COMMAND, host);
	
	if (Debug) {
		LOG(PIL_DEBUG, "command %s will be executed", cmd);
	}

	if (system(cmd) == 0) {
		return S_OK;
	} else {
		LOG(PIL_CRIT, "command %s failed", cmd);
		return(S_RESETFAIL);
	}
}

/*
 *	Parse the information in the given string,
 *	and stash it away...
 */
static int
riloe_set_config(StonithPlugin* s, StonithNVpair *list)
{
	StonithNamesToGet	namestocopy [] =
	{	{ST_HOSTLIST,	NULL}
	,	{NULL,		NULL}
	};
	struct pluginDevice*	nd;
	int rc;

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,S_OOPS);
	nd = (struct pluginDevice*) s;
	
	if ((rc = OurImports->CopyAllValues(namestocopy, list)) != S_OK) {
		return rc;
	}
	
	rc = RILOE_parse_config_info(nd , namestocopy[0].s_value);
	FREE(namestocopy[0].s_value);
	return rc;
}

/*
 *  Return the  Stonith plugin configuration parameter
 */
static const char* const *
riloe_get_confignames(StonithPlugin* p)
{
	static const char *	RiloeParams[] = {ST_HOSTLIST, NULL };

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	return RiloeParams;
}

/*
 * Return STONITH info string
 */

static const char *
riloe_getinfo(StonithPlugin * s, int reqtype)
{
	struct pluginDevice* nd;
	const char * ret;

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,NULL);
	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	nd = (struct pluginDevice *)s;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = nd->idinfo;
			break;
		case ST_DEVICEDESCR:
			ret = "Compaq RILOE STONITH device\n"
			"Very early version!";
			break;
		case ST_DEVICEURL:
			ret = "http://www.hp.com/";
			break;
		case ST_CONF_XML:		/* XML metadata */
			ret = riloeXML;
			break;
		default:
			ret = NULL;
			break;
	}
	return ret;
}

/*
 *	RILOE Stonith destructor...
 */
static void
riloe_destroy(StonithPlugin *s)
{
	struct pluginDevice* nd;

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	VOIDERRIFWRONGDEV(s);
	nd = (struct pluginDevice *)s;

	nd->pluginid = NOTriloeID;
	if (nd->hostlist) {
		stonith_free_hostlist(nd->hostlist);
		nd->hostlist = NULL;
	}
	nd->hostcount = -1;
	FREE(nd);
}

/* Create a new Riloe Stonith device.  Too bad this function can't be static */
static StonithPlugin *
riloe_new(const char *subplugin)
{
	struct pluginDevice*	nd = ST_MALLOCT(struct pluginDevice);

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	if (nd == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(nd, 0, sizeof(*nd));
	nd->pluginid = pluginid;
	nd->hostlist = NULL;
	nd->hostcount = -1;
	nd->idinfo = DEVICE;
	nd->sp.s_ops = &riloeOps;

	return &(nd->sp);
}
