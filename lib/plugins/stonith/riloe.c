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

#define	DEVICE	"RILOE STONITH device"
#include "stonith_plugin_common.h"

#define PIL_PLUGIN              riloe
#define PIL_PLUGIN_S            "riloe"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

static StonithPlugin *	riloe_new(const char *);
static void		riloe_destroy(StonithPlugin *);
static int		riloe_set_config(StonithPlugin *, StonithNVpair *);
static const char **	riloe_get_confignames(StonithPlugin * );
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
	char **		hostlist;
	int		hostcount;
};

static const char * pluginid = "pluginDevice-Stonith";
static const char * NOTriloeID = "Hey, dummy this has been destroyed (RiloeDev)";

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
	int		numnames = 0;
	char **		ret = NULL;
	struct pluginDevice*	nd;
	int		j;

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,NULL);
	nd = (struct pluginDevice*) s;
	if (nd->hostcount < 0) {
		LOG(PIL_CRIT
		,	"unconfigured stonith object in RILOE_list_hosts");
		return(NULL);
	}
	numnames = nd->hostcount;

	ret = (char **)MALLOC(numnames*sizeof(char*));
	if (ret == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return ret;
	}

	memset(ret, 0, numnames*sizeof(char*));

	for (j=0; j < numnames-1; ++j) {
		ret[j] = MALLOC(strlen(nd->hostlist[j])+1);
		if (ret[j] == NULL) {
			stonith_free_hostlist(ret);
			ret = NULL;
			return ret;
		}
		strcpy(ret[j], nd->hostlist[j]);
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
RILOE_parse_config_info(struct pluginDevice* nd, const char * info)
{
	char **			ret;
	int			wc;
	int			numnames;
	const char *		s = info;
	int			j;

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	if (nd->hostcount >= 0) {
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
		}
	}
	nd->hostlist = ret;
	nd->hostcount = numnames;
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
	
	sprintf(cmd, "%s %s reset", RILOE_COMMAND, host);
	
	if (Debug) {
		LOG(PIL_DEBUG, "command %s  will be execute", cmd);
	}

	if (system(cmd) == 0)
		return S_OK;
	else {
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
	const char*	RILOEline;

	struct pluginDevice*	nd;

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,S_OOPS);
	nd = (struct pluginDevice*) s;
	
	if ((RILOEline = OurImports->GetValue(list, ST_HOSTLIST)) == NULL) {
		return S_OOPS;
	}
	
	return (RILOE_parse_config_info(nd , RILOEline));
}

/*
 *  Return the  Stonith plugin configuration parameter
 */
static const char**
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
	char *		ret;

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
			ret = _("riloe STONITH device");
			break;
		case ST_DEVICEDESCR:
			ret = _("Compaq RILOE STONITH device\n"
			"Very early version!");
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
	struct pluginDevice*	nd = MALLOCT(struct pluginDevice);

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
	nd->sp.s_ops = &riloeOps;

	return &(nd->sp);
}
