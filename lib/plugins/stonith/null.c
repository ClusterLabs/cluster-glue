/*
 * Stonith module for NULL Stonith device
 *
 * Copyright (c) 2000 Alan Robertson <alanr@unix.sh>
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

#define	DEVICE	"NULL STONITH device"
#include "stonith_plugin_common.h"

#define PIL_PLUGIN              null
#define PIL_PLUGIN_S            "null"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

struct pluginDevice {
	StonithPlugin	sp;
	const char *	pluginid;
	const char *	idinfo;
	char **		hostlist;
	int		hostcount;
};

static StonithPlugin*	null_new(const char *);
static void		null_destroy(StonithPlugin *);
static int		null_set_config(StonithPlugin*
,				StonithNVpair*);
static const char * const *	null_get_confignames(StonithPlugin*);
static const char *	null_getinfo(StonithPlugin * s, int InfoType);
static int		null_status(StonithPlugin * );
static int		null_reset_req(StonithPlugin * s
,			int request, const char * host);
static char **		null_hostlist(StonithPlugin  *);

static struct stonith_ops nullOps ={
	null_new,		/* Create new STONITH object	*/
	null_destroy,		/* Destroy STONITH object	*/
	null_getinfo,		/* Return STONITH info string	*/
	null_get_confignames,	/* Return list of config params */
	null_set_config,	/* configure fron NV pairs */
	null_status,		/* Return STONITH device status	*/
	null_reset_req,		/* Request a reset */
	null_hostlist,		/* Return list of supported hosts */
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
	,	&nullOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*
 *	Null STONITH device.  We are very agreeable, but don't do much :-)
 */


static const char * pluginid = "nullDevice-Stonith";
static const char * NOTpluginID = "Null device has been destroyed";

#include "stonith_config_xml.h"

static const char *nullXML = 
  XML_PARAMETERS_BEGIN
    XML_HOSTLIST_PARM
  XML_PARAMETERS_END;

static int
null_status(StonithPlugin  *s)
{

	ERRIFWRONGDEV(s, S_OOPS);
	return S_OK;
}


/*
 *	Return the list of hosts configured for this NULL device
 */

static char **
null_hostlist(StonithPlugin  *s)
{
	struct pluginDevice*	nd = (struct pluginDevice*)s;

	ERRIFWRONGDEV(s, NULL);
	return OurImports->CopyHostList((const char * const *)nd->hostlist);
}


/*
 *	Pretend to reset the given host on this Stonith device.
 *	(we don't even error check the "request" type)
 */
static int
null_reset_req(StonithPlugin * s, int request, const char * host)
{

	ERRIFWRONGDEV(s,S_OOPS);

	/* Real devices need to pay attention to the "request" */
	/* (but we don't care ;-)) */

	LOG(PIL_INFO, "Host null-reset: %s", host);
	return S_OK;
}


static const char * const *
null_get_confignames(StonithPlugin* p)
{
	static const char *	NullParams[] = {ST_HOSTLIST, NULL };
	return NullParams;
}

/*
 *	Parse the config information in the given string,
 *	and stash it away...
 */
static int
null_set_config(StonithPlugin* s, StonithNVpair* list)
{
	struct pluginDevice* nd = (struct pluginDevice*) s;
	StonithNamesToGet	namestocopy [] =
	{	{ST_HOSTLIST,	NULL}
	,	{NULL,		NULL}
	};
	int rc;

	ERRIFWRONGDEV(s, S_OOPS);

	if ((rc=OurImports->CopyAllValues(namestocopy, list)) != S_OK) {
		return rc;
	}
	nd->hostlist = OurImports->StringToHostList(namestocopy[0].s_value);
	FREE(namestocopy[0].s_value);
	if (nd->hostlist == NULL) {
		LOG(PIL_CRIT,"StringToHostList() failed");
		return S_OOPS;
	}
	for (nd->hostcount = 0; nd->hostlist[nd->hostcount]
	;	nd->hostcount++) {
		strdown(nd->hostlist[nd->hostcount]);
	}
	return nd->hostcount ? S_OK : S_BADCONFIG;
}

static const char *
null_getinfo(StonithPlugin * s, int reqtype)
{
	struct pluginDevice* nd = (struct pluginDevice*) s;
	const char *		ret;

	ERRIFWRONGDEV(s, NULL);

	switch (reqtype) {
		case ST_DEVICEID:
			ret = nd->idinfo;
			break;
	
		case ST_DEVICENAME:
			ret = "(nil)";
			break;

		case ST_DEVICEDESCR:
			ret = "Dummy (do-nothing) STONITH device\n"
			"FOR TESTING ONLY!";
			break;

		case ST_CONF_XML:		/* XML metadata */
			ret = nullXML;
			break;

		default:
			ret = NULL;
			break;
	}
	return ret;
}

/*
 *	NULL Stonith destructor...
 */
static void
null_destroy(StonithPlugin *s)
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
	FREE(s);
}

/* Create a new Null Stonith device.
 * Too bad this function can't be static
 */
static StonithPlugin *
null_new(const char *subplugin)
{
	struct pluginDevice*	nd = ST_MALLOCT(struct pluginDevice);

	if (nd == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(nd, 0, sizeof(*nd));
	nd->pluginid = pluginid;
	nd->idinfo = DEVICE;
	nd->sp.s_ops = &nullOps;
	return (StonithPlugin *)nd;
}
