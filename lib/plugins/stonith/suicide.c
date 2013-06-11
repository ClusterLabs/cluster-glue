/* File: suicide.c
 * Description: Stonith module for suicide
 *
 * Author: Sun Jiang Dong <sunjd@cn.ibm.com>
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
 */

#include <lha_internal.h>
#include <config.h>
#include <sys/utsname.h>

#define	DEVICE	"Suicide STONITH device"
#include "stonith_plugin_common.h"

#define PIL_PLUGIN              suicide
#define PIL_PLUGIN_S            "suicide"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

static StonithPlugin *	suicide_new(const char *);
static void		suicide_destroy(StonithPlugin *);
static const char * const *	suicide_get_confignames(StonithPlugin *);
static int		suicide_set_config(StonithPlugin *, StonithNVpair*);
static const char *	suicide_get_info(StonithPlugin * s, int InfoType);
static int		suicide_status(StonithPlugin * );
static int		suicide_reset_req(StonithPlugin * s, int request
					, const char * host);
static char **		suicide_hostlist(StonithPlugin  *);

static struct stonith_ops suicideOps ={
	suicide_new,			/* Create new STONITH object	*/
	suicide_destroy,		/* Destroy STONITH object	*/
	suicide_get_info,		/* Return STONITH info string	*/
	suicide_get_confignames,	/* Return configuration parameters */
	suicide_set_config,		/* Set configuration */
	suicide_status,			/* Return STONITH device status	*/
	suicide_reset_req,		/* Request a reset */
	suicide_hostlist,		/* Return list of supported hosts */
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
	,	&suicideOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

#define REBOOT_COMMAND "nohup sh -c 'sleep 2; " REBOOT " " REBOOT_OPTIONS " </dev/null >/dev/null 2>&1' &"
#define POWEROFF_COMMAND "nohup sh -c 'sleep 2; " POWEROFF_CMD " " POWEROFF_OPTIONS " </dev/null >/dev/null 2>&1' &"
/*
#define REBOOT_COMMAND "echo 'sleep 2; "  REBOOT " " REBOOT_OPTIONS "' | SHELL=/bin/sh at now >/dev/null 2>&1"
#define POWEROFF_COMMAND "echo 'sleep 2; "  POWEROFF_CMD " " POWEROFF_OPTIONS "' | SHELL=/bin/sh at now >/dev/null 2>&1"
*/

/*
 *    Suicide STONITH device
 */
struct pluginDevice {
	StonithPlugin	sp;
	const char *	pluginid;
	const char *	idinfo;
};

static const char * pluginid = "SuicideDevice-Stonith";
static const char * NOTpluginid = "Suicide device has been destroyed";

#include "stonith_config_xml.h"

static const char *suicideXML = 
  XML_PARAMETERS_BEGIN
  XML_PARAMETERS_END;

static int
suicide_status(StonithPlugin  *s)
{
	ERRIFWRONGDEV(s, S_OOPS);

	return S_OK;
}

/*
 *	Return the list of hosts configured for this Suicide device
 */
static char **
suicide_hostlist(StonithPlugin  *s)
{
	char** 		ret = NULL;
	struct utsname	name;

	ERRIFWRONGDEV(s, NULL);

	if (uname(&name) == -1) {
		LOG(PIL_CRIT, "uname error %d", errno);
		return ret;
	}

	ret = OurImports->StringToHostList(name.nodename);
	if (ret == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return ret;
	}
	strdown(ret[0]);

	return ret;
}

/*
 *	Suicide - reset or poweroff itself.
 */
static int
suicide_reset_req(StonithPlugin * s, int request, const char * host)
{
	int		rc = -1;
	struct utsname	name;

	ERRIFWRONGDEV(s, S_OOPS);

	if (request == ST_POWERON) {
		LOG(PIL_CRIT, "%s not capable of power-on operation", DEVICE);
		return S_INVAL;
	} else if (request != ST_POWEROFF && request != ST_GENERIC_RESET) {
		LOG(PIL_CRIT, "As for suicide virtual stonith device, "
			"reset request=%d is not supported", request);
		return S_INVAL;
	}

	if (uname(&name) == -1) {
		LOG(PIL_CRIT, "uname error %d", errno);
		return S_RESETFAIL ;
	}

	if (strcmp(name.nodename, host)) {
		LOG(PIL_CRIT, "%s doesn't control host [%s]"
		,	name.nodename, host);
		return S_RESETFAIL ;
	}

	LOG(PIL_INFO, "Initiating suicide on host %s", host);
	
	rc = system(
	    request == ST_GENERIC_RESET ? REBOOT_COMMAND : POWEROFF_COMMAND);

	if (rc == 0)  {
		LOG(PIL_INFO, "Suicide stonith succeeded.");
    		return S_OK;
	} else {
		LOG(PIL_CRIT, "Suicide stonith failed.");
		return S_RESETFAIL ;
	}
}

static const char * const *
suicide_get_confignames(StonithPlugin* p)
{
	/* Donnot need to initialize from external. */
	static const char *	SuicideParams[] = { NULL };
	return SuicideParams;
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
suicide_set_config(StonithPlugin* s, StonithNVpair* list)
{
	ERRIFWRONGDEV(s,S_OOPS);
	return S_OK;
}

static const char *
suicide_get_info(StonithPlugin * s, int reqtype)
{
	struct pluginDevice*	sd = (struct pluginDevice *)s;
	const char *		ret;

	ERRIFWRONGDEV(s, NULL);
	sd = (struct pluginDevice *)s;

	switch (reqtype) {
	case ST_DEVICEID:
		ret = sd->idinfo;
		break;

	case ST_DEVICENAME:
		ret = "suicide STONITH device";
		break;

	case ST_DEVICEDESCR:	/* Description of device type */
		ret = "Virtual device to reboot/powerdown itself.\n";
		break;

	case ST_CONF_XML:		/* XML metadata */
		ret = suicideXML;
		break;

	default:
		ret = NULL;
		break;
	}
	return ret;
}

/*
 * Suicide Stonith destructor...
 */
static void
suicide_destroy(StonithPlugin *s)
{
	struct pluginDevice* sd;

	VOIDERRIFWRONGDEV(s);

	sd = (struct pluginDevice *)s;

	sd->pluginid = NOTpluginid;
	FREE(sd);
}

/* Create a new suicide Stonith device */
static StonithPlugin*
suicide_new(const char * subplugin)
{
	struct pluginDevice*	sd = ST_MALLOCT(struct pluginDevice);

	if (sd == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(sd, 0, sizeof(*sd));
	sd->pluginid = pluginid;
	sd->idinfo = DEVICE;
	sd->sp.s_ops = &suicideOps;
	return &(sd->sp);
}
