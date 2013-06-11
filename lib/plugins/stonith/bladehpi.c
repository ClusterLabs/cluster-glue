/*
 * Stonith module for BladeCenter via OpenHPI, an implementation of Service 
 *   Availability Forum's Hardware Platfrom Interface
 *
 * Author: Dave Blaschke <debltc@us.ibm.com>
 *
 * Copyright (c) 2005 International Business Machines
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

#define DEVICE		"IBM BladeCenter (OpenHPI)"

#include "stonith_plugin_common.h"

#define PIL_PLUGIN		bladehpi
#define PIL_PLUGIN_S            "bladehpi"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

#include <openhpi/SaHpi.h>

/* Maximum number of seconds to wait for host to power off */
#define MAX_POWEROFF_WAIT	60

/* entity_root, the one required plugin parameter */
#define ST_ENTITYROOT		"entity_root"

/* String format of entity_root */
#define SYSTEM_CHASSIS_FMT	"{SYSTEM_CHASSIS,%d}"

/* soft_reset, the one optional plugin parameter */
#define ST_SOFTRESET		"soft_reset"

#define OPENHPIURL		"http://www.openhpi.org/"

/* OpenHPI resource types of interest to this plugin */
#define OHRES_NONE		0
#define OHRES_BLADECENT		1
#define OHRES_MGMTMOD		2
#define OHRES_BLADE		3

/* IBMBC_WAIT_FOR_OFF - This constant has to do with the problem that
   saHpiResourcePowerStateSet can return before the desired state has been
   achieved by the blade.  In the SAHPI_POWER_OFF case this is not good,
   as whoever calls this plugin assumes that the power is actually off
   when the plugin returns with a successful return code.  Define this
   constant to build code that loops in one second intervals after calling
   saHpiResourcePowerStateSet(SAHPI_POWER_OFF) to make sure the power is
   really off.
#define IBMBC_WAIT_FOR_OFF */

static StonithPlugin *	bladehpi_new(const char *);
static void		bladehpi_destroy(StonithPlugin *);
static const char *	bladehpi_getinfo(StonithPlugin *, int);
static const char * const *	bladehpi_get_confignames(StonithPlugin *);
static int		bladehpi_status(StonithPlugin *);
static int		bladehpi_reset_req(StonithPlugin *, int, const char *);
static char **		bladehpi_hostlist(StonithPlugin *);
static int		bladehpi_set_config(StonithPlugin *, StonithNVpair *);

static struct stonith_ops bladehpiOps = {
	bladehpi_new,			/* Create new STONITH object	*/
	bladehpi_destroy,		/* Destroy STONITH object	*/
	bladehpi_getinfo,		/* Return STONITH info string	*/
	bladehpi_get_confignames,	/* Return configuration parameters */
	bladehpi_set_config,		/* Set configuration            */
	bladehpi_status,		/* Return STONITH device status	*/
	bladehpi_reset_req,		/* Request a reset */
	bladehpi_hostlist,		/* Return list of supported hosts */
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug)

static const PILPluginImports *	PluginImports;
static PILPlugin *		OurPlugin;
static PILInterface *		OurInterface;
static StonithImports *		OurImports;
static void *			interfprivate;


PIL_rc
PIL_PLUGIN_INIT(PILPlugin *us, const PILPluginImports *imports);

PIL_rc
PIL_PLUGIN_INIT(PILPlugin *us, const PILPluginImports *imports)
{
	/* Force the compiler to do a little type checking */
	(void)(PILPluginInitFun)PIL_PLUGIN_INIT;

	PluginImports = imports;
	OurPlugin = us;

	/* Register ourself as a plugin */
	imports->register_plugin(us, &OurPIExports);  

	/*  Register our interface implementation */
 	return imports->register_interface(us
	,	PIL_PLUGINTYPE_S
	,	PIL_PLUGIN_S
	,	&bladehpiOps
	,	NULL		/* close */
	,	&OurInterface
	,	(void *)&OurImports
	,	&interfprivate); 
}

struct pluginDevice {	
	StonithPlugin		sp;
	const char *		pluginid;
	char *			idinfo;
	char *			device;
	int			softreset;
	GList *		 	hostlist;
	SaHpiVersionT		ohver;		/* OpenHPI interface version */
	SaHpiSessionIdT		ohsession;	/* session ID */
	SaHpiUint32T		ohrptcnt;	/* RPT count for hostlist */
	SaHpiResourceIdT	ohdevid;	/* device resource ID */
	SaHpiResourceIdT	ohsensid;	/* sensor resource ID */
	SaHpiSensorNumT		ohsensnum;	/* sensor number */
};

static int open_hpi_session(struct pluginDevice *dev);
static void close_hpi_session(struct pluginDevice *dev);

static const char *pluginid = "BladeCenterDevice-Stonith";
static const char *NOTpluginID = "IBM BladeCenter device has been destroyed";

#include "stonith_config_xml.h"

#define XML_ENTITYROOT_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	ST_ENTITYROOT \
	XML_PARM_SHORTDESC_END

#define XML_ENTITYROOT_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The entity_root of the STONITH device from the OpenHPI config file" \
	XML_PARM_LONGDESC_END

#define XML_ENTITYROOT_PARM \
	XML_PARAMETER_BEGIN(ST_ENTITYROOT, "string", "1", "0") \
	  XML_ENTITYROOT_SHORTDESC \
	  XML_ENTITYROOT_LONGDESC \
	XML_PARAMETER_END

#define XML_SOFTRESET_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	ST_SOFTRESET \
	XML_PARM_SHORTDESC_END

#define XML_SOFTRESET_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"Soft reset indicator, true|1 if STONITH device should use soft reset (power cycle) to reset nodes, false|0 if device should use hard reset (power off, wait, power on); default is false" \
	XML_PARM_LONGDESC_END

#define XML_SOFTRESET_PARM \
	XML_PARAMETER_BEGIN(ST_SOFTRESET, "string", "0", "0") \
	  XML_SOFTRESET_SHORTDESC \
	  XML_SOFTRESET_LONGDESC \
	XML_PARAMETER_END

static const char *bladehpiXML = 
  XML_PARAMETERS_BEGIN
    XML_ENTITYROOT_PARM
    XML_SOFTRESET_PARM
  XML_PARAMETERS_END;

static int get_resource_type(char *, SaHpiRptEntryT *);
static int get_sensor_num(SaHpiSessionIdT, SaHpiResourceIdT);
static int get_bladehpi_hostlist(struct pluginDevice *);
static void free_bladehpi_hostlist(struct pluginDevice *);
static int get_num_tokens(char *str);

struct blade_info {
	char *			name;		/* blade name */
	SaHpiResourceIdT	resourceId;	/* blade resource ID */
	SaHpiCapabilitiesT	resourceCaps;	/* blade capabilities */
};


static int
bladehpi_status(StonithPlugin *s)
{
	struct pluginDevice *	dev;
	SaErrorT		ohrc;
	SaHpiDomainInfoT 	ohdi;
	int rc = S_OK;
	
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called", __FUNCTION__);
	}

	ERRIFWRONGDEV(s, S_OOPS);

	dev = (struct pluginDevice *)s;
	rc = open_hpi_session(dev);
	if( rc != S_OK )
		return rc;

	/* Refresh the hostlist only if RPTs updated */
	ohrc = saHpiDomainInfoGet(dev->ohsession, &ohdi);
	if (ohrc != SA_OK) {
		LOG(PIL_CRIT, "Unable to get domain info in %s (%d)"
		,	__FUNCTION__, ohrc);
		rc = S_BADCONFIG;
		goto done;
	}
	if (dev->ohrptcnt != ohdi.RptUpdateCount) {
		free_bladehpi_hostlist(dev);
		if (get_bladehpi_hostlist(dev) != S_OK) {
			LOG(PIL_CRIT, "Unable to obtain list of hosts in %s"
			,	__FUNCTION__);
			rc = S_BADCONFIG;
			goto done;
		}
	}

	/* At this point, hostlist is up to date */
	if (dev->ohsensid && dev->ohsensnum) {
		/*
		 * For accurate status, need to make a call that goes out to
		 * BladeCenter MM because the calls made so far by this
		 * function (and perhaps get_bladehpi_hostlist) only retrieve
		 * information from memory cached by OpenHPI
		 */
		ohrc = saHpiSensorReadingGet(dev->ohsession
			, dev->ohsensid, dev->ohsensnum, NULL, NULL);
		if (ohrc == SA_ERR_HPI_BUSY || ohrc == SA_ERR_HPI_NO_RESPONSE) {
			LOG(PIL_CRIT, "Unable to connect to BladeCenter in %s"
			,	__FUNCTION__);
			rc = S_OOPS;
			goto done;
		}
	}

done:
	close_hpi_session(dev);
	return (rc == S_OK) ? (dev->ohdevid ? S_OK : S_OOPS) : rc;
}


/*
 *	Return the list of hosts configured for this HMC device
 */

static char **
bladehpi_hostlist(StonithPlugin *s)
{
	struct pluginDevice *	dev;
	int			numnames = 0, j;
	char **			ret = NULL;
	GList *			node = NULL;
	SaErrorT		ohrc;
	SaHpiDomainInfoT 	ohdi;
	int rc = S_OK;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called", __FUNCTION__);
	}

	ERRIFWRONGDEV(s, NULL);

	dev = (struct pluginDevice *)s;
	rc = open_hpi_session(dev);
	if( rc != S_OK )
		return NULL;

	/* Refresh the hostlist only if RPTs updated */
	ohrc = saHpiDomainInfoGet(dev->ohsession, &ohdi);
	if (ohrc != SA_OK) {
		LOG(PIL_CRIT, "Unable to get domain info in %s (%d)"
		,	__FUNCTION__, ohrc);
		goto done;
	}
	if (dev->ohrptcnt != ohdi.RptUpdateCount) {
		free_bladehpi_hostlist(dev);
		if (get_bladehpi_hostlist(dev) != S_OK) {
			LOG(PIL_CRIT, "Unable to obtain list of hosts in %s"
			,	__FUNCTION__);
			goto done;
		}
	}

	/* At this point, hostlist is up to date */
	numnames = g_list_length(dev->hostlist);
	if (numnames < 0) {
		LOG(PIL_CRIT, "Unconfigured stonith object in %s"
		,	__FUNCTION__);
		goto done;
	}

	ret = (char **)MALLOC((numnames+1) * sizeof(char *));
	if (ret == NULL) {
		LOG(PIL_CRIT, "Out of memory for malloc in %s", __FUNCTION__);
		goto done;
	}

	memset(ret, 0, (numnames+1) * sizeof(char *));
	for (node = g_list_first(dev->hostlist), j = 0
	;	NULL != node
	;	j++, node = g_list_next(node))	{
		ret[j] = STRDUP(((struct blade_info *)node->data)->name);
		if (ret[j] == NULL) {
			LOG(PIL_CRIT, "Out of memory for strdup in %s"
			,	__FUNCTION__);
			stonith_free_hostlist(ret);
			ret = NULL;
			goto done;
		}
		strdown(ret[j]);
	}

done:
	close_hpi_session(dev);
	return ret;
}


static const char * const *
bladehpi_get_confignames(StonithPlugin *s)
{
	static const char *	names[] = {ST_ENTITYROOT, NULL};

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called", __FUNCTION__);
	}

	return names;
}


/*
 *	Reset the given host, and obey the request type.
 */

static int
bladehpi_reset_req(StonithPlugin *s, int request, const char *host)
{
	GList *			node = NULL;
	struct pluginDevice *	dev = NULL;
	struct blade_info *	bi = NULL;
	SaHpiPowerStateT	ohcurstate, ohnewstate;
	SaHpiDomainInfoT 	ohdi;
	SaErrorT		ohrc;
	int rc = S_OK;
	
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called, request=%d, host=%s"
		,	__FUNCTION__, request, host);
	}
	
	ERRIFWRONGDEV(s, S_OOPS);
	
	if (host == NULL) {
		LOG(PIL_CRIT, "Invalid host argument to %s", __FUNCTION__);
		rc = S_OOPS;
		goto done;
	}

	dev = (struct pluginDevice *)s;
	rc = open_hpi_session(dev);
	if( rc != S_OK )
		return rc;

	ohrc = saHpiDomainInfoGet(dev->ohsession, &ohdi);
	if (ohrc != SA_OK) {
		LOG(PIL_CRIT, "Unable to get domain info in %s (%d)"
		,	__FUNCTION__, ohrc);
		rc = S_BADCONFIG;
		goto done;
	}
	if (dev->ohrptcnt != ohdi.RptUpdateCount) {
		free_bladehpi_hostlist(dev);
		if (get_bladehpi_hostlist(dev) != S_OK) {
			LOG(PIL_CRIT, "Unable to obtain list of hosts in %s"
			,	__FUNCTION__);
			rc = S_OOPS;
			goto done;
		}
	}

	for (node = g_list_first(dev->hostlist)
	;	node != NULL
	;	node = g_list_next(node)) {
		bi = ((struct blade_info *)node->data);
		if (Debug) {
			LOG(PIL_DEBUG, "Found host %s in hostlist", bi->name);
		}
		
		if (!strcasecmp(bi->name, host)) {
			break;
		}
	}

	if (!node || !bi) {
		LOG(PIL_CRIT
		,	"Host %s is not configured in this STONITH module, "
			"please check your configuration information", host);
		rc = S_OOPS;
		goto done;
	}

	/* Make sure host has proper capabilities for get */
	if (!(bi->resourceCaps & SAHPI_CAPABILITY_POWER)) {
		LOG(PIL_CRIT
		,	"Host %s does not have power capability", host);
		rc = S_OOPS;
		goto done;
	}

	ohrc = saHpiResourcePowerStateGet(dev->ohsession, bi->resourceId
			, &ohcurstate);
	if (ohrc != SA_OK) {
		LOG(PIL_CRIT, "Unable to get host %s power state (%d)"
		,	host, ohrc);
		rc = S_OOPS;
		goto done;
	}

	switch (request) {
		case ST_POWERON:
			if (ohcurstate == SAHPI_POWER_ON) {
				LOG(PIL_INFO, "Host %s already on", host);
				goto done;
			}
			ohnewstate = SAHPI_POWER_ON;

			break;

		case ST_POWEROFF:
			if (ohcurstate == SAHPI_POWER_OFF) {
				LOG(PIL_INFO, "Host %s already off", host);
				goto done;
			}
			ohnewstate = SAHPI_POWER_OFF;
	
			break;

		case ST_GENERIC_RESET:
			if (ohcurstate == SAHPI_POWER_OFF) {
				ohnewstate = SAHPI_POWER_ON;
			} else {
				ohnewstate = SAHPI_POWER_CYCLE;
			}

			break;

		default:
			LOG(PIL_CRIT, "Invalid request argument to %s"
			,	__FUNCTION__);
			rc = S_INVAL;
			goto done;
	}

	if (!dev->softreset && (ohnewstate == SAHPI_POWER_CYCLE)) {
		int maxwait;

		ohrc = saHpiResourcePowerStateSet(dev->ohsession
				, bi->resourceId, SAHPI_POWER_OFF);
		if (ohrc != SA_OK) {
			LOG(PIL_CRIT, "Unable to set host %s power state to"
				" OFF (%d)", host, ohrc);
			rc = S_OOPS;
			goto done;
		}

		/* 
		 * Must wait for power off here or subsequent power on request
		 * may take place while power is still on and thus ignored
		 */
		maxwait = MAX_POWEROFF_WAIT;
		do {
			maxwait--;
			sleep(1);
			ohrc = saHpiResourcePowerStateGet(dev->ohsession
					, bi->resourceId, &ohcurstate);
		} while ((ohrc == SA_OK)
			&& (ohcurstate != SAHPI_POWER_OFF)
			&& (maxwait > 0));

		if (Debug) {
			LOG(PIL_DEBUG, "Waited %d seconds for power off"
			,	MAX_POWEROFF_WAIT - maxwait);
		}

		ohrc = saHpiResourcePowerStateSet(dev->ohsession
				, bi->resourceId, SAHPI_POWER_ON);
		if (ohrc != SA_OK) {
			LOG(PIL_CRIT, "Unable to set host %s power state to"
			" ON (%d)", host, ohrc);
			rc = S_OOPS;
			goto done;
		}
	} else {
		/* Make sure host has proper capabilities to reset */
		if ((ohnewstate == SAHPI_POWER_CYCLE) &&
		    (!(bi->resourceCaps & SAHPI_CAPABILITY_RESET))) {
			LOG(PIL_CRIT
			,	"Host %s does not have reset capability"
			,	host);
			rc = S_OOPS;
			goto done;
		}

		if ((ohrc = saHpiResourcePowerStateSet(dev->ohsession
				, bi->resourceId, ohnewstate)) != SA_OK) {
			LOG(PIL_CRIT, "Unable to set host %s power state (%d)"
			,	host, ohrc);
			rc = S_OOPS;
			goto done;
		}
	}

#ifdef IBMBC_WAIT_FOR_OFF
	if (ohnewstate == SAHPI_POWER_OFF) {
		int maxwait = MAX_POWEROFF_WAIT;

		do {
			maxwait--;
			sleep(1);
			ohrc = saHpiResourcePowerStateGet(dev->ohsession
					, bi->resourceId, &ohcurstate);
		} while ((ohrc == SA_OK)
			&& (ohcurstate != SAHPI_POWER_OFF)
			&& (maxwait > 0));

		if (Debug) {
			LOG(PIL_DEBUG, "Waited %d seconds for power off"
			,	MAX_POWEROFF_WAIT - maxwait);
		}
	}
#endif

	LOG(PIL_INFO, "Host %s %s %d.", host, __FUNCTION__, request);

done:
	close_hpi_session(dev);
	return rc;
}


/*
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */

static int
bladehpi_set_config(StonithPlugin *s, StonithNVpair *list)
{
	struct pluginDevice *	dev = NULL;
	StonithNamesToGet	namestocopy [] =
	{	{ST_ENTITYROOT,	NULL}
	,	{NULL,		NULL}
	};
	int			rc, i;
	
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called", __FUNCTION__);
	}
	
	ERRIFWRONGDEV(s, S_OOPS);

	dev = (struct pluginDevice *)s;

	if (Debug) {
		LOG(PIL_DEBUG, "%s conditionally compiled with:"
#ifdef IBMBC_WAIT_FOR_OFF
		" IBMBC_WAIT_FOR_OFF"
#endif
		, dev->pluginid);
	}
	
	if ((rc = OurImports->CopyAllValues(namestocopy, list)) != S_OK) {
		return rc;
	}

	if (Debug) {
		LOG(PIL_DEBUG, "%s = %s", ST_ENTITYROOT
		,	namestocopy[0].s_value);	
	}

	if (get_num_tokens(namestocopy[0].s_value) == 1) {
		/* name=value pairs on command line, look for soft_reset */
		const char *softreset = 
			OurImports->GetValue(list, ST_SOFTRESET);
		if (softreset != NULL) {
			if (!strcasecmp(softreset, "true") ||
			    !strcmp(softreset, "1")) {
				dev->softreset = 1;
			} else if (!strcasecmp(softreset, "false") ||
				   !strcmp(softreset, "0")) {
				dev->softreset = 0;
			} else {
				LOG(PIL_CRIT, "Invalid %s %s, must be "
					"true, 1, false or 0"
				,	ST_SOFTRESET, softreset);
				FREE(namestocopy[0].s_value);
				return S_OOPS;
			}
		}
	} else {
		/* -p or -F option with args "entity_root [soft_reset]..." */
		char *pch = namestocopy[0].s_value;

		/* skip over entity_root and null-terminate */
		pch += strcspn(pch, WHITESPACE);
		*pch = EOS;

		/* skip over white-space up to next token */
		pch++;
		pch += strspn(pch, WHITESPACE);
		if (!strcasecmp(pch, "true") || !strcmp(pch, "1")) {
			dev->softreset = 1;
		} else if (!strcasecmp(pch, "false") || !strcmp(pch, "0")) {
			dev->softreset = 0;
		} else {
			LOG(PIL_CRIT, "Invalid %s %s, must be "
				"true, 1, false or 0"
			,	ST_SOFTRESET, pch);
			FREE(namestocopy[0].s_value);
			return S_OOPS;
		}
	}

	dev->device = STRDUP(namestocopy[0].s_value);
	FREE(namestocopy[0].s_value);
	if (dev->device == NULL) {
		LOG(PIL_CRIT, "Out of memory for strdup in %s", __FUNCTION__);
		return S_OOPS;
	}

	if (strcspn(dev->device, WHITESPACE) != strlen(dev->device) ||
	    sscanf(dev->device, SYSTEM_CHASSIS_FMT, &i) != 1 || i < 0) {
		LOG(PIL_CRIT, "Invalid %s %s, must be of format %s"
		,	ST_ENTITYROOT, dev->device, SYSTEM_CHASSIS_FMT);
		return S_BADCONFIG;
	}
	
	dev->ohver = saHpiVersionGet();
	if (dev->ohver > SAHPI_INTERFACE_VERSION) {
		LOG(PIL_CRIT, "Installed OpenHPI interface (%x) greater than "
			"one used by plugin (%x), incompatibilites may exist"
		,	dev->ohver, SAHPI_INTERFACE_VERSION);
		return S_BADCONFIG;
	}
	return S_OK;
}

static int
open_hpi_session(struct pluginDevice *dev)
{
	SaErrorT		ohrc;

	ohrc = saHpiSessionOpen(SAHPI_UNSPECIFIED_DOMAIN_ID
				    , &dev->ohsession, NULL);
	if (ohrc != SA_OK) {
		LOG(PIL_CRIT, "Unable to open HPI session (%d)", ohrc);
		return S_BADCONFIG;
	}

	ohrc = saHpiDiscover(dev->ohsession);
	if (ohrc != SA_OK) {
		LOG(PIL_CRIT, "Unable to discover resources (%d)", ohrc);
		return S_BADCONFIG;
	}

	return S_OK;
}
static void
close_hpi_session(struct pluginDevice *dev)
{
	if (dev && dev->ohsession) {
		saHpiSessionClose(dev->ohsession);
		dev->ohsession = 0;
	}
}

static const char *
bladehpi_getinfo(StonithPlugin *s, int reqtype)
{
	struct pluginDevice *	dev;
	const char *		ret;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called, reqtype=%d"
		,	__FUNCTION__, reqtype);
	}
	
	ERRIFWRONGDEV(s, NULL);

	dev = (struct pluginDevice *)s;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = dev->idinfo;
			break;

		case ST_DEVICENAME:
			ret = dev->device;
			break;

		case ST_DEVICEDESCR:
			ret = "IBM BladeCenter via OpenHPI\n"
			"Use for IBM xSeries systems managed by BladeCenter\n"
			"  Required parameter name " ST_ENTITYROOT " is "
			"a string (no white-space) of\n"
			"the format \""SYSTEM_CHASSIS_FMT"\" "
			"which is entity_root of BladeCenter\n"
			"from OpenHPI config file, where %d is a positive "
			"integer\n"
			"  Optional parameter name " ST_SOFTRESET " is "
			"true|1 if STONITH device should\n"
			"use soft reset (power cycle) to reset nodes or "
			"false|0 if device should\n"
			"use hard reset (power off, wait, power on); "
			"default is false";
			break;

		case ST_DEVICEURL:
			ret = OPENHPIURL;
			break;

		case ST_CONF_XML:		/* XML metadata */
			ret = bladehpiXML;
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
bladehpi_destroy(StonithPlugin *s)
{
	struct pluginDevice *	dev;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called", __FUNCTION__);
	}

	VOIDERRIFWRONGDEV(s);

	dev = (struct pluginDevice *)s;

	dev->pluginid = NOTpluginID;
	if (dev->device) {
		FREE(dev->device);
		dev->device = NULL;
	}
	if (dev->idinfo) {
		FREE(dev->idinfo);
		dev->idinfo = NULL;
	}
	free_bladehpi_hostlist(dev);

	if (dev->ohsession) {
		saHpiSessionClose(dev->ohsession);
		dev->ohsession = 0;
	}
	
	FREE(dev);
}


static StonithPlugin *
bladehpi_new(const char *subplugin)
{
	struct pluginDevice *	dev = ST_MALLOCT(struct pluginDevice);
	
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called", __FUNCTION__);
	}
	
	if (dev == NULL) {
		LOG(PIL_CRIT, "Out of memory in %s", __FUNCTION__);
		return NULL;
	}

	memset(dev, 0, sizeof(*dev));

	dev->pluginid = pluginid;
	dev->device = NULL;
	dev->hostlist = NULL;
	REPLSTR(dev->idinfo, DEVICE);
	if (dev->idinfo == NULL) {
		FREE(dev);
		return NULL;
	}
	dev->sp.s_ops = &bladehpiOps;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: returning successfully", __FUNCTION__);
	}

	return ((void *)dev);
}


static int
get_resource_type(char *entityRoot, SaHpiRptEntryT *ohRPT)
{
	int			i, rc = OHRES_NONE;
	int			foundBlade = 0, foundExp = 0, foundMgmt = 0;
	int			foundRoot = 0, foundOther = 0;
	char			rootName[64];
	SaHpiEntityPathT *	ohep = &ohRPT->ResourceEntity;

	if (ohep == NULL || entityRoot == NULL) {
		return 0;
	}

	/* First find root of entity path, which is last entity in entry */
        for (i = 0; i < SAHPI_MAX_ENTITY_PATH; i++) {
                if (ohep->Entry[i].EntityType == SAHPI_ENT_ROOT) {
                            break;
                }
        }

	/* Then back up through entries looking for specific entity */
        for (i--; i >= 0; i--) {
		switch (ohep->Entry[i].EntityType) {
			case SAHPI_ENT_SBC_BLADE:
				foundBlade = 1;
				break;

			case SAHPI_ENT_SYS_EXPANSION_BOARD:
				foundExp = 1;
				break;

			case SAHPI_ENT_SYS_MGMNT_MODULE:
				if (ohep->Entry[i].EntityLocation == 0) {
					foundMgmt = 1;
				}
				break;

			case SAHPI_ENT_SYSTEM_CHASSIS:
				snprintf(rootName, sizeof(rootName)
				,	SYSTEM_CHASSIS_FMT
				,	ohep->Entry[i].EntityLocation);
				if (!strcmp(entityRoot, rootName)) {
					foundRoot = 1;
				}
				break;

			default:
				foundOther = 1;
				break;
		}
	}

	/* We are only interested in specific entities on specific device */
	if (foundRoot) {
		if (foundMgmt && !(foundBlade||foundExp||foundOther)) {
			rc = OHRES_MGMTMOD;
		} else if (!(foundMgmt||foundBlade||foundExp||foundOther)) {
			rc = OHRES_BLADECENT;
		} else if (foundBlade && !foundExp) {
			rc = OHRES_BLADE;
		}
	}

	return rc;
}


static int
get_sensor_num(SaHpiSessionIdT ohsession, SaHpiResourceIdT ohresid)
{
	SaErrorT	ohrc = SA_OK;
	SaHpiEntryIdT	ohnextid;
	SaHpiRdrT	ohRDR;

	ohnextid = SAHPI_FIRST_ENTRY;
	do {
		ohrc = saHpiRdrGet(ohsession, ohresid, ohnextid
				, &ohnextid, &ohRDR);
		if (ohrc != SA_OK) {
			LOG(PIL_CRIT, "Unable to get RDR entry in %s (%d)"
			,	__FUNCTION__, ohrc);
		} else if (ohRDR.RdrType == SAHPI_SENSOR_RDR) {
			return ohRDR.RdrTypeUnion.SensorRec.Num;
		}
	} while (ohrc == SA_OK && ohnextid != SAHPI_LAST_ENTRY);

	return 0;
}


/*
 *	Get RPT update count
 *	Loop through all RPT entries
 *	  If entry is BladeCenter, save resource ID in dev->ohdevid
 *	  If entry is MgmtMod and has sensor, save resource ID in dev->ohsensid
 *	    and sensor number in dev->ohsensnum
 *	  If entry is blade, save blade_info and add to dev->hostlist
 *	Get RPT update count
 *	If RPT update count changed since start of loop, repeat loop
 *	Save RPT update count in dev->ohrptcnt
 *
 *	Note that not only does this function update hostlist, it also
 *	updates ohrptcnt, ohdevid, ohsensid and ohsensnum.  However, with
 *	this logic it does not need to be called again until the RPT update
 *	count changes.
 */

static int
get_bladehpi_hostlist(struct pluginDevice *dev)
{
	struct blade_info *	bi;
	SaErrorT		ohrc;
	SaHpiEntryIdT		ohnextid;
	SaHpiRptEntryT		ohRPT;
	SaHpiDomainInfoT 	ohdi;
	SaHpiUint32T		ohupdate;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called, dev->device=%s"
		,	__FUNCTION__,	dev->device);
	}

	if (dev->device == NULL || *dev->device == 0) {
		LOG(PIL_CRIT, "Unconfigured stonith object in %s"
		,	__FUNCTION__);
		return S_BADCONFIG;
	}

	ohrc = saHpiDomainInfoGet(dev->ohsession, &ohdi);
	if (ohrc != SA_OK) {
		LOG(PIL_CRIT, "Unable to get domain info in %s (%d)"
		,	__FUNCTION__, ohrc);
		return S_BADCONFIG;
	}
	
try_again:
	ohupdate = ohdi.RptUpdateCount;
	dev->ohdevid = dev->ohsensid = dev->ohsensnum = 0;
	ohnextid = SAHPI_FIRST_ENTRY;
	do {
		char blname[SAHPI_MAX_TEXT_BUFFER_LENGTH];
		int  blnum;

		ohrc = saHpiRptEntryGet(dev->ohsession, ohnextid
				       , &ohnextid, &ohRPT);
		if (ohrc != SA_OK) {
			LOG(PIL_CRIT, "Unable to get RPT entry in %s (%d)"
			,	__FUNCTION__, ohrc);
			free_bladehpi_hostlist(dev);
			return S_BADCONFIG;
		}

		switch (get_resource_type(dev->device, &ohRPT)) {
		case OHRES_BLADECENT:
			dev->ohdevid = ohRPT.ResourceId;

			if (Debug) {
				LOG(PIL_DEBUG, "BladeCenter '%s' has id %d"
				,	(char*)ohRPT.ResourceTag.Data
				,	dev->ohdevid);
			}
			break;

		case OHRES_MGMTMOD:
			if (ohRPT.ResourceCapabilities&SAHPI_CAPABILITY_SENSOR){
 				dev->ohsensnum = get_sensor_num(dev->ohsession
							, ohRPT.ResourceId);

				if (dev->ohsensnum) {
					dev->ohsensid = ohRPT.ResourceId;

					if (Debug) {
						LOG(PIL_DEBUG
						, "MgmtModule '%s' has id %d "
						"with sensor #%d"
						, (char*)ohRPT.ResourceTag.Data
						, dev->ohsensid
						, dev->ohsensnum);
					}
				}
			} 
			break;

		case OHRES_BLADE:
			if ((bi = (struct blade_info *)
				MALLOC(sizeof(struct blade_info))) == NULL) {
			        LOG(PIL_CRIT, "Out of memory in %s"
				,	__FUNCTION__);
				free_bladehpi_hostlist(dev);
			        return S_OOPS;
			}

			/*
			 * New format consists of "Blade N - name" while older
			 * format consists only of "name"; we only need to
			 * stash name because ResourceID is the important info
			 */
			if (sscanf((char*)ohRPT.ResourceTag.Data, "Blade %d - %s"
					, &blnum, blname) == 2) {
				bi->name = STRDUP(blname);
			} else {
				bi->name = STRDUP((char*)ohRPT.ResourceTag.Data);
			}
			if (bi->name == NULL) {
				LOG(PIL_CRIT, "Out of memory for strdup in %s"
				,	__FUNCTION__);
				free_bladehpi_hostlist(dev);
			        return S_OOPS;
			}

			bi->resourceId = ohRPT.ResourceId;
			bi->resourceCaps = ohRPT.ResourceCapabilities;
			dev->hostlist = g_list_append(dev->hostlist, bi);

			if (Debug) {
				LOG(PIL_DEBUG, "Blade '%s' has id %d, caps %x"
				, bi->name, bi->resourceId, bi->resourceCaps);
			}
			break;
		}
	} while (ohrc == SA_OK && ohnextid != SAHPI_LAST_ENTRY);

	ohrc = saHpiDomainInfoGet(dev->ohsession, &ohdi);
	if (ohrc != SA_OK) {
		LOG(PIL_CRIT, "Unable to get domain info in %s (%d)"
		,	__FUNCTION__, ohrc);
		free_bladehpi_hostlist(dev);
		return S_BADCONFIG;
	}

	if (ohupdate != ohdi.RptUpdateCount) {
		free_bladehpi_hostlist(dev);
		if(Debug){
			LOG(PIL_DEBUG, "Looping through entries again,"
				" count changed from %d to %d"
			,	ohupdate, ohdi.RptUpdateCount);
		}
		goto try_again;
	}

	dev->ohrptcnt = ohupdate;

	return S_OK;
}


static void
free_bladehpi_hostlist(struct pluginDevice *dev)
{
	if (dev->hostlist) {
		GList *node;
		while (NULL != (node = g_list_first(dev->hostlist))) {
			dev->hostlist = 
				g_list_remove_link(dev->hostlist, node);
			FREE(((struct blade_info *)node->data)->name);
			FREE(node->data);
			g_list_free(node);
		}
		dev->hostlist = NULL;
	}
	dev->ohdevid = dev->ohsensid = dev->ohsensnum = 0;
}


static int
get_num_tokens(char *str)
{
	int 	namecount = 0;

	while (*str != EOS) {
		str += strspn(str, WHITESPACE);
		if (*str == EOS)
			break;
		str += strcspn(str, WHITESPACE);
		namecount++;
	}
	return namecount;
}
