/*
 * Stonith module for BladeCenter via OpenHPI, an implementation of Service 
 * Availability Forum's Hardware Platfrom Interface *
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

#define DEVICE		"IBM BladeCenter"

#include "stonith_plugin_common.h"

#define PIL_PLUGIN		ibmbc
#define PIL_PLUGIN_S            "ibmbc"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

#include <SaHpi.h>

#define MAX_HOST_NAME_LEN	(256*4)
#define MAX_CMD_LEN		2048
#define MAX_POWERON_RETRY	10
#define MAX_POWEROFF_WAIT	60

#define SYSTEM_CHASSIS_FMT	"{SYSTEM_CHASSIS,%d}"
#define OPENHPIURL		"http://openhpi.sourceforge.net/"

/* IBMBC_WAIT_FOR_OFF - This constant has to do with the problem that
   saHpiResourcePowerStateSet can return before the desired state has been
   achieved by the blade.  In the SAHPI_POWER_OFF case this is not good,
   as whoever calls this plugin assumes that the power is actually off
   when the plugin returns with a successful return code.  Define this
   constant to build code that loops in one second intervals after calling
   saHpiResourcePowerStateSet(SAHPI_POWER_OFF) to make sure the power is
   really off. */
#define IBMBC_WAIT_FOR_OFF

/* IBMBC_DO_OWN_RESET - This constant has to do with the problem that
   saHpiResourcePowerStateSet(SAHPI_POWER_CYCLE) does not turn the power
   off, then on as described in the spec but rather triggers a cold reset.
   Define this constant to build code that replaces the SAHPI_POWER_CYCLE
   invocation with SAHPI_POWER_OFF, followed by a loop to make sure it is
   really off, followed by SAHPI_POWER_ON. */
#define IBMBC_DO_OWN_RESET

/* IBMBC_OPENHPI_PSS_BUG - This constant has to do with the problem that
   calling saHpiResourcePowerStateSet causes communications with the blade
   to cease in such a manner that all subsequent HPI calls return with
   error -1012 (SA_ERR_HPI_NO_RESPONSE).  Define this constant to clear
   the event log via saHpiEventLogClear before and after setting the power
   state. NOTE: This bug is present in OpenHPI versions between Sep 05 and
   Dec 05. */
#define IBMBC_OPENHPI_PSS_BUG

static StonithPlugin *	ibmbc_new(const char *);
static void		ibmbc_destroy(StonithPlugin *);
static const char *	ibmbc_getinfo(StonithPlugin * s, int InfoType);
static const char**	ibmbc_get_confignames(StonithPlugin* p);
static int		ibmbc_status(StonithPlugin * );
static int		ibmbc_reset_req(StonithPlugin * s,int request,const char* host);
static char **		ibmbc_hostlist(StonithPlugin  *);
static int		ibmbc_set_config(StonithPlugin *, StonithNVpair*);

static struct stonith_ops ibmbcOps = {
	ibmbc_new,		/* Create new STONITH object	*/
	ibmbc_destroy,		/* Destroy STONITH object	*/
	ibmbc_getinfo,		/* Return STONITH info string	*/
	ibmbc_get_confignames,	/* Return configuration parameters */
	ibmbc_set_config,	/* Set configuration            */
	ibmbc_status,		/* Return STONITH device status	*/
	ibmbc_reset_req,	/* Request a reset */
	ibmbc_hostlist,	/* Return list of supported hosts */
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
	,	&ibmbcOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

#define ST_ENTITYROOT "entity_root"

struct pluginDevice {	
	StonithPlugin		sp;
	const char *		pluginid;
	char *			idinfo;
	char *			device;
	GList*		 	hostlist;
	SaHpiVersionT		ohver;
	SaHpiSessionIdT		ohsession;
#ifdef IBMBC_OPENHPI_PSS_BUG
	SaHpiResourceIdT	eventlogId1;
	SaHpiResourceIdT	eventlogId2;
#endif
};

static const char * pluginid = "BladeCenterDevice-Stonith";
static const char * NOTpluginID = "IBM BladeCenter device has been destroyed";

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
	XML_PARAMETER_BEGIN(ST_ENTITYROOT, "string") \
	  XML_ENTITYROOT_SHORTDESC \
	  XML_ENTITYROOT_LONGDESC \
	XML_PARAMETER_END

static const char *ibmbcXML = 
  XML_PARAMETERS_BEGIN
    XML_ENTITYROOT_PARM
  XML_PARAMETERS_END;

static int is_resource_bladecenter(char *entityRoot, SaHpiRptEntryT *ohRPT);
static int is_resource_blade(char *entityRoot, SaHpiRptEntryT *ohRPT);
static int get_ibmbc_hostlist(struct pluginDevice* dev);
static void free_ibmbc_hostlist(struct pluginDevice* dev);

struct blade_info {
	char*			name;
	SaHpiResourceIdT	resourceId;
	SaHpiCapabilitiesT	resourceCaps;
};

static int
ibmbc_status(StonithPlugin  *s)
{
	struct pluginDevice*	dev = NULL;
	SaErrorT		ohrc;
	SaHpiEntryIdT		ohnextid;
	SaHpiRptEntryT		ohRPT;
	int			status = S_BADCONFIG;
	SaHpiDomainInfoT 	ohdi;
	SaHpiUint32T		ohupdate;
	
	if(Debug){
		LOG(PIL_DEBUG, "%s: called", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,S_OOPS);

	dev = (struct pluginDevice*) s;
	
	if ((ohrc = saHpiDomainInfoGet(dev->ohsession, &ohdi)) != SA_OK) {
		LOG(PIL_CRIT, "Unable to get domain info (%d)", ohrc);
		return S_BADCONFIG;
	}
	ohupdate = ohdi.RptUpdateCount;

try_again:
	ohnextid = SAHPI_FIRST_ENTRY;
	do {
		ohrc = saHpiRptEntryGet(dev->ohsession, ohnextid
				       , &ohnextid, &ohRPT);
		if (ohrc == SA_OK && 
		    is_resource_bladecenter(dev->device, &ohRPT)) {
			status = S_OK;
			break;
		}
	} while (ohrc == SA_OK && ohnextid != SAHPI_LAST_ENTRY);

	if ((ohrc = saHpiDomainInfoGet(dev->ohsession, &ohdi)) != SA_OK) {
		LOG(PIL_CRIT, "Unable to get domain info (%d)", ohrc);
		return S_BADCONFIG;
	}
	if (ohupdate != ohdi.RptUpdateCount) {
		status = S_BADCONFIG;
		if(Debug){
			LOG(PIL_DEBUG, "Looping through entries again");
		}
		goto try_again;
	}
	return status;
}


/*
 *	Return the list of hosts configured for this HMC device
 */

static char **
ibmbc_hostlist(StonithPlugin  *s)
{
	struct pluginDevice*	dev;
	int			numnames = 0, j;
	char**			ret = NULL;
	GList*			node = NULL;

	if(Debug){
		LOG(PIL_DEBUG, "%s: called", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,NULL);

	dev = (struct pluginDevice*) s;

	/* refresh the hostlist */
	free_ibmbc_hostlist(dev);
	if (S_OK != get_ibmbc_hostlist(dev)){
		LOG(PIL_CRIT, "unable to obtain list of blade servers in %s"
		,	__FUNCTION__);
		return NULL;
	}

	numnames = g_list_length(dev->hostlist);
	if (numnames < 0) {
		LOG(PIL_CRIT, "unconfigured stonith object in %s"
		,	__FUNCTION__);
		return(NULL);
	}

	ret = (char **)MALLOC((numnames+1)*sizeof(char*));
	if (ret == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return ret;
	}

	memset(ret, 0, (numnames+1)*sizeof(char*));
	for (node = g_list_first(dev->hostlist), j = 0
	;	NULL != node
	;	j++, node = g_list_next(node))	{
		ret[j] = STRDUP(((struct blade_info *)node->data)->name);
		if (ret[j] == NULL) {
			LOG(PIL_CRIT, "out of memory");
			stonith_free_hostlist(ret);
			return NULL;
		}
		g_strdown(ret[j]);
	}
	return ret;
}


static const char**     
ibmbc_get_confignames(StonithPlugin* p)
{
	static const char* names[] = {ST_ENTITYROOT, NULL};
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}
	return names;
}


#ifdef IBMBC_OPENHPI_PSS_BUG
static int
ibmbc_clear_bladecenter_eventlog(struct pluginDevice* dev)
{
	SaErrorT	ohrc;

	/* There is at least one, maximum two management modules */
	if ((ohrc = saHpiEventLogClear(dev->ohsession
			, dev->eventlogId1)) != SA_OK) {
		LOG(PIL_CRIT, "Unable to clear event log (%d)", ohrc);
		return (S_OOPS);
	}
	if (dev->eventlogId2 && (ohrc = saHpiEventLogClear(dev->ohsession
			, dev->eventlogId2)) != SA_OK) {
		LOG(PIL_CRIT, "Unable to clear event log (%d)", ohrc);
		return (S_OOPS);
	}
	return S_OK;
}
#endif


/*
 *	Reset the given host, and obey the request type.
 *	We should reset without power cycle for the non-partitioned case
 */

static int
ibmbc_reset_req(StonithPlugin * s, int request, const char * host)
{
	GList*			node = NULL;
	struct pluginDevice*	dev = NULL;
	SaHpiPowerStateT	ohcurstate, ohnewstate;
	SaErrorT		ohrc;
	struct blade_info*	bi = NULL;
	
	if(Debug){
		LOG(PIL_DEBUG, "%s: called, host=%s", __FUNCTION__, host);
	}
	
	ERRIFWRONGDEV(s,S_OOPS);
	
	if (NULL == host) {
		LOG(PIL_CRIT, "invalid argument to %s", __FUNCTION__);
		return(S_OOPS);
	}

	dev = (struct pluginDevice*) s;

	for (node = g_list_first(dev->hostlist)
	;	NULL != node
	;	node = g_list_next(node)) {
		bi = ((struct blade_info *)node->data);
		if(Debug){
			LOG(PIL_DEBUG, "%s: node->data->name=%s"
			,	__FUNCTION__, bi->name);
		}
		
		if (!strcasecmp(bi->name, host)) {
			break;
		}
	}

	if (!node || !bi) {
		LOG(PIL_CRIT
		,	"Host %s is not configured in this STONITH module. "
			"Please check your configuration information.", host);
		return (S_OOPS);
	}

	/* Make sure host has proper capabilities */
	if (((request == ST_POWERON || request == ST_POWEROFF) && 
	     (!(bi->resourceCaps & SAHPI_CAPABILITY_POWER))) ||
	    ((request == ST_GENERIC_RESET) && 
	     (!(bi->resourceCaps & SAHPI_CAPABILITY_RESET)))) {
		LOG(PIL_CRIT
		,	"Resource %s does not have capability to %s"
		,	host, request == ST_GENERIC_RESET ? "reset" : "power");
		return (S_OOPS);
	}

	if ((ohrc = saHpiResourcePowerStateGet(dev->ohsession
			, bi->resourceId, &ohcurstate)) != SA_OK) {
		LOG(PIL_CRIT, "Unable to obtain resource %s power state (%d)"
		,	host, ohrc);
		return (S_OOPS);
	}

	switch (request) {
		case ST_POWERON:
			if (ohcurstate == SAHPI_POWER_ON) {
				LOG(PIL_INFO, "Host %s already on", host);
				return S_OK;
			}
			ohnewstate = SAHPI_POWER_ON;

			break;
		case ST_POWEROFF:
			if (ohcurstate == SAHPI_POWER_OFF) {
				LOG(PIL_INFO, "Host %s already off", host);
				return S_OK;
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
			return S_INVAL;
	}

#ifdef IBMBC_OPENHPI_PSS_BUG
	if (ibmbc_clear_bladecenter_eventlog(dev) != SA_OK) {
		return (S_OOPS);
	}
#endif

#ifdef IBMBC_DO_OWN_RESET
	if (ohnewstate == SAHPI_POWER_CYCLE) {
		int	maxwait = MAX_POWEROFF_WAIT;

		if ((ohrc = saHpiResourcePowerStateSet(dev->ohsession
				, bi->resourceId, SAHPI_POWER_OFF)) != SA_OK) {
			LOG(PIL_CRIT, "Unable to change resource %s power"
			" state (%d)", host, ohrc);
			return (S_OOPS);
		}

#ifdef IBMBC_OPENHPI_PSS_BUG
		if (ibmbc_clear_bladecenter_eventlog(dev) != SA_OK) {
			return (S_OOPS);
		}
#endif

		do {
			maxwait--;
			sleep(1);
			ohrc = saHpiResourcePowerStateGet(dev->ohsession
					, bi->resourceId, &ohcurstate);
		} while ((ohrc == SA_OK)
			&& (ohcurstate != SAHPI_POWER_OFF)
			&& (maxwait > 0));

		if(Debug){
			LOG(PIL_DEBUG, "Waited %d seconds for power off"
			,	MAX_POWEROFF_WAIT - maxwait);
		}

		if ((ohrc = saHpiResourcePowerStateSet(dev->ohsession
				, bi->resourceId, SAHPI_POWER_ON)) != SA_OK) {
			LOG(PIL_CRIT, "Unable to change resource %s power"
			" state (%d)", host, ohrc);
			return (S_OOPS);
		}

#ifdef IBMBC_OPENHPI_PSS_BUG
		if (ibmbc_clear_bladecenter_eventlog(dev) != SA_OK) {
			return (S_OOPS);
		}
#endif

		/* Don't want to wait for POWEROFF */
		ohnewstate = SAHPI_POWER_ON;
	}
	else
#endif
	if ((ohrc = saHpiResourcePowerStateSet(dev->ohsession
			, bi->resourceId, ohnewstate)) != SA_OK) {
		LOG(PIL_CRIT, "Unable to change resource %s power state (%d)"
		,	host, ohrc);
		return (S_OOPS);
	}

#ifdef IBMBC_OPENHPI_PSS_BUG
	if (ibmbc_clear_bladecenter_eventlog(dev) != SA_OK) {
		return (S_OOPS);
	}
#endif

#ifdef IBMBC_WAIT_FOR_OFF
	if (ohnewstate != SAHPI_POWER_ON) {
		int	maxwait = MAX_POWEROFF_WAIT;
		do {
			maxwait--;
			sleep(1);
			ohrc = saHpiResourcePowerStateGet(dev->ohsession
					, bi->resourceId, &ohcurstate);
		} while ((ohrc == SA_OK)
			&& (ohcurstate != SAHPI_POWER_OFF)
			&& (maxwait > 0));

		if(Debug){
			LOG(PIL_DEBUG, "Waited %d seconds for power off"
			,	MAX_POWEROFF_WAIT - maxwait);
		}
	}
#endif

	LOG(PIL_INFO, "Host %s %s %d.", host, __FUNCTION__, request);

	return S_OK;
}


/*
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */

static int
ibmbc_set_config(StonithPlugin * s, StonithNVpair* list)
{
	struct pluginDevice*	dev = NULL;
	StonithNamesToGet	namestocopy [] =
	{	{ST_ENTITYROOT,	NULL}
	,	{NULL,		NULL}
	};
	int			rc, i;
	SaErrorT		ohrc;
	
	ERRIFWRONGDEV(s,S_OOPS);

	if(Debug){
		LOG(PIL_DEBUG, "%s: called", __FUNCTION__);
	}
	
	dev = (struct pluginDevice*) s;

	if(Debug){
		LOG(PIL_DEBUG, "%s conditionally compiled with:"
#ifdef IBMBC_WAIT_FOR_OFF
		" IBMBC_WAIT_FOR_OFF"
#endif
#ifdef IBMBC_DO_OWN_RESET
		" IBMBC_DO_OWN_RESET"
#endif
#ifdef IBMBC_OPENHPI_PSS_BUG
		" IBMBC_OPENHPI_PSS_BUG"
#endif
		, dev->pluginid);
	}
	
	if ((rc = OurImports->CopyAllValues(namestocopy, list)) != S_OK) {
		return rc;
	}
	if(Debug){
		LOG(PIL_DEBUG, "%s: entity_root=%s", __FUNCTION__
		,	namestocopy[0].s_value);	
	}

	dev->device = STRDUP(namestocopy[0].s_value);
	FREE(namestocopy[0].s_value);

	if (strcspn(dev->device, WHITESPACE) != strlen(dev->device) ||
	    sscanf(dev->device, SYSTEM_CHASSIS_FMT, &i) != 1 || i < 0) {
		LOG(PIL_CRIT, "Invalid entity_root %s, must be of format %s "
		, dev->device, SYSTEM_CHASSIS_FMT);
		return S_BADCONFIG;
	}
	
	if ((dev->ohver = saHpiVersionGet()) > SAHPI_INTERFACE_VERSION) {
		LOG(PIL_CRIT, "Installed OpenHPI version (%x) greater than "
		" version built for plugin (%x), incompatibilites may exist"
		, dev->ohver, SAHPI_INTERFACE_VERSION);
		return S_BADCONFIG;
	}

	if ((ohrc = saHpiSessionOpen(SAHPI_UNSPECIFIED_DOMAIN_ID
				    , &dev->ohsession, NULL)) != SA_OK) {
		LOG(PIL_CRIT, "Unable to open HPI session (%d)", ohrc);
		return S_BADCONFIG;
	}

	if ((ohrc = saHpiDiscover(dev->ohsession)) != SA_OK) {
		LOG(PIL_CRIT, "Unable to discover resources (%d)", ohrc);
		return S_BADCONFIG;
	}

	if (S_OK != get_ibmbc_hostlist(dev)){
		LOG(PIL_CRIT, "unable to obtain list of blade servers in %s"
		,	__FUNCTION__);
		return S_BADCONFIG;
	}
	
	return S_OK;
}


static const char*
ibmbc_getinfo(StonithPlugin* s, int reqtype)
{
	struct pluginDevice*	dev;
	const char*		ret;

	ERRIFWRONGDEV(s,NULL);

	dev = (struct pluginDevice *)s;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = dev->idinfo;
			break;

		case ST_DEVICENAME:
			ret = dev->device;
			break;

		case ST_DEVICEDESCR:
			ret = DEVICE;
			ret = "IBM BladeCenter via OpenHPI\n"
			"Use for IBM xSeries systems managed by BladeCenter\n"
			"Required parameter name " ST_ENTITYROOT " is "
			"a string (no white-space) of the format " 
			"\""SYSTEM_CHASSIS_FMT"\" "
			"which is entity_root of BladeCenter from OpenHPI "
			"config file, where %d is a positive integer\n";
			break;

		case ST_DEVICEURL:
			ret = OPENHPIURL;
			break;

		case ST_CONF_XML:		/* XML metadata */
			ret = ibmbcXML;
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
ibmbc_destroy(StonithPlugin *s)
{
	struct pluginDevice*	dev;

	if(Debug){
		LOG(PIL_DEBUG, "%s : called", __FUNCTION__);
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
	free_ibmbc_hostlist(dev);

	if (dev->ohsession) {
		saHpiSessionClose(dev->ohsession);
		dev->ohsession = 0;
	}
	
	FREE(dev);
}


static StonithPlugin *
ibmbc_new(const char *subplugin)
{
	struct pluginDevice*	dev = MALLOCT(struct pluginDevice);
	
	if(Debug){
		LOG(PIL_DEBUG, "%s: called", __FUNCTION__);
	}
	
	if (dev == NULL) {
		LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
		return(NULL);
	}

	memset(dev, 0, sizeof(*dev));

	dev->pluginid = pluginid;
	dev->device = NULL;
	dev->hostlist = NULL;
	REPLSTR(dev->idinfo, DEVICE);
	if (dev->idinfo == NULL) {
		FREE(dev);
		return(NULL);
	}
	dev->sp.s_ops = &ibmbcOps;

	if(Debug){
		LOG(PIL_DEBUG, "%s: returning successfully", __FUNCTION__);
	}

	return((void *)dev);
}

static int
is_resource_bladecenter(char *entityRoot, SaHpiRptEntryT *ohRPT)
{

	int 			i, foundRoot = 0, foundOther = 0;
	SaHpiEntityPathT*	ohep = &ohRPT->ResourceEntity;
	char 			rootName[64];

	if (ohep == NULL || entityRoot == NULL) {
		return 0;
	}

        for (i = 0; i < SAHPI_MAX_ENTITY_PATH; i++) {
                if (ohep->Entry[i].EntityType == SAHPI_ENT_ROOT) {
                            break;
                }
        }

        for (i--; i >= 0; i--) {
		switch (ohep->Entry[i].EntityType) {
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

	/* We are only interested in bladecenter chasses on specific device */
	return foundRoot && !foundOther;
}

#ifdef IBMBC_OPENHPI_PSS_BUG
static int
is_resource_bladecenter_eventlog(char *entityRoot, SaHpiRptEntryT *ohRPT)
{

	int 			i, foundRoot = 0;
	SaHpiEntityPathT*	ohep = &ohRPT->ResourceEntity;
	char 			rootName[64];

	if (ohep == NULL || entityRoot == NULL) {
		return 0;
	}

        for (i = 0; i < SAHPI_MAX_ENTITY_PATH; i++) {
                if (ohep->Entry[i].EntityType == SAHPI_ENT_ROOT) {
                            break;
                }
        }

        for (i--; i >= 0; i--) {
		switch (ohep->Entry[i].EntityType) {
			case SAHPI_ENT_SYSTEM_CHASSIS:
				snprintf(rootName, sizeof(rootName)
				,	SYSTEM_CHASSIS_FMT
				,	ohep->Entry[i].EntityLocation);
				if (!strcmp(entityRoot, rootName)) {
					foundRoot = 1;
				}
				break;

			default:
				break;
		}
	}

	/* We are only interested in event log on specific device */
	return foundRoot
	&& (ohRPT->ResourceCapabilities & SAHPI_CAPABILITY_EVENT_LOG);
}
#endif

static int
is_resource_blade(char *entityRoot, SaHpiRptEntryT *ohRPT)
{

	int			i, foundBlade = 0, foundRoot = 0, foundExp = 0;
	SaHpiEntityPathT *	ohep = &ohRPT->ResourceEntity;
	char			rootName[64];

	if (ohep == NULL || entityRoot == NULL) {
		return 0;
	}

        for (i = 0; i < SAHPI_MAX_ENTITY_PATH; i++) {
                if (ohep->Entry[i].EntityType == SAHPI_ENT_ROOT) {
                            break;
                }
        }

        for (i--; i >= 0; i--) {
		switch (ohep->Entry[i].EntityType) {
			case SAHPI_ENT_SBC_BLADE:
				foundBlade = 1;
				break;

			case SAHPI_ENT_SYSTEM_CHASSIS:
				snprintf(rootName, sizeof(rootName)
				,	SYSTEM_CHASSIS_FMT
				,	ohep->Entry[i].EntityLocation);
				if (!strcmp(entityRoot, rootName)) {
					foundRoot = 1;
				}
				break;

			case SAHPI_ENT_SYS_EXPANSION_BOARD:
				foundExp = 1;
				break;

			default:
				break;
		}
	}

	/* We are only interested in blades on the specific device that are
	 * not expansion boards */
	return foundBlade && foundRoot && !foundExp;

}

static int
get_ibmbc_hostlist(struct pluginDevice* dev)
{
	SaErrorT		ohrc;
	SaHpiEntryIdT		ohnextid;
	SaHpiRptEntryT		ohRPT;
	SaHpiDomainInfoT 	ohdi;
	SaHpiUint32T		ohupdate;

	if(Debug){
		LOG(PIL_DEBUG, "%s: called, dev->device=%s", __FUNCTION__
		,	dev->device);
	}

	if (dev->device == NULL || *dev->device == 0) {
		return S_BADCONFIG;
	}

	if ((ohrc = saHpiDomainInfoGet(dev->ohsession, &ohdi)) != SA_OK) {
		LOG(PIL_CRIT, "Unable to get domain info (%d)", ohrc);
		return S_BADCONFIG;
	}
	ohupdate = ohdi.RptUpdateCount;
	
try_again:
	ohnextid = SAHPI_FIRST_ENTRY;
	do {
		ohrc = saHpiRptEntryGet(dev->ohsession, ohnextid
				       , &ohnextid, &ohRPT);
		if (ohrc == SA_OK && is_resource_blade(dev->device, &ohRPT)) {
			struct blade_info *bi;

			if ((bi = (struct blade_info *)
				MALLOC(sizeof(struct blade_info))) == NULL) {
			        LOG(PIL_CRIT, "%s: out of memory."
				,	__FUNCTION__);
				free_ibmbc_hostlist(dev);
			        return (S_OOPS);
			}
			bi->name = STRDUP(ohRPT.ResourceTag.Data);
			bi->resourceId = ohRPT.ResourceId;
			bi->resourceCaps = ohRPT.ResourceCapabilities;
			dev->hostlist = g_list_append(dev->hostlist, bi);

			if(Debug){
				LOG(PIL_DEBUG, "Blade %s has id %d, caps %x"
				, bi->name, bi->resourceId, bi->resourceCaps);
			}
		}
#ifdef IBMBC_OPENHPI_PSS_BUG
		else if (ohrc == SA_OK
		&& is_resource_bladecenter_eventlog(dev->device, &ohRPT)) {
			if (dev->eventlogId1 == 0) {
				dev->eventlogId1 = ohRPT.ResourceId;
			} else {
				dev->eventlogId2 = ohRPT.ResourceId;
			}
		}
#endif
	} while (ohrc == SA_OK && ohnextid != SAHPI_LAST_ENTRY);

	if (ohupdate != ohdi.RptUpdateCount) {
		free_ibmbc_hostlist(dev);
		if(Debug){
			LOG(PIL_DEBUG, "Looping through entries again");
		}
		goto try_again;
	}
	return S_OK;
}

static void
free_ibmbc_hostlist(struct pluginDevice* dev)
{
	if (dev->hostlist) {
		GList* node;
		while (NULL != (node = g_list_first(dev->hostlist))) {
			dev->hostlist = g_list_remove_link(dev->hostlist, node);
			FREE(((struct blade_info *)node->data)->name);
			FREE(node->data);
			g_list_free(node);
		}
		dev->hostlist = NULL;
	}
}
