/* $Id: ipmilan.c,v 1.17 2006/05/16 09:01:51 sunjd Exp $ */
/*
 * Stonith module for ipmi lan Stonith device
 *
 * Copyright (c) 2003 Intel Corp. 
 *	Yixiong Zou <yixiong.zou@intel.com>
 *
 * Mangled by Sun Jiang Dong <sunjd@cn.ibm.com>, IBM, 2005.
 * And passed the compiling with OpenIPMI-1.4.8.
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
 * See README.ipmi for information regarding this plugin.
 *
 */

#define	DEVICE	"IPMI Over LAN"

#include "stonith_plugin_common.h"

#define PIL_PLUGIN              ipmilan
#define PIL_PLUGIN_S            "ipmilan"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

#include <OpenIPMI/ipmi_types.h>
#include <OpenIPMI/ipmi_auth.h>

#include "ipmilan.h"

static StonithPlugin *	ipmilan_new(const char *);
static void		ipmilan_destroy(StonithPlugin *);
static const char **	ipmilan_get_confignames(StonithPlugin *);
static int		ipmilan_set_config(StonithPlugin *, StonithNVpair *);
static const char *	ipmilan_getinfo(StonithPlugin * s, int InfoType);
static int		ipmilan_status(StonithPlugin * );
static int		ipmilan_reset_req(StonithPlugin * s, int request, const char * host);
static char **		ipmilan_hostlist(StonithPlugin  *);

static struct stonith_ops ipmilanOps ={
	ipmilan_new,		/* Create new STONITH object	*/
	ipmilan_destroy,	/* Destroy STONITH object	*/
	ipmilan_getinfo,	/* Return STONITH info string	*/
	ipmilan_get_confignames,/* Get configuration parameter names */
	ipmilan_set_config,	/* Set configuration */
	ipmilan_status,		/* Return STONITH device status	*/
	ipmilan_reset_req,	/* Request a reset */
	ipmilan_hostlist,	/* Return list of supported hosts */
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug);
const PILPluginImports*  PluginImports;
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
	,	&ipmilanOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*
 *	ipmilan STONITH device.  
 * 
 * 	ipmilanHostInfo is a double linked list. Where the prev of the head always
 *	points to the tail.  This is a little wierd.  But it saves me from looping
 *	around to find the tail when destroying the list.
 */

struct pluginDevice {
	StonithPlugin   sp;
	const char *	pluginid;
	const char *	idinfo;
	int		hostcount;
	struct ipmilanHostInfo * 	hostlist;
};

static const char * pluginid = "IPMI-LANDevice-Stonith";
static const char * NOTpluginid = "IPMI-LAN device has been destroyed";

#define ST_HOSTNAME	"hostname"
#define ST_PORT		"port"
#define ST_AUTH		"auth"
#define ST_PRIV		"priv"

#include "stonith_config_xml.h"

#define XML_HOSTNAME_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	ST_HOSTNAME \
	XML_PARM_SHORTDESC_END

#define XML_HOSTNAME_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The hostname of the STONITH device" \
	XML_PARM_LONGDESC_END

#define XML_HOSTNAME_PARM \
	XML_PARAMETER_BEGIN(ST_HOSTNAME, "string", "1") \
	  XML_HOSTNAME_SHORTDESC \
	  XML_HOSTNAME_LONGDESC \
	XML_PARAMETER_END

#define XML_PORT_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	ST_PORT \
	XML_PARM_SHORTDESC_END

#define XML_PORT_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The port number to where the IPMI message is sent" \
	XML_PARM_LONGDESC_END

#define XML_PORT_PARM \
	XML_PARAMETER_BEGIN(ST_PORT, "string", "1") \
	  XML_PORT_SHORTDESC \
	  XML_PORT_LONGDESC \
	XML_PARAMETER_END

#define XML_AUTH_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	ST_AUTH \
	XML_PARM_SHORTDESC_END

#define XML_AUTH_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The authorization type of the IPMI session (\"none\", \"straight\", \"md2\", or \"md5\")" \
	XML_PARM_LONGDESC_END

#define XML_AUTH_PARM \
	XML_PARAMETER_BEGIN(ST_AUTH, "string", "1") \
	  XML_AUTH_SHORTDESC \
	  XML_AUTH_LONGDESC \
	XML_PARAMETER_END

#define XML_PRIV_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	ST_PRIV \
	XML_PARM_SHORTDESC_END

#define XML_PRIV_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The privilege level of the user (\"operator\" or \"admin\")" \
	XML_PARM_LONGDESC_END

#define XML_PRIV_PARM \
	XML_PARAMETER_BEGIN(ST_PRIV, "string", "1") \
	  XML_PRIV_SHORTDESC \
	  XML_PRIV_LONGDESC \
	XML_PARAMETER_END

static const char *ipmilanXML = 
  XML_PARAMETERS_BEGIN
    XML_HOSTNAME_PARM
    XML_IPADDR_PARM
    XML_PORT_PARM
    XML_AUTH_PARM
    XML_PRIV_PARM
    XML_LOGIN_PARM
    XML_PASSWD_PARM
  XML_PARAMETERS_END;

/*
 * Check the status of the IPMI Lan STONITH device. 
 * 
 * NOTE: not sure what we should do here since each host is configured
 * seperately.
 *     
 * Two options: 
 *   1) always return S_OK. 
 *   2) using IPMI ping to confirm the status for every host that's
 *      configured. 
 * 
 * For now I choose the option 1 hoping that I can get by. Maybe we should
 * change it to option 2 later. 
 */

static int
ipmilan_status(StonithPlugin  *s)
{
	struct pluginDevice * nd;
	struct ipmilanHostInfo * node;
	int ret;

	ERRIFWRONGDEV(s,S_OOPS);

	ret = S_OK;

	nd = (struct pluginDevice *)s;
	node = nd->hostlist;
#if 0
	do {
		ret = send_ipmi_msg(node, ST_IPMI_STATUS);
		if (ret) {
			LOG(PIL_INFO, "Host %s ipmilan status failure."
			,	node->hostname);
			ret = S_ACCESS;
		} else {
			LOG(PIL_INFO, "Host %s ipmilan status OK."
			,	node->hostname);
		}
		node = node->next;

	} while (node);
#endif
	return ret;
}

/*
 * This function returns the list of hosts that's configured. 
 *
 * The detailed configuration is disabled because the STONITH command can be
 * run by anyone so there is a security risk if that to be exposed.
 */

static char *
get_config_string(struct pluginDevice * nd, int index)
{
	struct ipmilanHostInfo * host;
	int i;

	if (index >= nd->hostcount || index < 0) {
		return (NULL);
	}

	host = nd->hostlist;
	for (i = 0; i < index; i++) {
		host = host->next;
	}

	return STRDUP(host->hostname);
}


/*
 *	Return the list of hosts configured for this ipmilan device
 *	
 */

static char **
ipmilan_hostlist(StonithPlugin  *s)
{
	int		numnames = 0;
	char **		ret = NULL;
	struct pluginDevice*	nd;
	int		j;

	ERRIFWRONGDEV(s,NULL);
	
	nd = (struct pluginDevice*) s;
	if (nd->hostcount < 0) {
		LOG(PIL_CRIT
		,	"unconfigured stonith object in ipmi_hostlist");
		return(NULL);
	}
	numnames = nd->hostcount;

	ret = (char **)MALLOC((numnames + 1)*sizeof(char*));
	if (ret == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return (ret);
	}

	memset(ret, 0, (numnames + 1)*sizeof(char*));

	for (j = 0; j < numnames; ++j) {
		ret[j] = get_config_string(nd, j);
		if (!ret[j]) {
			stonith_free_hostlist(ret);
			ret = NULL;
			break;
		}
		g_strdown(ret[j]);
	}

	return(ret);
}

/*
 *	Parse the config information, and stash it away...
 *
 *	The buffer for each string is MAX_IPMI_STRING_LEN bytes long.
 *      Right now it is set to 64. Hope this is enough.
 *	
 */

#define MAX_IPMI_STRING_LEN 64

/*
 *	Reset the given host on this StonithPlugin device.
 */
static int
ipmilan_reset_req(StonithPlugin * s, int request, const char * host)
{
	int rc = 0;
	struct pluginDevice * nd;
	struct ipmilanHostInfo * node;

	ERRIFWRONGDEV(s,S_OOPS);
	
	nd = (struct pluginDevice *)s;
	node = nd->hostlist;
	do {
		if (strcasecmp(node->hostname, host) == 0) {
			break;
		};

		node = node->next;
	} while (node);
	
	if (!node) {
		LOG(PIL_CRIT, "Host %s is not configured in this STONITH "
		" module. Please check your configuration file.", host);
		return (S_OOPS);
	}

	rc = do_ipmi_cmd(node, request);
	if (!rc) {
		LOG(PIL_INFO, "Host %s ipmilan-reset.", host);
	} else {
		LOG(PIL_INFO, "Host %s ipmilan-reset error. Error = %d."
		,	host, rc);
	}
	return rc;
}

/*
 *	Get configuration parameter names
 */
static const char **
ipmilan_get_confignames(StonithPlugin * s)
{
	static const char * ret[] = 
		{ ST_HOSTNAME, ST_IPADDR, ST_PORT, ST_AUTH,
		  ST_PRIV, ST_LOGIN, ST_PASSWD, NULL};
	return ret;
}

/*
 *	Set the configuration parameters
 */
static int
ipmilan_set_config(StonithPlugin* s, StonithNVpair * list)
{
	struct pluginDevice* nd;
	int		rc;
	struct ipmilanHostInfo *  tmp;

	ERRIFWRONGDEV(s,S_OOPS);
	nd = (struct pluginDevice *)s;

	StonithNamesToGet	namestocopy [] =
	{	{ST_HOSTNAME,	NULL}
	,	{ST_IPADDR,	NULL}
	,	{ST_PORT,	NULL}
	,	{ST_AUTH,	NULL}
	,	{ST_PRIV,	NULL}
	,	{ST_LOGIN,	NULL}
	,	{ST_PASSWD,	NULL}
	,	{NULL,		NULL}
	};

	ERRIFWRONGDEV(s, S_OOPS);
	if (nd->sp.isconfigured) {
		return S_OOPS;
	}

	if ((rc=OurImports->CopyAllValues(namestocopy, list)) != S_OK) {
		return rc;
	}

	tmp = MALLOCT(struct ipmilanHostInfo);
	tmp->hostname = namestocopy[0].s_value;
	tmp->ipaddr   = namestocopy[1].s_value;
	tmp->portnumber = atoi(namestocopy[2].s_value);
	FREE(namestocopy[2].s_value);
	tmp->authtype = atoi(namestocopy[3].s_value);
	FREE(namestocopy[3].s_value);
	tmp->privilege = atoi(namestocopy[4].s_value);
	FREE(namestocopy[4].s_value);
	tmp->username = namestocopy[5].s_value;
	tmp->password = namestocopy[6].s_value;
	
	if (nd->hostlist == NULL ) {
		nd->hostlist = tmp;
		nd->hostlist->prev = tmp;
		nd->hostlist->next = tmp;
	} else {
		tmp->prev = nd->hostlist->prev;
		tmp->next = nd->hostlist;
		nd->hostlist->prev->next = tmp;
		nd->hostlist->prev = tmp;
	}
	nd->hostcount++;

	return(S_OK);
}

static const char *
ipmilan_getinfo(StonithPlugin * s, int reqtype)
{
	struct pluginDevice *	nd;
	const char *		ret;

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
			ret = nd->hostlist ? nd->hostlist->hostname : NULL;
			break;

		case ST_DEVICEDESCR:
			ret = "IPMI LAN STONITH device\n";
			break;

		case ST_DEVICEURL:
			ret = "http://www.intel.com/design/servers/ipmi/";
			break;

		case ST_CONF_XML:		/* XML metadata */
			ret = ipmilanXML;
			break;

		default:
			ret = NULL;
			break;
	}
	return ret;
}

/*
 *	ipmilan StonithPlugin destructor...
 *
 * 	The hostlist is a link list.  So have to iterate through.
 */
static void
ipmilan_destroy(StonithPlugin *s)
{
	struct pluginDevice* nd;
	struct ipmilanHostInfo * host;
	int i;

	VOIDERRIFWRONGDEV(s);

	nd = (struct pluginDevice *)s;

	nd->pluginid = NOTpluginid;

	if (nd->hostlist) {
		host = nd->hostlist->prev;
		for (i = 0; i < nd->hostcount; i++) {
			struct ipmilanHostInfo * host_prev = host->prev;

			FREE(host->hostname);
			FREE(host->ipaddr);
			FREE(host->username);
			FREE(host->password);

			FREE(host);
			host = host_prev;
		}
	}

	nd->hostcount = -1;
	FREE(nd);
}

/* Create a new ipmilan StonithPlugin device.  Too bad this function can't be static */
static StonithPlugin *
ipmilan_new(const char *subplugin)
{
	struct pluginDevice*	nd = MALLOCT(struct pluginDevice);

	if (nd == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(nd, 0, sizeof(*nd));
	nd->pluginid = pluginid;
	nd->hostlist = NULL;
	nd->hostcount = 0; 
	nd->idinfo = DEVICE;
	nd->sp.s_ops = &ipmilanOps;
	return(&(nd->sp));
}
