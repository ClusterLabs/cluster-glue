/* $Id: ipmilan.c,v 1.14 2005/04/06 18:58:42 blaschke Exp $ */
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
 * See RADEME.ipmi for information regarding this plugin.
 *
 */

#define	DEVICE	"ipmilan STONITH device"

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
	int		hostcount;
	struct ipmilanHostInfo * 	hostlist;
};

static const char * pluginid = "pluginDevice-Stonith";
static const char * NOTpluginid = "Hey, dummy this has been destroyed (ipmilanDev)";

#define ST_HOSTNAME	"hostname"
#define ST_PORT		"port"
#define ST_AUTH		"auth"
#define ST_PRIV		"priv"

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
			LOG(PIL_INFO, _("Host %s ipmilan status failure."), node->hostname);
			ret = S_ACCESS;
		} else {
			LOG(PIL_INFO, _("Host %s ipmilan status OK."), node->hostname);
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

	char * buf;

	if (index >= nd->hostcount || index < 0) {
		return (NULL);
	}

	host = nd->hostlist;
	for (i = 0; i < index; i++) {
		host = host->next;
	}

	buf = STRDUP(host->hostname);
	if (!buf) {
		return (NULL);
	}
	g_strdown(buf);

	return buf;
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
	char *shost;
	struct pluginDevice * nd;
	struct ipmilanHostInfo * node;

	ERRIFWRONGDEV(s,S_OOPS);
	
	if ((shost = STRDUP(host)) == NULL) {
		LOG(PIL_CRIT, "strdup failed in %s", __FUNCTION__);
	}
	g_strdown(shost);

	nd = (struct pluginDevice *)s;
	node = nd->hostlist;
	do {
		if (strcmp(node->hostname, host) == 0) {
			break;
		};

		node = node->next;
	} while (node);
	
	free(shost);
	
	if (!node) {
		LOG(PIL_CRIT, _("host %s is not configured in this STONITH module. Please check you configuration file."), host);
		return (S_OOPS);
	}

	rc = do_ipmi_cmd(node, request);
	if (!rc) {
		LOG(PIL_INFO, _("Host %s ipmilan-reset."), host);
	} else {
		LOG(PIL_INFO, _("Host %s ipmilan-reset error. Error = %d."), host, rc);
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

	StonithNamesToGet	namestoget [] =
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

	if ((rc=OurImports->GetAllValues(namestoget, list)) != S_OK) {
		return rc;
	}

	tmp = MALLOCT(struct ipmilanHostInfo);
	tmp->hostname = namestoget[0].s_value;
	tmp->ipaddr   = namestoget[1].s_value;
	tmp->portnumber = atoi(namestoget[2].s_value);
	tmp->authtype = atoi(namestoget[3].s_value);
	tmp->privilege = atoi(namestoget[4].s_value);
	tmp->username = namestoget[5].s_value;
	tmp->password = namestoget[6].s_value;
	
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
	struct pluginDevice* nd;
	char *		ret;

	ERRIFWRONGDEV(s,NULL);
	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	nd = (struct pluginDevice *)s;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = _("ipmilan STONITH device");
			break;

		case ST_DEVICEDESCR:
			ret = _("IPMI_LAN STONITH device\n");
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

			FREE(host->hostname);
			FREE(host->ipaddr);
			FREE(host->username);
			FREE(host->password);

			FREE(host);
			host = host->prev;
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
	nd->sp.s_ops = &ipmilanOps;
	return(&(nd->sp));
}
