/*
 * Stonith module for ipmi lan Stonith device
 *
 * Copyright (c) 2003 Intel Corp. 
 *	Yixiong Zou <yixiong.zou@intel.com>
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

#include <portability.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <libintl.h>
#include <sys/wait.h>

#include <stonith/stonith.h>

#define PIL_PLUGINTYPE          STONITH_TYPE
#define PIL_PLUGINTYPE_S        STONITH_TYPE_S
#define PIL_PLUGIN              ipmilan
#define PIL_PLUGIN_S            "ipmilan"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

#include <OpenIPMI/ipmi_types.h>
#include <OpenIPMI/ipmi_auth.h>

#include "ipmilan.h"

/*
 * ipmilanclose is called as part of unloading the ipmilan STONITH plugin.
 * If there was any global data allocated, or file descriptors opened, etc.
 * which is associated with the plugin, and not a single interface
 * in particular, here's our chance to clean it up.
 */

static void
ipmilanclosepi(PILPlugin*pi)
{
}


/*
 * ipmilancloseintf called as part of shutting down the ipmilan STONITH
 * interface.  If there was any global data allocated, or file descriptors
 * opened, etc.  which is associated with the ipmilan implementation,
 * here's our chance to clean it up.
 */
static PIL_rc
ipmilancloseintf(PILInterface* pi, void* pd)
{
	return PIL_OK;
}

static void *		ipmilan_new(void);
static void		ipmilan_destroy(Stonith *);
static int		ipmilan_set_config_file(Stonith *, const char * cfgname);
static int		ipmilan_set_config_info(Stonith *, const char * info);
static const char *	ipmilan_getinfo(Stonith * s, int InfoType);
static int		ipmilan_status(Stonith * );
static int		ipmilan_reset_req(Stonith * s, int request, const char * host);
static char **		ipmilan_hostlist(Stonith  *);
static void		ipmilan_free_hostlist(char **);

static struct stonith_ops ipmilanOps ={
	ipmilan_new,		/* Create new STONITH object	*/
	ipmilan_destroy,		/* Destroy STONITH object	*/
	ipmilan_set_config_file,	/* set configuration from file	*/
	ipmilan_set_config_info,	/* Get configuration from file	*/
	ipmilan_getinfo,		/* Return STONITH info string	*/
	ipmilan_status,		/* Return STONITH device status	*/
	ipmilan_reset_req,		/* Request a reset */
	ipmilan_hostlist,		/* Return list of supported hosts */
	ipmilan_free_hostlist	/* free above list */
};

PIL_PLUGIN_BOILERPLATE("1.0", Debug, ipmilanclosepi);
static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static StonithImports*		OurImports;
static void*			interfprivate;

#define LOG		PluginImports->log
#define MALLOC		PluginImports->alloc
#define STRDUP  	PluginImports->mstrdup
#define FREE		PluginImports->mfree
#define EXPECT_TOK	OurImports->ExpectToken
#define STARTPROC	OurImports->StartProcess

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
	,	ipmilancloseintf		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

#define	DEVICE	"ipmilan STONITH device"
#define WHITESPACE	" \t\n\r\f"

/*
 *	ipmilan STONITH device.  
 * 
 * 	ipmilanHostInfo is a double linked list. Where the prev of the head always
 *	points to the tail.  This is a little wierd.  But it saves me from looping
 *	around to find the tail when destroying the list.
 */

struct ipmilanDevice {
	const char *	ipmiid;
	int		hostcount;
	struct ipmilanHostInfo * 	hostlist;
};

static const char * ipmilanid = "ipmilanDevice-Stonith";
static const char * NOTipmilanID = "Hey, dummy this has been destroyed (ipmilanDev)";

#define	ISipmilanDEV(i)	(((i)!= NULL && (i)->pinfo != NULL)	\
	&& ((struct ipmilanDevice *)(i->pinfo))->ipmiid == ipmilanid)


#ifndef MALLOC
#	define	MALLOC	malloc
#endif
#ifndef FREE
#	define	FREE	free
#endif
#ifndef MALLOCT
#	define     MALLOCT(t)      ((t *)(MALLOC(sizeof(t)))) 
#endif

#define N_(text)	(text)
#define _(text)		dgettext(ST_TEXTDOMAIN, text)

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
ipmilan_status(Stonith  *s)
{
	struct ipmilanDevice * nd;
	struct ipmilanHostInfo * node;
	int ret;

	if (!ISipmilanDEV(s)) {
		syslog(LOG_ERR, "invalid argument to ipmilan_status");
		return(S_OOPS);
	}
	ret = S_OK;

	nd = (struct ipmilanDevice *)s->pinfo;
	node = nd->hostlist;
#if 0
	do {
		ret = send_ipmi_msg(node, ST_IPMI_STATUS);
		if (ret) {
			syslog(LOG_INFO, _("Host %s ipmilan status failure."), node->hostname);
			ret = S_ACCESS;
		} else {
			syslog(LOG_INFO, _("Host %s ipmilan status OK."), node->hostname);
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
get_config_string(struct ipmilanDevice * nd, int index)
{
	struct ipmilanHostInfo * host;
	int i;

	char * buf, *p;

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

	return buf;
}


/*
 *	Return the list of hosts configured for this ipmilan device
 *	
 */

static char **
ipmilan_hostlist(Stonith  *s)
{
	int		numnames = 0;
	char **		ret = NULL;
	struct ipmilanDevice*	nd;
	int		j;

	if (!ISipmilanDEV(s)) {
		syslog(LOG_ERR, "invalid argument to ipmilan_hostlist");
		return(NULL);
	}
	nd = (struct ipmilanDevice*) s->pinfo;
	if (nd->hostcount < 0) {
		syslog(LOG_ERR
		,	"unconfigured stonith object in ipmi_hostlist");
		return(NULL);
	}
	numnames = nd->hostcount;

	ret = (char **)MALLOC((numnames + 1)*sizeof(char*));
	if (ret == NULL) {
		syslog(LOG_ERR, "out of memory");
		return (ret);
	}

	memset(ret, 0, (numnames + 1)*sizeof(char*));

	for (j = 0; j < numnames; ++j) {
		ret[j] = get_config_string(nd, j);
		if (!ret[j]) {
			ipmilan_free_hostlist(ret);
			ret = NULL;
			break;
		}
	}

	return(ret);
}

static void
ipmilan_free_hostlist (char ** hlist)
{
	char **	hl = hlist;
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
 *
 *	The buffer for each string is MAX_IPMI_STRING_LEN bytes long.
 *      Right now it is set to 64. Hope this is enough.
 *	
 */

#define MAX_IPMI_STRING_LEN 64

static int
ipmilan_parse_config_info(struct ipmilanDevice* nd, const char * info)
{
	static int port;

	static char name[MAX_IPMI_STRING_LEN];
	static char ip[MAX_IPMI_STRING_LEN]; 

	static char auth[MAX_IPMI_STRING_LEN];
	static char priv[MAX_IPMI_STRING_LEN];

	static char user[MAX_IPMI_STRING_LEN];
	static char pass[MAX_IPMI_STRING_LEN];

	struct ipmilanHostInfo * hostinfo, * head, * tail;

	port = 0;
	hostinfo = NULL;
	memset(name, 0, MAX_IPMI_STRING_LEN);
	memset(ip, 0, MAX_IPMI_STRING_LEN);
	memset(auth, 0, MAX_IPMI_STRING_LEN);
	memset(priv, 0, MAX_IPMI_STRING_LEN);
	memset(user, 0, MAX_IPMI_STRING_LEN);
	memset(pass, 0, MAX_IPMI_STRING_LEN);

	do {
		if (sscanf(info, "%s %s %i %s %s %s %[^\r\n\t]", 
			name, ip, &port, auth, priv, user, pass) == 7 && 
			strlen(user) > 1 && strlen(pass) > 1) {

			if ((hostinfo = (struct ipmilanHostInfo *) MALLOC(sizeof(struct ipmilanHostInfo))) == NULL) {
				syslog(LOG_ERR, "out of memory");
				return (S_OOPS);
			}

			hostinfo->portnumber = port;

			if (strncmp(auth, "none", strlen(auth)) == 0) {
				hostinfo->authtype = IPMI_AUTHTYPE_NONE;
			} 
			else if (strncmp(auth, "md2", strlen(auth)) == 0) {
				hostinfo->authtype = IPMI_AUTHTYPE_MD2;
			}
			else if (strncmp(auth, "md5", strlen(auth)) == 0) {
				hostinfo->authtype = IPMI_AUTHTYPE_MD5;
			}
			else if (strncmp(auth, "straight", strlen(auth)) == 0) {
				hostinfo->authtype = IPMI_AUTHTYPE_STRAIGHT;
			}
			else {
				break;
			}

			if (strncmp(priv, "admin", strlen(priv)) == 0) {
				hostinfo->privilege = IPMI_PRIVILEGE_ADMIN;
			}
			else if (strncmp(priv, "operator", strlen(priv)) == 0) {
				hostinfo->privilege = IPMI_PRIVILEGE_OPERATOR;
			}
			else {
				break;
			}

			if ((hostinfo->hostname = STRDUP(name)) == NULL) {
				break;
			}

			if ((hostinfo->ipaddr = STRDUP(ip)) == NULL) {
				FREE(hostinfo->hostname);
				break;
			}

			if (strncmp(user, "\"\"", 2)==0) {
				memset(hostinfo->username, 0, sizeof(hostinfo->username));
			} else {
				strncpy(hostinfo->username, user, strlen(user)+1);
			}

			if (strncmp(pass, "\"\"", 2)==0) {
				memset(hostinfo->password, 0, sizeof(hostinfo->password));
			} else {
				strncpy(hostinfo->password, pass, strlen(pass)+1);
			}

			hostinfo->next = NULL;

			head = nd->hostlist;
			// find the last one in the list
			if (head) {
				tail = head->prev;
				tail->next = hostinfo;

				hostinfo->prev = tail;
				head->prev = hostinfo;

			} else {
				nd->hostlist = hostinfo;
				hostinfo->prev = hostinfo;
			}

			// increment the host counter
			nd->hostcount++;

			return (S_OK);
		} 
		else {
			break;
		}

	} while (0); // using this do loop here so we can have 'break' statement.

	if (hostinfo) {
		FREE(hostinfo);
		hostinfo = NULL;
	}
	return (S_BADCONFIG);
}

/*
 *	Reset the given host on this Stonith device.
 */
static int
ipmilan_reset_req(Stonith * s, int request, const char * host)
{
	int rc = 0;
	struct ipmilanDevice * nd;
	struct ipmilanHostInfo * node;

	if (!ISipmilanDEV(s)) {
		syslog(LOG_ERR, "invalid stonith device argument to %s", __FUNCTION__);
		return(S_OOPS);
	}

	nd = (struct ipmilanDevice *)s->pinfo;
	node = nd->hostlist;
	do {
		if (strcmp(node->hostname, host) == 0) {
			break;
		};

		node = node->next;
	} while (node);

	if (!node) {
		syslog(LOG_ERR, _("host %s is not configured in this STONITH module. Please check you configuration file."), host);
		return (S_OOPS);
	}

	rc = do_ipmi_cmd(node, request);
	if (!rc) {
		syslog(LOG_INFO, _("Host %s ipmilan-reset."), host);
	} else {
		syslog(LOG_INFO, _("Host %s ipmilan-reset error. Error = %d."), host, rc);
	}
	return rc;
}

/*
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */
static int
ipmilan_set_config_file(Stonith* s, const char * configname)
{
	FILE *	cfgfile;

	char	ipmiline[256];

	struct ipmilanDevice*	nd;

	int rc = S_BADCONFIG;

	if (!ISipmilanDEV(s)) {
		syslog(LOG_ERR, "invalid argument to ipmilan_set_configfile");
		return(S_OOPS);
	}
	nd = (struct ipmilanDevice*) s->pinfo;

	if ((cfgfile = fopen(configname, "r")) == NULL)  {
		syslog(LOG_ERR, "Cannot open %s", configname);
		return(S_BADCONFIG);
	}
	while (fgets(ipmiline, sizeof(ipmiline), cfgfile) != NULL){
		if (*ipmiline == '#' || *ipmiline == '\n' || *ipmiline == EOS) {
			continue;
		}
		if ((rc = ipmilan_parse_config_info(nd, ipmiline)) != S_OK) {
			break;
		};
	}

	fclose(cfgfile);
	return(rc);
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
ipmilan_set_config_info(Stonith* s, const char * info)
{
	struct ipmilanDevice* nd;

	if (!ISipmilanDEV(s)) {
		syslog(LOG_ERR, "%s: invalid argument", __FUNCTION__);
		return(S_OOPS);
	}
	nd = (struct ipmilanDevice *)s->pinfo;

	return(ipmilan_parse_config_info(nd, info));
}

static const char *
ipmilan_getinfo(Stonith * s, int reqtype)
{
	struct ipmilanDevice* nd;
	char *		ret;

	if (!ISipmilanDEV(s)) {
		syslog(LOG_ERR, "ipmilan_getinfo: invalid argument");
		return NULL;
	}
	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	nd = (struct ipmilanDevice *)s->pinfo;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = _("ipmilan STONITH device");
			break;

		case ST_CONF_INFO_SYNTAX:
			ret = _("hostname ipaddr port auth priv user pass \n"
			"all fields are white-space delimited.");
			break;

		case ST_CONF_FILE_SYNTAX:
			ret = _("hostname ipaddr port auth priv user pass \n"
			"All fields are white-space delimited.  "
			"Blank lines and lines beginning with # are ignored");
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
 *	ipmilan Stonith destructor...
 *
 * 	The hostlist is a link list.  So have to iterate through.
 */
static void
ipmilan_destroy(Stonith *s)
{
	struct ipmilanDevice* nd;
	struct ipmilanHostInfo * host;
	int i;

	if (!ISipmilanDEV(s)) {
		syslog(LOG_ERR, "%s: invalid argument", __FUNCTION__);
		return;
	}
	nd = (struct ipmilanDevice *)s->pinfo;

	nd->ipmiid = NOTipmilanID;

	host = nd->hostlist->prev;
	for (i = 0; i < nd->hostcount; i++) {

		FREE(host->hostname);
		FREE(host->ipaddr);

		FREE(host);
		host = host->prev;
	}

	nd->hostcount = -1;
	FREE(nd);
}

/* Create a new ipmilan Stonith device.  Too bad this function can't be static */
static void *
ipmilan_new(void)
{
	struct ipmilanDevice*	nd = MALLOCT(struct ipmilanDevice);

	if (nd == NULL) {
		syslog(LOG_ERR, "out of memory");
		return(NULL);
	}
	memset(nd, 0, sizeof(*nd));
	nd->ipmiid = ipmilanid;
	nd->hostlist = NULL;
	nd->hostcount = 0; 
	return((void *)nd);
}


