/*
 * Stonith module for Dell DRACIII (Dell Remote Access Card)
 *
 * Copyright (C) 2003 Alfa21 Outsourcing
 * Copyright (C) 2003 Roberto Moreda <moreda@alfa21.com>
 * Tiny bits Copyright 2005 International Business Machines
 * Significantly Mangled by Sun Jiang Dong <sunjd@cn.ibm.com>, IBM, 2005
 *
 * (Using snippets of other stonith modules code)
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 *
 */

#define DEVICE  "Dell DRACIII Card"
#include "stonith_plugin_common.h"

#include <curl/curl.h>
#include "drac3_command.h"

#define PIL_PLUGIN              drac3
#define PIL_PLUGIN_S            "drac3"
#define PIL_PLUGINLICENSE       LICENSE_LGPL
#define PIL_PLUGINLICENSEURL    URL_LGPL
#include <pils/plugin.h>
#include "stonith_signal.h"

static StonithPlugin *	drac3_new(const char *);
static void	drac3_destroy(StonithPlugin *);
static const char * const * drac3_get_confignames(StonithPlugin *);
static int	drac3_set_config(StonithPlugin *, StonithNVpair *);
static const char * drac3_getinfo(StonithPlugin * s, int InfoType);
static int	drac3_status(StonithPlugin * );
static int	drac3_reset_req(StonithPlugin * s, int request, const char * host);
static char **	drac3_hostlist(StonithPlugin  *);

static struct stonith_ops drac3Ops ={
	drac3_new,		/* Create new STONITH object	*/
	drac3_destroy,		/* Destroy STONITH object	*/
	drac3_getinfo,		/* Return STONITH info string	*/
	drac3_get_confignames,	/* Return configuration parameters */
	drac3_set_config,	/* Set configuration */
	drac3_status,		/* Return STONITH device status	*/
	drac3_reset_req,	/* Request a reset */
	drac3_hostlist,		/* Return list of supported hosts */
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
	,	&drac3Ops
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

#define BUFLEN	1024
#define ST_HOST "host"

struct pluginDevice {
	StonithPlugin sp;
	const char *pluginid;
	const char *idinfo;
	CURL *curl;
	char *host;
	char *user;
	char *pass;
};

static const char *pluginid = "Dell-DRACIII-Stonith";
static const char *NOTpluginID = "Dell DRACIII device has been destroyed";

#include "stonith_config_xml.h"

#define XML_HOST_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	ST_HOST \
	XML_PARM_SHORTDESC_END

#define XML_HOST_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The hostname of the STONITH device" \
	XML_PARM_LONGDESC_END

#define XML_HOST_PARM \
	XML_PARAMETER_BEGIN(ST_HOST, "string", "1", "1") \
	  XML_HOST_SHORTDESC \
	  XML_HOST_LONGDESC \
	XML_PARAMETER_END

static const char *drac3XML = 
  XML_PARAMETERS_BEGIN
    XML_HOST_PARM
    XML_LOGIN_PARM
    XML_PASSWD_PARM
  XML_PARAMETERS_END;

/* ------------------------------------------------------------------ */
/* STONITH PLUGIN API                                                 */
/* ------------------------------------------------------------------ */
static StonithPlugin *
drac3_new(const char *subplugin)
{
	struct pluginDevice *drac3d = ST_MALLOCT(struct pluginDevice);

	if (drac3d == NULL) {
			LOG(PIL_CRIT, "out of memory");
			return(NULL);
	}
	memset(drac3d, 0, sizeof(*drac3d));
	drac3d->pluginid = pluginid;
	drac3d->curl = curl_easy_init();
	drac3InitCurl(drac3d->curl);
	drac3d->host = NULL;
	drac3d->user = NULL;
	drac3d->pass = NULL;
	drac3d->idinfo = DEVICE;
	drac3d->sp.s_ops = &drac3Ops;
	return (&(drac3d->sp));
}

/* ------------------------------------------------------------------ */
static void
drac3_destroy(StonithPlugin * s)
{
	struct pluginDevice *drac3d;

	VOIDERRIFWRONGDEV(s);

	drac3d = (struct pluginDevice *) s;

	drac3d->pluginid = NOTpluginID;

	/* release curl connection */
	if (drac3d->curl != NULL) {
		drac3Logout(drac3d->curl, drac3d->host);
		curl_easy_cleanup(drac3d->curl);
		drac3d->curl = NULL;
	}

	if (drac3d->host != NULL) {
		FREE(drac3d->host);
		drac3d->host = NULL;
	}
	if (drac3d->user != NULL) {
		FREE(drac3d->user);
		drac3d->user = NULL;
	}
	if (drac3d->pass != NULL) {
		FREE(drac3d->pass);
		drac3d->pass = NULL;
	}

	/* release stonith-object itself */
	FREE(drac3d);
}

/* ------------------------------------------------------------------ */
static const char * const *
drac3_get_confignames(StonithPlugin * s)
{
	static const char * ret[] = {ST_HOST, ST_LOGIN, ST_PASSWD, NULL};
	return ret;
}

/* ------------------------------------------------------------------ */
static int
drac3_set_config(StonithPlugin * s, StonithNVpair * list)
{
	struct pluginDevice* sd = (struct pluginDevice *)s;
	int		rc;
	StonithNamesToGet	namestocopy [] =
	{	{ST_HOST,	NULL}
	,	{ST_LOGIN,	NULL}
	,	{ST_PASSWD,	NULL}
	,	{NULL,		NULL}
	};

	ERRIFWRONGDEV(s, S_OOPS);
	if (sd->sp.isconfigured) {
		return S_OOPS;
	}

	if ((rc=OurImports->CopyAllValues(namestocopy, list)) != S_OK) {
		return rc;
	}
	sd->host = namestocopy[0].s_value;
	sd->user = namestocopy[1].s_value;
	sd->pass = namestocopy[2].s_value;

	return(S_OK);
}

/* ------------------------------------------------------------------ */
const char *
drac3_getinfo(StonithPlugin * s, int reqtype)
{
	struct pluginDevice *drac3d;
	const char *ret = NULL;

	ERRIFWRONGDEV(s,NULL);

	drac3d = (struct pluginDevice *) s;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = drac3d->idinfo;
			break;
		case ST_DEVICENAME:
			ret = drac3d->host;
			break;
		case ST_DEVICEDESCR:
			ret = "Dell DRACIII (via HTTPS)\n"
			"The Dell Remote Access Controller accepts XML "
			"commands over HTTPS";
			break;
		case ST_DEVICEURL:
			ret = "http://www.dell.com/";
			break;
		case ST_CONF_XML:		/* XML metadata */
			ret = drac3XML;
			break;
		default:
			ret = NULL;
			break;
	}

	return(ret);
}

/* ------------------------------------------------------------------ */
int
drac3_status(StonithPlugin  *s)
{
	struct pluginDevice *drac3d;

	ERRIFNOTCONFIGED(s,S_OOPS);

	drac3d = (struct pluginDevice *) s;

	if (drac3VerifyLogin(drac3d->curl, drac3d->host)) {
		if (drac3Login(drac3d->curl, drac3d->host,
		                drac3d->user, drac3d->pass)) {
		 	LOG(PIL_CRIT, "%s: cannot log into %s at %s", 
							__FUNCTION__,
							drac3d->idinfo,
							drac3d->host);
		 	return(S_ACCESS);
		}
	}

	if (drac3GetSysInfo(drac3d->curl, drac3d->host)) {
		return(S_ACCESS);
	}else{
		return(S_OK);
	}
}

/* ------------------------------------------------------------------ */
int
drac3_reset_req(StonithPlugin * s, int request, const char *host)
{
	struct pluginDevice *drac3d;
	int rc = S_OK;

	ERRIFNOTCONFIGED(s,S_OOPS);

	drac3d = (struct pluginDevice *) s;

	if (strcasecmp(host, drac3d->host)) {
		LOG(PIL_CRIT, "%s doesn't control host [%s]"
		,	drac3d->idinfo, host);
		return(S_BADHOST);
	}

	if (drac3VerifyLogin(drac3d->curl, drac3d->host)) {
		if (drac3Login(drac3d->curl, drac3d->host,
		                drac3d->user, drac3d->pass)) {
		 	LOG(PIL_CRIT, "%s: cannot log into %s at %s", 
							__FUNCTION__,
							drac3d->idinfo,
							drac3d->host);
		 	return(S_ACCESS);
		}
	}

	switch(request) {
#if defined(ST_POWERON) && defined(ST_POWEROFF)
		case ST_POWERON:
		case ST_POWEROFF:
			/* TODO... */
#endif
		case ST_GENERIC_RESET:
			if (drac3PowerCycle(drac3d->curl, drac3d->host))
				rc = S_ACCESS;
			break;
		default:
			rc = S_INVAL;
			break;
	}

	return(rc);
}

/* ------------------------------------------------------------------ */
char **
drac3_hostlist(StonithPlugin * s)
{
	struct pluginDevice *drac3d;
	char **hl;

	ERRIFNOTCONFIGED(s,NULL);

	drac3d = (struct pluginDevice *) s;

	hl = OurImports->StringToHostList(drac3d->host);
	if (hl == NULL) {
		LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
	} else {
		strdown(hl[0]);
	}

	return(hl);
}
