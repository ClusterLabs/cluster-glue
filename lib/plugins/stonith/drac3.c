/* $Id: drac3.c,v 1.8 2004/10/05 14:26:16 lars Exp $ */
/*
 * Stonith module for Dell DRACIII (Dell Remote Access Card)
 *
 * Copyright (C) 2003 Alfa21 Outsourcing
 * Copyright (C) 2003 Roberto Moreda <moreda@alfa21.com>
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

#define DEVICE  "Dell DRAC III Card"
#include "stonith_plugin_common.h"

#include <curl/curl.h>
#include "drac3_command.h"

#define PIL_PLUGIN              drac3
#define PIL_PLUGIN_S            "drac3"
#define PIL_PLUGINLICENSE       LICENSE_LGPL
#define PIL_PLUGINLICENSEURL    URL_LGPL
#include <pils/plugin.h>
#include "stonith_signal.h"

static void *	drac3_new(void);
static void		drac3_destroy(Stonith *);
static int		drac3_set_config_file(Stonith *, const char * cfgname);
static int		drac3_set_config_info(Stonith *, const char * info);
static const char * drac3_getinfo(Stonith * s, int InfoType);
static int		drac3_status(Stonith * );
static int		drac3_reset_req(Stonith * s, int request, const char * host);
static char **	drac3_hostlist(Stonith  *);

static struct stonith_ops drac3Ops ={
	drac3_new,		/* Create new STONITH object	*/
	drac3_destroy,		/* Destroy STONITH object	*/
	drac3_set_config_file,	/* set configuration from file	*/
	drac3_set_config_info,	/* Get configuration from file	*/
	drac3_getinfo,		/* Return STONITH info string	*/
	drac3_status,			/* Return STONITH device status	*/
	drac3_reset_req,		/* Request a reset */
	drac3_hostlist,		/* Return list of supported hosts */
};

PIL_PLUGIN_BOILERPLATE("1.0", Debug, NULL);
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

struct pluginDevice {
	const char *pluginid;
	CURL *curl;
	int config;
	char *host;
	char *user;
	char *pass;
};

static const char *pluginid = DEVICE;
static const char *NOTpluginID = "destroyed (Dell DRAC III Card)";

/* private function prototypes */
static int DRAC3_parse_config_info(struct pluginDevice * drac3d, const char * info);


/* ------------------------------------------------------------------ */
/* STONITH PLUGIN API                                                 */
/* ------------------------------------------------------------------ */
void *
drac3_new(void)
{
	struct pluginDevice *drac3d = MALLOCT(struct pluginDevice);

	if (drac3d == NULL) {
			LOG(PIL_CRIT, "out of memory");
			return(NULL);
	}
	memset(drac3d, 0, sizeof(*drac3d));
	drac3d->pluginid = pluginid;
	drac3d->curl = NULL;
	drac3d->config = 0;
	drac3d->host = NULL;
	drac3d->user = NULL;
	drac3d->pass = NULL;

	return ((void *) drac3d);
}

/* ------------------------------------------------------------------ */
void
drac3_destroy(Stonith * s)
{
	struct pluginDevice *drac3d;

	VOIDERRIFWRONGDEV(s);

	drac3d = (struct pluginDevice *) s->pinfo;

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
int 
drac3_set_config_file(Stonith * s, const char *configname) 
{
	FILE *cfgfile;
	char confline[BUFLEN];
	struct pluginDevice *drac3d;

	ERRIFWRONGDEV(s,S_INVAL);

	drac3d = (struct pluginDevice *) s->pinfo;

	if ((cfgfile = fopen(configname, "r")) == NULL) {
		LOG(PIL_CRIT, "Cannot open %s", configname);
		return (S_BADCONFIG);
	}

	while (fgets(confline, sizeof(confline), cfgfile) != NULL) {
		if (*confline == '#' || *confline == '\n' || *confline == EOS)
			continue;
		return (DRAC3_parse_config_info(drac3d, confline));
	}
	return (S_BADCONFIG);
}

/* ------------------------------------------------------------------ */
int
drac3_set_config_info(Stonith * s, const char *info)
{
	struct pluginDevice *drac3d;

	ERRIFWRONGDEV(s,S_INVAL);

	drac3d = (struct pluginDevice *) s->pinfo;

	return (DRAC3_parse_config_info(drac3d, info));
}

/* ------------------------------------------------------------------ */
const char *
drac3_getinfo(Stonith * s, int reqtype)
{
	struct pluginDevice *drac3d;
	const char *ret = NULL;

	ERRIFWRONGDEV(s,NULL);

	drac3d = (struct pluginDevice *) s->pinfo;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = drac3d->pluginid;
			break;
		case ST_CONF_INFO_SYNTAX:
			ret = _("<drac3-address> <user> <password>\n");
			break;
		case ST_CONF_FILE_SYNTAX:
			ret = _("<drac3-address> <user> <password>\n"
				"All items must be on one line.\n"
				"Blank lines and lines beginning with # are ignored.");
			break;
		case ST_DEVICEDESCR:
			ret = _("Dell DRACIII (via HTTPS)\n"
				"The Dell Remote Access Controller accepts XML commands over HTTPS");
			break;
		case ST_DEVICEURL:
			ret = _("http://www.dell.com/us/en/biz/topics/power_ps2q02-bell.htm");
			break;
		default:
			ret = NULL;
			break;
	}

	return(ret);
}

/* ------------------------------------------------------------------ */
int
drac3_status(Stonith  *s)
{
	struct pluginDevice *drac3d;

	ERRIFNOTCONFIGED(s,S_OOPS);

	drac3d = (struct pluginDevice *) s->pinfo;

	if (drac3VerifyLogin(drac3d->curl, drac3d->host)) {
		if (drac3Login(drac3d->curl, drac3d->host,
		                drac3d->user, drac3d->pass)) {
		 	LOG(PIL_CRIT, "%s: cannot log into %s at %s", 
							__FUNCTION__,
							DEVICE,
							drac3d->host);
		 	return(S_ACCESS);
		}
	}

	if (drac3GetSysInfo(drac3d->curl, drac3d->host)) 
		return(S_ACCESS);
	else
		return(S_OK);
}

/* ------------------------------------------------------------------ */
int
drac3_reset_req(Stonith * s, int request, const char *host)
{
	struct pluginDevice *drac3d;
	int rc = S_OK;

	ERRIFNOTCONFIGED(s,S_OOPS);

	drac3d = (struct pluginDevice *) s->pinfo;

	if (drac3VerifyLogin(drac3d->curl, drac3d->host)) {
		if (drac3Login(drac3d->curl, drac3d->host,
		                drac3d->user, drac3d->pass)) {
		 	LOG(PIL_CRIT, "%s: cannot log into %s at %s", 
							__FUNCTION__,
							DEVICE,
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
drac3_hostlist(Stonith * s)
{
	struct pluginDevice *drac3d;
	char **hl;

	ERRIFNOTCONFIGED(s,NULL);

	drac3d = (struct pluginDevice *) s->pinfo;

	hl = (char **)MALLOC(2*sizeof(char*));
	if (hl == NULL) {
		LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
	} else {
		hl[1]=NULL;
		hl[0]=STRDUP(drac3d->host);
		if (hl[0]) {
			LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
			FREE(hl);
			hl = NULL;
		}
		g_strdown(hl[0]);
	}

	return(hl);
}

/* ------------------------------------------------------------------ */
/* PRIVATE FUNCTIONS                                                  */
/* ------------------------------------------------------------------ */

static int
DRAC3_parse_config_info(struct pluginDevice * drac3d, const char * info)
{
	static char host[BUFLEN];
	static char user[BUFLEN];
	static char pass[BUFLEN];
	CURL *curl;

	/* TODO: check strings length in conffile */
	if (sscanf(info, "%s %s %s", host, user, pass) == 3) {

			if ((drac3d->host = STRDUP(host)) == NULL) {
					LOG(PIL_CRIT, "%s: out of memory", 
							__FUNCTION__);
					return(S_OOPS);
			}
			g_strdown(drac3d->host);
			if ((drac3d->user = STRDUP(user)) == NULL) {
					LOG(PIL_CRIT, "%s: out of memory", 
							__FUNCTION__);
					FREE(drac3d->host);
					return(S_OOPS);
			}
			if ((drac3d->pass = STRDUP(pass)) == NULL) {
					LOG(PIL_CRIT, "%s: out of memory", 
							__FUNCTION__);
					FREE(drac3d->host);
					FREE(drac3d->user);
					return(S_OOPS);
			}

			curl = curl_easy_init();
			if ((drac3d->curl = curl_easy_init()) == NULL) { 
					LOG(PIL_CRIT, "%s: cannot init curl", 
							__FUNCTION__);
					FREE(drac3d->host);
					FREE(drac3d->user);
					FREE(drac3d->pass);
					return(S_OOPS);
			}

			drac3InitCurl(drac3d->curl);
			drac3d->config = 1;

			return(S_OK);
	} else {
			return(S_BADCONFIG);
	}
}
