/*
 * Stonith module for RILOE Stonith device
 *
 * Copyright (c) 2004 Alain St-Denis <alain.st-denis@ec.gc.ca>
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

static void *		riloe_new(void);
static void		riloe_destroy(Stonith *);
static int		riloe_set_config_file(Stonith *, const char * cfgname);
static int		riloe_set_config_info(Stonith *, const char * info);
static const char *	riloe_getinfo(Stonith * s, int InfoType);
static int		riloe_status(Stonith * );
static int		riloe_reset_req(Stonith * s, int request, const char * host);
static char **		riloe_hostlist(Stonith  *);

static struct stonith_ops riloeOps ={
	riloe_new,		/* Create new STONITH object	*/
	riloe_destroy,		/* Destroy STONITH object	*/
	riloe_set_config_file,	/* set configuration from file	*/
	riloe_set_config_info,	/* Get configuration from file	*/
	riloe_getinfo,		/* Return STONITH info string	*/
	riloe_status,		/* Return STONITH device status	*/
	riloe_reset_req,		/* Request a reset */
	riloe_hostlist,		/* Return list of supported hosts */
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
	const char *	pluginid;
	char **		hostlist;
	int		hostcount;
};

static const char * pluginid = "pluginDevice-Stonith";
static const char * NOTriloeID = "Hey, dummy this has been destroyed (RiloeDev)";

static int
riloe_status(Stonith  *s)
{

	ERRIFWRONGDEV(s,S_OOPS);
	return S_OK;
}


/*
 *	Return the list of hosts configured for this RILOE device
 */

static char **
riloe_hostlist(Stonith  *s)
{
	int		numnames = 0;
	char **		ret = NULL;
	struct pluginDevice*	nd;
	int		j;

	ERRIFWRONGDEV(s,NULL);
	nd = (struct pluginDevice*) s->pinfo;
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
riloe_reset_req(Stonith * s, int request, const char * host)
{
	char cmd[4096];

	ERRIFWRONGDEV(s,S_OOPS);
	LOG(PIL_INFO, _("Host %s riloe-reset."), host);

	sprintf(cmd, "%s %s reset", RILOE_COMMAND, host);

	if (system(cmd) == 0)
		return S_OK;
	else {
		LOG(PIL_CRIT, "command %s failed", cmd);
		return(S_RESETFAIL);
	}
}

/*
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */
static int
riloe_set_config_file(Stonith* s, const char * configname)
{
	FILE *	cfgfile;

	char	RILOEline[256];

	struct pluginDevice*	nd;

	ERRIFWRONGDEV(s,S_OOPS);
	nd = (struct pluginDevice*) s->pinfo;

	if ((cfgfile = fopen(configname, "r")) == NULL)  {
		LOG(PIL_CRIT, "Cannot open %s", configname);
		return(S_BADCONFIG);
	}
	while (fgets(RILOEline, sizeof(RILOEline), cfgfile) != NULL){
		if (*RILOEline == '#' || *RILOEline == '\n' || *RILOEline == EOS) {
			continue;
		}
		return(RILOE_parse_config_info(nd, RILOEline));
	}
	return(S_BADCONFIG);
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
riloe_set_config_info(Stonith* s, const char * info)
{
	struct pluginDevice* nd;

	ERRIFWRONGDEV(s,S_OOPS);
	nd = (struct pluginDevice *)s->pinfo;

	return(RILOE_parse_config_info(nd, info));
}

static const char *
riloe_getinfo(Stonith * s, int reqtype)
{
	struct pluginDevice* nd;
	char *		ret;

	ERRIFWRONGDEV(s,NULL);
	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	nd = (struct pluginDevice *)s->pinfo;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = _("riloe STONITH device");
			break;

		case ST_CONF_INFO_SYNTAX:
			ret = _("hostname ...\n"
			"host names are white-space delimited.");
			break;

		case ST_CONF_FILE_SYNTAX:
			ret = _("hostname ...\n"
			"host names are white-space delimited.  "
			"All host names must be on one line.  "
			"Blank lines and lines beginning with # are ignored");
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
riloe_destroy(Stonith *s)
{
	struct pluginDevice* nd;

	VOIDERRIFWRONGDEV(s);
	nd = (struct pluginDevice *)s->pinfo;

	nd->pluginid = NOTriloeID;
	if (nd->hostlist) {
		stonith_free_hostlist(nd->hostlist);
		nd->hostlist = NULL;
	}
	nd->hostcount = -1;
	FREE(nd);
}

/* Create a new Riloe Stonith device.  Too bad this function can't be static */
static void *
riloe_new(void)
{
	struct pluginDevice*	nd = MALLOCT(struct pluginDevice);

	if (nd == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(nd, 0, sizeof(*nd));
	nd->pluginid = pluginid;
	nd->hostlist = NULL;
	nd->hostcount = -1;
	return((void *)nd);
}
