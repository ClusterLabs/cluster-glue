/* $Id: null.c,v 1.15 2004/10/06 10:55:18 lars Exp $ */
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

#define	DEVICE	"NULL STONITH device"
#include "stonith_plugin_common.h"

#define PIL_PLUGIN              null
#define PIL_PLUGIN_S            "null"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

static void *		null_new(void);
static void		null_destroy(Stonith *);
static int		null_set_config_file(Stonith *, const char * cfgname);
static int		null_set_config_info(Stonith *, const char * info);
static const char *	null_getinfo(Stonith * s, int InfoType);
static int		null_status(Stonith * );
static int		null_reset_req(Stonith * s, int request, const char * host);
static char **		null_hostlist(Stonith  *);

static struct stonith_ops nullOps ={
	null_new,		/* Create new STONITH object	*/
	null_destroy,		/* Destroy STONITH object	*/
	null_set_config_file,	/* set configuration from file	*/
	null_set_config_info,	/* Get configuration from file	*/
	null_getinfo,		/* Return STONITH info string	*/
	null_status,		/* Return STONITH device status	*/
	null_reset_req,		/* Request a reset */
	null_hostlist,		/* Return list of supported hosts */
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug);
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

struct pluginDevice {
	const char *	pluginid;
	char **		hostlist;
	int		hostcount;
};

static const char * pluginid = "pluginDevice-Stonith";
static const char * NOTpluginID = "Hey, dummy this has been destroyed (NullDev)";

static int
null_status(Stonith  *s)
{

	ERRIFWRONGDEV(s,S_OOPS);
	return S_OK;
}


/*
 *	Return the list of hosts configured for this NULL device
 */

static char **
null_hostlist(Stonith  *s)
{
	int		numnames = 0;
	char **		ret = NULL;
	struct pluginDevice*	nd;
	int		j;

	ERRIFWRONGDEV(s,NULL);
	nd = (struct pluginDevice*) s->pinfo;
	if (nd->hostcount < 0) {
		LOG(PIL_CRIT
		,	"unconfigured stonith object in NULL_list_hosts");
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
		ret[j] = STRDUP(nd->hostlist[j]);
		if (ret[j] == NULL) {
			stonith_free_hostlist(ret);
			ret = NULL;
			return ret;
		}
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
NULL_parse_config_info(struct pluginDevice* nd, const char * info)
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
			g_strdown(ret[j]);
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
null_reset_req(Stonith * s, int request, const char * host)
{

	ERRIFWRONGDEV(s,S_OOPS);

	/* Real devices need to pay attention to the "request" */
	/* (but we don't care ;-)) */

	LOG(PIL_INFO,"%s: %s",  _("Host null-reset"), host);
	return S_OK;
}

/*
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */
static int
null_set_config_file(Stonith* s, const char * configname)
{
	FILE *	cfgfile;

	char	NULLline[256];

	struct pluginDevice*	nd;

	ERRIFWRONGDEV(s,S_OOPS);
	nd = (struct pluginDevice*) s->pinfo;

	if ((cfgfile = fopen(configname, "r")) == NULL)  {
		LOG(PIL_CRIT, "Cannot open %s", configname);
		return(S_BADCONFIG);
	}
	while (fgets(NULLline, sizeof(NULLline), cfgfile) != NULL){
		if (*NULLline == '#' || *NULLline == '\n' || *NULLline == EOS) {
			continue;
		}
		return(NULL_parse_config_info(nd, NULLline));
	}
	return(S_BADCONFIG);
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
null_set_config_info(Stonith* s, const char * info)
{
	struct pluginDevice* nd;

	ERRIFWRONGDEV(s,S_OOPS);
	nd = (struct pluginDevice *)s->pinfo;

	return(NULL_parse_config_info(nd, info));
}

static const char *
null_getinfo(Stonith * s, int reqtype)
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
			ret = _("null STONITH device");
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
			ret = _("Dummy (do-nothing) STONITH device\n"
			"FOR TESTING ONLY!");
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
null_destroy(Stonith *s)
{
	struct pluginDevice* nd;

	VOIDERRIFWRONGDEV(s);
	nd = (struct pluginDevice *)s->pinfo;

	nd->pluginid = NOTpluginID;
	if (nd->hostlist) {
		stonith_free_hostlist(nd->hostlist);
		nd->hostlist = NULL;
	}
	nd->hostcount = -1;
	FREE(nd);
}

/* Create a new Null Stonith device.  Too bad this function can't be static */
static void *
null_new(void)
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
