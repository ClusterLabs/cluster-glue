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
#define PIL_PLUGIN              null
#define PIL_PLUGIN_S            "null"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

/*
 * nullclose is called as part of unloading the null STONITH plugin.
 * If there was any global data allocated, or file descriptors opened, etc.
 * which is associated with the plugin, and not a single interface
 * in particular, here's our chance to clean it up.
 */

static void
nullclosepi(PILPlugin*pi)
{
}


/*
 * nullcloseintf called as part of shutting down the null STONITH
 * interface.  If there was any global data allocated, or file descriptors
 * opened, etc.  which is associated with the null implementation,
 * here's our chance to clean it up.
 */
static PIL_rc
nullcloseintf(PILInterface* pi, void* pd)
{
	return PIL_OK;
}

static void *		null_new(void);
static void		null_destroy(Stonith *);
static int		null_set_config_file(Stonith *, const char * cfgname);
static int		null_set_config_info(Stonith *, const char * info);
static const char *	null_getinfo(Stonith * s, int InfoType);
static int		null_status(Stonith * );
static int		null_reset_req(Stonith * s, int request, const char * host);
static char **		null_hostlist(Stonith  *);
static void		null_free_hostlist(char **);

static struct stonith_ops nullOps ={
	null_new,		/* Create new STONITH object	*/
	null_destroy,		/* Destroy STONITH object	*/
	null_set_config_file,	/* set configuration from file	*/
	null_set_config_info,	/* Get configuration from file	*/
	null_getinfo,		/* Return STONITH info string	*/
	null_status,		/* Return STONITH device status	*/
	null_reset_req,		/* Request a reset */
	null_hostlist,		/* Return list of supported hosts */
	null_free_hostlist	/* free above list */
};

PIL_PLUGIN_BOILERPLATE("1.0", Debug, nullclosepi);
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
	,	&nullOps
	,	nullcloseintf		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

#define	DEVICE	"NULL STONITH device"
#define WHITESPACE	" \t\n\r\f"

/*
 *	Null STONITH device.  We are very agreeable, but don't do much :-)
 */

struct NullDevice {
	const char *	NULLid;
	char **		hostlist;
	int		hostcount;
};

static const char * NULLid = "NullDevice-Stonith";
static const char * NOTnullID = "Hey, dummy this has been destroyed (NullDev)";

#define	ISNULLDEV(i)	(((i)!= NULL && (i)->pinfo != NULL)	\
	&& ((struct NullDevice *)(i->pinfo))->NULLid == NULLid)


#ifndef MALLOCT
#	define     MALLOCT(t)      ((t *)(MALLOC(sizeof(t)))) 
#endif

#define N_(text)	(text)
#define _(text)		dgettext(ST_TEXTDOMAIN, text)


static int
null_status(Stonith  *s)
{

	if (!ISNULLDEV(s)) {
		syslog(LOG_ERR, "invalid argument to NULL_status");
		return(S_OOPS);
	}
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
	struct NullDevice*	nd;
	int		j;

	if (!ISNULLDEV(s)) {
		syslog(LOG_ERR, "invalid argument to NULL_list_hosts");
		return(NULL);
	}
	nd = (struct NullDevice*) s->pinfo;
	if (nd->hostcount < 0) {
		syslog(LOG_ERR
		,	"unconfigured stonith object in NULL_list_hosts");
		return(NULL);
	}
	numnames = nd->hostcount;

	ret = (char **)MALLOC(numnames*sizeof(char*));
	if (ret == NULL) {
		syslog(LOG_ERR, "out of memory");
		return ret;
	}

	memset(ret, 0, numnames*sizeof(char*));

	for (j=0; j < numnames-1; ++j) {
		ret[j] = STRDUP(nd->hostlist[j]);
		if (ret[j] == NULL) {
			null_free_hostlist(ret);
			ret = NULL;
			return ret;
		}
	}
	return(ret);
}

static void
null_free_hostlist (char ** hlist)
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
NULL_parse_config_info(struct NullDevice* nd, const char * info)
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
		syslog(LOG_ERR, "out of memory");
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
				null_free_hostlist(ret);
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
null_reset_req(Stonith * s, int request, const char * host)
{

	if (!ISNULLDEV(s)) {
		syslog(LOG_ERR, "invalid argument to %s", __FUNCTION__);
		return(S_OOPS);
	}

	/* Real devices need to pay attention to the "request" */
	/* (but we don't care ;-)) */

	syslog(LOG_INFO, _("Host %s null-reset."), host);
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

	struct NullDevice*	nd;

	if (!ISNULLDEV(s)) {
		syslog(LOG_ERR, "invalid argument to NULL_set_configfile");
		return(S_OOPS);
	}
	nd = (struct NullDevice*) s->pinfo;

	if ((cfgfile = fopen(configname, "r")) == NULL)  {
		syslog(LOG_ERR, "Cannot open %s", configname);
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
	struct NullDevice* nd;

	if (!ISNULLDEV(s)) {
		syslog(LOG_ERR, "%s: invalid argument", __FUNCTION__);
		return(S_OOPS);
	}
	nd = (struct NullDevice *)s->pinfo;

	return(NULL_parse_config_info(nd, info));
}

static const char *
null_getinfo(Stonith * s, int reqtype)
{
	struct NullDevice* nd;
	char *		ret;

	if (!ISNULLDEV(s)) {
		syslog(LOG_ERR, "NULL_idinfo: invalid argument");
		return NULL;
	}
	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	nd = (struct NullDevice *)s->pinfo;

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
	struct NullDevice* nd;

	if (!ISNULLDEV(s)) {
		syslog(LOG_ERR, "%s: invalid argument", __FUNCTION__);
		return;
	}
	nd = (struct NullDevice *)s->pinfo;

	nd->NULLid = NOTnullID;
	if (nd->hostlist) {
		null_free_hostlist(nd->hostlist);
		nd->hostlist = NULL;
	}
	nd->hostcount = -1;
	FREE(nd);
}

/* Create a new Null Stonith device.  Too bad this function can't be static */
static void *
null_new(void)
{
	struct NullDevice*	nd = MALLOCT(struct NullDevice);

	if (nd == NULL) {
		syslog(LOG_ERR, "out of memory");
		return(NULL);
	}
	memset(nd, 0, sizeof(*nd));
	nd->NULLid = NULLid;
	nd->hostlist = NULL;
	nd->hostcount = -1;
	return((void *)nd);
}
