/*
 * Stonith module for Human Operator Stonith device
 *
 * Copyright (c) 2001 Gregor Binder <gbinder@sysfive.com>
 *
 *   This module is largely based on the "NULL Stonith device", written
 *   by Alan Robertson <alanr@unix.sh>, using code by David C. Teigland
 *   <teigland@sistina.com> originally appeared in the GFS stomith
 *   meatware agent.
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
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <libintl.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <stonith/stonith.h>

#define PIL_PLUGINTYPE          STONITH_TYPE
#define PIL_PLUGINTYPE_S        STONITH_TYPE_S
#define PIL_PLUGIN              meatware
#define PIL_PLUGIN_S            "meatware"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

/*
 * meatwareclose is called as part of unloading the meatware STONITH plugin.
 * If there was any global data allocated, or file descriptors opened, etc.
 * which is associated with the plugin, and not a single interface
 * in particular, here's our chance to clean it up.
 */

static void
meatwareclosepi(PILPlugin*pi)
{
}


/*
 * meatwarecloseintf called as part of shutting down the meatware STONITH
 * interface.  If there was any global data allocated, or file descriptors
 * opened, etc.  which is associated with the meatware implementation,
 * here's our chance to clean it up.
 */
static PIL_rc
meatwarecloseintf(PILInterface* pi, void* pd)
{
	return PIL_OK;
}

static void *		meatware_new(void);
static void		meatware_destroy(Stonith *);
static int		meatware_set_config_file(Stonith *, const char * cfgname);
static int		meatware_set_config_info(Stonith *, const char * info);
static const char *	meatware_getinfo(Stonith * s, int InfoType);
static int		meatware_status(Stonith * );
static int		meatware_reset_req(Stonith * s, int request, const char * host);
static char **		meatware_hostlist(Stonith  *);
static void		meatware_free_hostlist(char **);

static struct stonith_ops meatwareOps ={
	meatware_new,		/* Create new STONITH object	*/
	meatware_destroy,		/* Destroy STONITH object	*/
	meatware_set_config_file,	/* set configuration from file	*/
	meatware_set_config_info,	/* Get configuration from file	*/
	meatware_getinfo,		/* Return STONITH info string	*/
	meatware_status,		/* Return STONITH device status	*/
	meatware_reset_req,		/* Request a reset */
	meatware_hostlist,		/* Return list of supported hosts */
	meatware_free_hostlist	/* free above list */
};
static int WordCount(const char * s);

PIL_PLUGIN_BOILERPLATE("1.0", Debug, meatwareclosepi);
static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static StonithImports*		OurImports;
static void*			interfprivate;

#define LOG		PluginImports->log
#define MALLOC		PluginImports->alloc
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
	,	&meatwareOps
	,	meatwarecloseintf		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}
#define	DEVICE	"Meatware STONITH device"
#define WHITESPACE	" \t\n\r\f"

/*
 *	Meatware STONITH device.
 */

struct MeatDevice {
	const char *	Meatid;
	char **		hostlist;
	int		hostcount;
};

static const char * Meatid = "MeatwareDevice-Stonith";
static const char * NOTMeatID = "Hey, dummy this has been destroyed (MeatwareDev)";

#define	ISMeatDEV(i)	(((i)!= NULL && (i)->pinfo != NULL)	\
	&& ((struct MeatDevice *)(i->pinfo))->Meatid == Meatid)


#ifndef MALLOC
#	define	MALLOC	malloc
#endif
#ifndef FREE
#	define	FREE	free
#endif
#ifndef MALLOCT
#	define     MALLOCT(t)      ((t *)(MALLOC(sizeof(t)))) 
#endif

#define DIMOF(a)	(sizeof(a)/sizeof(a[0]))

#define N_(text)	(text)
#define _(text)		dgettext(ST_TEXTDOMAIN, text)


static int
meatware_status(Stonith  *s)
{

	if (!ISMeatDEV(s)) {
		syslog(LOG_ERR, "invalid argument to Meatware_status");
		return(S_OOPS);
	}
	return S_OK;
}


/*
 *	Return the list of hosts configured for this Meat device
 */

static char **
meatware_hostlist(Stonith  *s)
{
	int		numnames = 0;
	char **		ret = NULL;
	struct MeatDevice*	nd;
	int		j;

	if (!ISMeatDEV(s)) {
		syslog(LOG_ERR, "invalid argument to Meatware_list_hosts");
		return(NULL);
	}
	nd = (struct MeatDevice*) s->pinfo;
	if (nd->hostcount < 0) {
		syslog(LOG_ERR
		,	"unconfigured stonith object in Meatware_list_hosts");
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
		ret[j] = MALLOC(strlen(nd->hostlist[j])+1);
		if (ret[j] == NULL) {
			meatware_free_hostlist(ret);
			ret = NULL;
			return ret;
		}
		strcpy(ret[j], nd->hostlist[j]);
	}
	return(ret);
}

static void
meatware_free_hostlist (char ** hlist)
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
Meat_parse_config_info(struct MeatDevice* nd, const char * info)
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
				meatware_free_hostlist(ret);
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
 *	Indicate that host must be power cycled manually.
 */
static int
meatware_reset_req(Stonith * s, int request, const char * host)
{
	int fd, rc;
	const char *	meatpipe_pr = "/tmp/.meatware"; /* if you intend to
							change this, modify
							meatclient.c as well */

	char		line[256], meatpipe[256];
	char		resp_addr[50], resp_mw[50], resp_result[50];

	if (!ISMeatDEV(s)) {
		syslog(LOG_ERR, "invalid argument to %s", __FUNCTION__);
		return(S_OOPS);
	}

	snprintf(meatpipe, 256, "%s.%s", meatpipe_pr, host);

	umask(0);
	unlink(meatpipe);

	rc = mkfifo(meatpipe, (S_IRUSR | S_IWUSR));

	if (rc < 0) {
		syslog(LOG_ERR, "cannot create FIFO for Meatware_reset_host");
		return(S_OOPS);
	}

	syslog(LOG_CRIT, "OPERATOR INTERVENTION REQUIRED to reset %s.", host);
	syslog(LOG_CRIT, "Run \"meatclient -c %s\" AFTER power-cycling the "
	                 "machine.", host);

	fd = open(meatpipe, O_RDONLY);

	if (fd < 0) {
		syslog(LOG_ERR, "cannot open FIFO for Meatware_reset_host");
		return(S_OOPS);
	}

	memset(line, 0, 256);
	rc = read(fd, line, 256);

	if (rc < 0) {
		syslog(LOG_ERR, "read error on FIFO for Meatware_reset_host");
		return(S_OOPS);
	}

	memset(resp_mw, 0, 50);
	memset(resp_result, 0, 50);
	memset(resp_addr, 0, 50);

	sscanf(line, "%s %s %s", resp_mw, resp_result, resp_addr);

	if (strncmp(resp_mw, "meatware", 8) ||
	    strncmp(resp_result, "reply", 5) ||
	    strncmp(resp_addr, host, strlen(resp_addr))) {
		syslog(LOG_ERR, "failed to Meatware-reset node %s", host);	
		return(S_RESETFAIL);
	}
	else {
		syslog(LOG_INFO, _("node %s Meatware-reset."), host);
		unlink(meatpipe);
		return(S_OK);
	}
}

/*
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */
static int
meatware_set_config_file(Stonith* s, const char * configname)
{
	FILE *	cfgfile;

	char	Meatline[256];

	struct MeatDevice*	nd;

	if (!ISMeatDEV(s)) {
		syslog(LOG_ERR, "invalid argument to Meatware_set_configfile");
		return(S_OOPS);
	}
	nd = (struct MeatDevice*) s->pinfo;

	if ((cfgfile = fopen(configname, "r")) == NULL)  {
		syslog(LOG_ERR, "cannot open %s", configname);
		return(S_BADCONFIG);
	}
	while (fgets(Meatline, sizeof(Meatline), cfgfile) != NULL){
		if (*Meatline == '#' || *Meatline == '\n' || *Meatline == EOS) {
			continue;
		}
		return(Meat_parse_config_info(nd, Meatline));
	}
	return(S_BADCONFIG);
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
meatware_set_config_info(Stonith* s, const char * info)
{
	struct MeatDevice* nd;

	if (!ISMeatDEV(s)) {
		syslog(LOG_ERR, "%s: invalid argument", __FUNCTION__);
		return(S_OOPS);
	}
	nd = (struct MeatDevice *)s->pinfo;

	return(Meat_parse_config_info(nd, info));
}

static const char *
meatware_getinfo(Stonith * s, int reqtype)
{
	struct MeatDevice* nd;
	char *		ret;

	if (!ISMeatDEV(s)) {
		syslog(LOG_ERR, "Meatware_idinfo: invalid argument");
		return NULL;
	}
	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	nd = (struct MeatDevice *)s->pinfo;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = _("Meatware STONITH device");
			break;

		case ST_CONF_INFO_SYNTAX:
			ret = _("hostname ...\n"
			"host names are white-space delimited.");
			break;

		case ST_CONF_FILE_SYNTAX:
			ret = _("hostname...\n"
			"host names are white-space delimited.  "
			"All host names must be on one line.  "
			"Blank lines and lines beginning with # are ignored");
			break;

		case ST_DEVICEDESCR:
			ret = _("Human (meatware) intervention STONITH device.\n"
			"This STONITH agent prompts a human to reset a machine.\n"
			"The human tells it when the reset was completed.");
			break;

		default:
			ret = NULL;
			break;
	}
	return ret;
}

/*
 *	Meat Stonith destructor...
 */
static void
meatware_destroy(Stonith *s)
{
	struct MeatDevice* nd;

	if (!ISMeatDEV(s)) {
		syslog(LOG_ERR, "%s: invalid argument", __FUNCTION__);
		return;
	}
	nd = (struct MeatDevice *)s->pinfo;

	nd->Meatid = NOTMeatID;
	if (nd->hostlist) {
		meatware_free_hostlist(nd->hostlist);
		nd->hostlist = NULL;
	}
	nd->hostcount = -1;
	FREE(nd);
}

/* Create a new Meatware Stonith device. */

static void *
meatware_new(void)
{
	struct MeatDevice*	nd = MALLOCT(struct MeatDevice);

	if (nd == NULL) {
		syslog(LOG_ERR, "out of memory");
		return(NULL);
	}
	memset(nd, 0, sizeof(*nd));
	nd->Meatid = Meatid;
	nd->hostlist = NULL;
	nd->hostcount = -1;
	return((void *)nd);
}
