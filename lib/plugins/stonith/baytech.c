/*
 *	Stonith module for BayTech Remote Power Controllers (RPC-x devices)
 *
 *	Copyright (c) 2000 Alan Robertson <alanr@unix.sh>
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
#define PIL_PLUGIN              baytech
#define PIL_PLUGIN_S            "baytech"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

#include "stonith_signal.h"

/*
 * baytechclosepi is called as part of unloading the baytech STONITH plugin.
 * If there was any global data allocated, or file descriptors opened, etc.
 * which is associated with the plugin, and not a single interface
 * in particular, here's our chance to clean it up.
 */

static void
baytechclosepi(PILPlugin*pi)
{
}


/*
 * baytechcloseintf called as part of shutting down the baytech STONITH
 * interface.  If there was any global data allocated, or file descriptors
 * opened, etc.  which is associated with the baytech implementation,
 * here's our chance to clean it up.
 */
static PIL_rc
baytechcloseintf(PILInterface* pi, void* pd)
{
	return PIL_OK;
}

static void *		baytech_new(void);
static void		baytech_destroy(Stonith *);
static int		baytech_set_config_file(Stonith *, const char * cfgname);
static int		baytech_set_config_info(Stonith *, const char * info);
static const char *	baytech_getinfo(Stonith * s, int InfoType);
static int		baytech_status(Stonith * );
static int		baytech_reset_req(Stonith * s, int request, const char * host);
static char **		baytech_hostlist(Stonith  *);
static void		baytech_free_hostlist(char **);

static struct stonith_ops baytechOps ={
	baytech_new,		/* Create new STONITH object	*/
	baytech_destroy,		/* Destroy STONITH object	*/
	baytech_set_config_file,	/* set configuration from file	*/
	baytech_set_config_info,	/* Get configuration from file	*/
	baytech_getinfo,		/* Return STONITH info string	*/
	baytech_status,			/* Return STONITH device status	*/
	baytech_reset_req,		/* Request a reset */
	baytech_hostlist,		/* Return list of supported hosts */
	baytech_free_hostlist		/* free above list */
};

PIL_PLUGIN_BOILERPLATE("1.0", Debug, baytechclosepi);
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
	,	&baytechOps
	,	baytechcloseintf		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

#define	DEVICE	"BayTech power switch"

#define N_(text)	(text)
#define _(text)		dgettext(ST_TEXTDOMAIN, text)

/*
 *	I have an RPC-5.  This code has been tested with this switch.
 *
 *	The BayTech switches are quite nice, but the dialogues are a bit of a
 *	pain for mechanical parsing.
 */

struct BayTech {
	const char *			BTid;
	char *				idinfo;
	char *				unitid;
	const struct BayTechModelInfo*	modelinfo;
	pid_t				pid;
	int				rdfd;
	int				wrfd;
	int				config;
	char *				device;
	char *				user;
	char *				passwd;
};

struct BayTechModelInfo {
		const char *	type;		/* Baytech model info */
		int		socklen;	/* Length of socket name string */
		struct Etoken *	expect;		/* Expect string before outlet list */
};

static const char * BTid = "BayTech-Stonith";
static const char * NOTbtid = "Hey, dummy this has been destroyed (BayTech)";

#define	ISBAYTECH(i)	(((i)!= NULL && (i)->pinfo != NULL)	\
	&& ((struct BayTech *)(i->pinfo))->BTid == BTid)

#define	ISCONFIGED(i)	(ISBAYTECH(i) && ((struct BayTech *)(i->pinfo))->config)

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
#define WHITESPACE	" \t\n\r\f"

#define	REPLSTR(s,v)	{					\
			if ((s) != NULL) {			\
				FREE(s);			\
				(s)=NULL;			\
			}					\
			(s) = MALLOC(strlen(v)+1);		\
			if ((s) == NULL) {			\
				syslog(LOG_ERR, _("out of memory"));\
			}else{					\
				strcpy((s),(v));		\
			}					\
			}

/*
 *	Different expect strings that we get from the Baytech
 *	Remote Power Controllers...
 */

#define BAYTECHASSOC	"Bay Technical Associates"

static struct Etoken EscapeChar[] =	{ {"Escape character is '^]'.", 0, 0}
					,	{NULL,0,0}};
static struct Etoken BayTechAssoc[] =	{ {BAYTECHASSOC, 0, 0}, {NULL,0,0}};
static struct Etoken UnitId[] =		{ {"Unit ID: ", 0, 0}, {NULL,0,0}};
static struct Etoken login[] =		{ {"username>", 0, 0} ,{NULL,0,0}};
static struct Etoken password[] =	{ {"password>", 0, 0}
					, {"username>", 0, 0} ,{NULL,0,0}};
static struct Etoken Selection[] =	{ {"election>", 0, 0} ,{NULL,0,0}};
static struct Etoken RPC[] =		{ {"RPC", 0, 0} ,{NULL,0,0}};
static struct Etoken LoginOK[] =	{ {"RPC", 0, 0}, {"Invalid password", 1, 0}
					,	{NULL,0,0}};
static struct Etoken GTSign[] =		{ {">", 0, 0} ,{NULL,0,0}};
static struct Etoken Menu[] =		{ {"Menu:", 0, 0} ,{NULL,0,0}};
static struct Etoken Temp[] =		{ {"emperature: ", 0, 0}
					,	{NULL,0,0}};
static struct Etoken Break[] =		{ {"reaker: ", 0, 0}
					,	{NULL,0,0}};
static struct Etoken PowerApplied[] =	{ {"ower applied to outlet", 0, 0}
					,	{NULL,0,0}};
/* Accept either a CR/NL or an NL/CR */
static struct Etoken CRNL[] =		{ {"\n\r",0,0},{"\r\n",0,0},{NULL,0,0}};

/* We may get a notice about rebooting, or a request for confirmation */
static struct Etoken Rebooting[] =	{ {"ebooting selected outlet", 0, 0}
				,	{"(Y/N)>", 1, 0}
				,	{"already off.", 2, 0}
				,	{NULL,0,0}};


static struct BayTechModelInfo ModelInfo [] = {
		{"RPC-5", 18, Temp},	/* This first model will be the default */
		{"RPC-3", 10, Break},	
		{"RPC-3A", 10, Break},
		{NULL, 0, NULL},
};

static int	RPCLookFor(struct BayTech* bt, struct Etoken * tlist, int timeout);
static int	RPC_connect_device(struct BayTech * bt);
static int	RPCLogin(struct BayTech * bt);
static int	RPCRobustLogin(struct BayTech * bt);
static int	RPCNametoOutlet(struct BayTech*, const char * name);
static int	RPCReset(struct BayTech*, int unitnum, const char * rebootid);
static int	RPCScanLine(struct BayTech* bt, int timeout, char * buf, int max);
static int	RPCLogout(struct BayTech * bt);
static void	RPCkillcomm(struct BayTech * bt);


static int	RPC_parse_config_info(struct BayTech* bt, const char * info);
#if defined(ST_POWERON) && defined(ST_POWEROFF)
static int	RPC_onoff(struct BayTech*, int unitnum, const char * unitid
,		int request);
#endif

/*
 *	We do these things a lot.  Here are a few shorthand macros.
 */

#define	SEND(s)	(write(bt->wrfd, (s), strlen(s)))

#define	EXPECT(p,t)	{						\
			if (RPCLookFor(bt, p, t) < 0)			\
				return(errno == ETIMEDOUT			\
			?	S_TIMEOUT : S_OOPS);			\
			}

#define	NULLEXPECT(p,t)	{						\
				if (RPCLookFor(bt, p, t) < 0)		\
					return(NULL);			\
			}

#define	SNARF(s, to)	{						\
				if (RPCScanLine(bt,to,(s),sizeof(s))	\
				!=	S_OK)				\
					return(S_OOPS);			\
			}

#define	NULLSNARF(s, to)	{					\
				if (RPCScanLine(bt,to,(s),sizeof(s))	\
				!=	S_OK)				\
					return(NULL);			\
				}

/* Look for any of the given patterns.  We don't care which */

#define	MAXSAVE	512
static int
RPCLookFor(struct BayTech* bt, struct Etoken * tlist, int timeout)
{
	int	rc;
	char	savebuf[MAXSAVE];
	savebuf[MAXSAVE-1] = EOS;
	savebuf[0] = EOS;

	if ((rc = EXPECT_TOK(bt->rdfd, tlist, timeout, savebuf, MAXSAVE)) < 0){
		syslog(LOG_ERR, _("Did not find string: '%s' from " DEVICE ".")
		,	tlist[0].string);
		syslog(LOG_ERR, _("Got '%s' from " DEVICE " instead.")
		,	savebuf);
		RPCkillcomm(bt);
		return(-1);
	}
#if 0
	syslog(LOG_INFO
	,	"BayTech: Expecting [%s] Received [%s]"
	,	tlist[0].string
	,	savebuf);
#endif
	return(rc);
}

/* Read and return the rest of the line */

static int
RPCScanLine(struct BayTech* bt, int timeout, char * buf, int max)
{
	if (EXPECT_TOK(bt->rdfd, CRNL, timeout, buf, max) < 0) {
		syslog(LOG_ERR, ("Could not read line from " DEVICE "."));
		RPCkillcomm(bt);
		bt->pid = -1;
		return(S_OOPS);
	}
	return(S_OK);
}

/* Login to the Baytech Remote Power Controller (RPC) */

static int
RPCLogin(struct BayTech * bt)
{
	char		IDinfo[128];
	static char	IDbuf[128];
	char *		idptr = IDinfo;
	char *		delim;
	int		j;


	EXPECT(EscapeChar, 10);
	/* Look for the unit type info */
	if (EXPECT_TOK(bt->rdfd, BayTechAssoc, 2, IDinfo
	,	sizeof(IDinfo)) < 0) {
		syslog(LOG_ERR, _("No initial response from " DEVICE "."));
		RPCkillcomm(bt);
		return(errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS);
	}
	idptr += strspn(idptr, WHITESPACE);
	/*
	 * We should be looking at something like this:
         *	RPC-5 Telnet Host
    	 *	Revision F 4.22, (C) 1999
    	 *	Bay Technical Associates
	 */

	/* Truncate the result after the RPC-5 part */
	if ((delim = strchr(idptr, ' ')) != NULL) {
		*delim = EOS;
	}
	snprintf(IDbuf, sizeof(IDbuf), "BayTech %s", idptr);
	REPLSTR(bt->idinfo, IDbuf);

	bt->modelinfo = &ModelInfo[0];

	for (j=0; ModelInfo[j].type != NULL; ++j) {
		/*
		 * TIMXXX - 
		 * Look at device ID as this really describes the model.
		 */
		if (strcasecmp(ModelInfo[j].type, idptr) == 0) {
			bt->modelinfo = &ModelInfo[j];
			break;
		}
	}

	/* Look for the unit id info */
	EXPECT(UnitId, 10);
	SNARF(IDbuf, 2);
	delim = IDbuf + strcspn(IDbuf, WHITESPACE);
	*delim = EOS;
	REPLSTR(bt->unitid, IDbuf);

	/* Expect "username>" */
	EXPECT(login, 2);

	SEND(bt->user);
	SEND("\r");

	/* Expect "password>" */

	switch (RPCLookFor(bt, password, 5)) {
		case 0:	/* Good! */
			break;

		case 1:	/* OOPS!  got another username prompt */
			syslog(LOG_ERR, _("Invalid username for " DEVICE "."));
			return(S_ACCESS);

		default:
			return(errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS);
	}

	SEND(bt->passwd);
	SEND("\r");

	/* Expect "RPC-x Menu" */

	switch (RPCLookFor(bt, LoginOK, 5)) {

		case 0:	/* Good! */
			break;

		case 1:	/* Uh-oh - bad password */
			syslog(LOG_ERR, _("Invalid password for " DEVICE "."));
			return(S_ACCESS);

		default:
			RPCkillcomm(bt);
			return(errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS);
	}
	EXPECT(Menu, 2);

	return(S_OK);
}

static int
RPCRobustLogin(struct BayTech * bt)
{
	int	rc=S_OOPS;
	int	j;

	for (j=0; j < 20 && rc != S_OK; ++j) {

		if (bt->pid > 0) {
			RPCkillcomm(bt);
		}

		if (RPC_connect_device(bt) != S_OK) {
			RPCkillcomm(bt);
			continue;
		}

		rc = RPCLogin(bt);
	}
	return rc;
}

/* Log out of the Baytech RPC */

static int
RPCLogout(struct BayTech* bt)
{
	int	rc;

	/* Make sure we're in the right menu... */
	SEND("\r");

	/* Expect "Selection>" */
	rc = RPCLookFor(bt, Selection, 5);

	/* Option 6 is Logout */
	SEND("6\r");

	close(bt->wrfd);
	close(bt->rdfd);
	bt->wrfd = bt->rdfd = -1;
	RPCkillcomm(bt);
	return(rc >= 0 ? S_OK : (errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS));
}
static void
RPCkillcomm(struct BayTech* bt)
{
	if (bt->pid > 0) {
		STONITH_KILL(bt->pid, SIGKILL);
		(void)waitpid(bt->pid, NULL, 0);
		bt->pid = -1;
	}
}

/* Reset (power-cycle) the given outlet number */
static int
RPCReset(struct BayTech* bt, int unitnum, const char * rebootid)
{
	char		unum[32];


	SEND("\r");

	/* Make sure we're in the top level menu */

	/* Expect "RPC-x Menu" */
	EXPECT(RPC, 5);
	EXPECT(Menu, 5);

	/* OK.  Request sub-menu 1 (Outlet Control) */
	SEND("1\r");

	/* Verify that we're in the sub-menu */

	/* Expect: "RPC-x>" */
	EXPECT(RPC, 5);
	EXPECT(GTSign, 5);


	/* Send REBOOT command for given outlet */
	snprintf(unum, sizeof(unum), "REBOOT %d\r", unitnum);
	SEND(unum);

	/* Expect "ebooting "... or "(Y/N)" (if confirmation turned on) */

	retry:
	switch (RPCLookFor(bt, Rebooting, 5)) {
		case 0: /* Got "Rebooting" Do nothing */
			break;

		case 1: /* Got that annoying command confirmation :-( */
			SEND("Y\r");
			goto retry;

		case 2:	/* Outlet is turned off */
			syslog(LOG_ERR, _("Host %s is OFF."), rebootid);
			return(S_ISOFF);

		default:
			return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}
	syslog(LOG_INFO, _("Host %s being rebooted."), rebootid);

	/* Expect "ower applied to outlet" */
	if (RPCLookFor(bt, PowerApplied, 30) < 0) {
		return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}

	/* All Right!  Power is back on.  Life is Good! */

	syslog(LOG_INFO, _("Power restored to host %s."), rebootid);

	/* Expect: "RPC-x>" */
	EXPECT(RPC,5);
	EXPECT(GTSign, 5);

	/* Pop back to main menu */
	SEND("MENU\r");
	return(S_OK);
}

#if defined(ST_POWERON) && defined(ST_POWEROFF)
static int
RPC_onoff(struct BayTech* bt, int unitnum, const char * unitid, int req)
{
	char		unum[32];

	const char *	onoff = (req == ST_POWERON ? "on" : "off");
	int	rc;


	if ((rc = RPCRobustLogin(bt) != S_OK)) {
		syslog(LOG_ERR, _("Cannot log into " DEVICE "."));
		return(rc);
	}
	SEND("\r");

	/* Make sure we're in the top level menu */

	/* Expect "RPC-x Menu" */
	EXPECT(RPC, 5);
	EXPECT(Menu, 5);

	/* OK.  Request sub-menu 1 (Outlet Control) */
	SEND("1\r");

	/* Verify that we're in the sub-menu */

	/* Expect: "RPC-x>" */
	EXPECT(RPC, 5);
	EXPECT(GTSign, 5);


	/* Send ON/OFF command for given outlet */
	snprintf(unum, sizeof(unum), "%s %d\r"
	,	onoff, unitnum);
	SEND(unum);

	/* Expect "RPC->x "... or "(Y/N)" (if confirmation turned on) */

	if (RPCLookFor(bt, RPC, 5) == 1) {
		/* They've turned on that annoying command confirmation :-( */
		SEND("Y\r");
		EXPECT(RPC, 5);
	}

	EXPECT(GTSign, 5);

	/* All Right!  Command done. Life is Good! */
	syslog(LOG_NOTICE, _("Power to host %s turned %s."), unitid, onoff);
	/* Pop back to main menu */
	SEND("MENU\r");
	return(S_OK);
}
#endif /* defined(ST_POWERON) && defined(ST_POWEROFF) */

/*
 *	Map the given host name into an (AC) Outlet number on the power strip
 */

static int
RPCNametoOutlet(struct BayTech* bt, const char * name)
{
	char	NameMapping[128];
	int	sockno;
	char	sockname[32];
	int	ret = -1;
	char	format[32];


	snprintf(format, sizeof(format), "%%7d       %%%dc"
	,	bt->modelinfo->socklen);

	/* Verify that we're in the top-level menu */
	SEND("\r");

	/* Expect "RPC-x Menu" */
	EXPECT(RPC, 5);
	EXPECT(Menu, 5);


	/* OK.  Request sub-menu 1 (Outlet Control) */
	SEND("1\r");

	/* Verify that we're in the sub-menu */

	/* Expect: "RPC-x>" */
	EXPECT(RPC, 5);
	EXPECT(GTSign, 5);

	/* The status command output contains mapping of hosts to outlets */
	SEND("STATUS\r");

	/* Expect: "emperature:" so we can skip over it... */
	EXPECT(bt->modelinfo->expect, 5);
	EXPECT(CRNL, 5);

	/* Looks Good!  Parse the status output */

	do {
		NameMapping[0] = EOS;
		SNARF(NameMapping, 5);
		if (sscanf(NameMapping, format, &sockno, sockname) == 2) {

			char *	last = sockname+bt->modelinfo->socklen;
			*last = EOS;
			--last;

			/* Strip off trailing blanks */
			for(; last > sockname; --last) {
				if (*last == ' ') {
					*last = EOS;
				}else{
					break;
				}
			}
			if (strcmp(name, sockname) == 0) {
				ret = sockno;
			}
		}
	} while (strlen(NameMapping) > 2 && ret < 0);

	/* Pop back out to the top level menu */
	SEND("MENU\r");
	return(ret);
}

static int
baytech_status(Stonith  *s)
{
	struct BayTech*	bt;
	int	rc;

	if (!ISBAYTECH(s)) {
		syslog(LOG_ERR, "invalid argument to RPC_status");
		return(S_OOPS);
	}
	if (!ISCONFIGED(s)) {
		syslog(LOG_ERR
		,	"unconfigured stonith object in RPC_status");
		return(S_OOPS);
	}
	bt = (struct BayTech*) s->pinfo;

	if ((rc = RPCRobustLogin(bt) != S_OK)) {
		syslog(LOG_ERR, _("Cannot log into " DEVICE "."));
		return(rc);
	}

	/* Verify that we're in the top-level menu */
	SEND("\r");

	/* Expect "RPC-x Menu" */
	EXPECT(RPC, 5);
	EXPECT(Menu, 5);

	return(RPCLogout(bt));
}
/*
 *	Return the list of hosts (outlet names) for the devices on this BayTech unit
 */

static char **
baytech_hostlist(Stonith  *s)
{
	char		NameMapping[128];
	char*		NameList[64];
	unsigned int	numnames = 0;
	char **		ret = NULL;
	struct BayTech*	bt;
	char		format[32];


	if (!ISBAYTECH(s)) {
		syslog(LOG_ERR, "invalid argument to baytech_hostlist");
		return(NULL);
	}
	if (!ISCONFIGED(s)) {
		syslog(LOG_ERR
		,	"unconfigured stonith object in baytech_hostlist");
		return(NULL);
	}
	bt = (struct BayTech*) s->pinfo;


	snprintf(format, sizeof(format), "%%7d       %%%dc"
	,	bt->modelinfo->socklen);

	if (RPCRobustLogin(bt) != S_OK) {
		syslog(LOG_ERR, _("Cannot log into " DEVICE "."));
		return(NULL);
	}

	/* Verify that we're in the top-level menu */
	SEND("\r");

	/* Expect "RPC-x Menu" */
	NULLEXPECT(RPC, 5);
	NULLEXPECT(Menu, 5);


	/* OK.  Request sub-menu 1 (Outlet Control) */
	SEND("1\r");

	/* Verify that we're in the sub-menu */

	/* Expect: "RPC-x>" */
	NULLEXPECT(RPC, 5);
	NULLEXPECT(GTSign, 5);

	/* The status command output contains mapping of hosts to outlets */
	SEND("STATUS\r");

	/* Expect: "emperature:" so we can skip over it... */
	NULLEXPECT(bt->modelinfo->expect, 5);
	NULLEXPECT(CRNL, 5);

	/* Looks Good!  Parse the status output */

	do {
		int	sockno;
		char	sockname[64];
		NameMapping[0] = EOS;
		NULLSNARF(NameMapping, 5);
		if (sscanf(NameMapping, format, &sockno, sockname) == 2) {

			char *	last = sockname+bt->modelinfo->socklen;
			char *	nm;
			*last = EOS;
			--last;

			/* Strip off trailing blanks */
			for(; last > sockname; --last) {
				if (*last == ' ') {
					*last = EOS;
				}else{
					break;
				}
			}
			if (numnames >= DIMOF(NameList)-1) {
				break;
			}
			if ((nm = (char*)MALLOC(strlen(sockname)+1)) == NULL) {
				syslog(LOG_ERR, "out of memory");
				return(NULL);
			}
			strcpy(nm, sockname);
			NameList[numnames] = nm;
			++numnames;
			NameList[numnames] = NULL;
		}
	} while (strlen(NameMapping) > 2);

	/* Pop back out to the top level menu */
	SEND("MENU\r");
	if (numnames >= 1) {
		ret = (char **)MALLOC((numnames+1)*sizeof(char*));
		if (ret == NULL) {
			syslog(LOG_ERR, "out of memory");
		}else{
			memcpy(ret, NameList, (numnames+1)*sizeof(char*));
		}
	}
	(void)RPCLogout(bt);
	return(ret);
}

static void
baytech_free_hostlist (char ** hlist)
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
}


/*
 *	Parse the given configuration information, and stash it away...
 */

static int
RPC_parse_config_info(struct BayTech* bt, const char * info)
{
	static char dev[1024];
	static char user[1024];
	static char passwd[1024];

	if (bt->config) {
		return(S_OOPS);
	}


	if (sscanf(info, "%s %s %[^\n\r\t]", dev, user, passwd) == 3
	&&	strlen(passwd) > 1) {

		if ((bt->device = (char *)MALLOC(strlen(dev)+1)) == NULL) {
			syslog(LOG_ERR, "out of memory");
			return(S_OOPS);
		}
		if ((bt->user = (char *)MALLOC(strlen(user)+1)) == NULL) {
			free(bt->device);
			bt->device=NULL;
			syslog(LOG_ERR, "out of memory");
			return(S_OOPS);
		}
		if ((bt->passwd = (char *)MALLOC(strlen(passwd)+1)) == NULL) {
			free(bt->user);
			bt->user=NULL;
			free(bt->device);
			bt->device=NULL;
			syslog(LOG_ERR, "out of memory");
			return(S_OOPS);
		}
		strcpy(bt->device, dev);
		strcpy(bt->user, user);
		strcpy(bt->passwd, passwd);
		bt->config = 1;
		return(S_OK);
	}
	return(S_BADCONFIG);
}

/*
 *	Connect to the given BayTech device.  We should add serial support here
 *	eventually...
 */
static int
RPC_connect_device(struct BayTech * bt)
{
	char	TelnetCommand[256];

	snprintf(TelnetCommand, sizeof(TelnetCommand)
	,	"exec telnet %s 2>/dev/null", bt->device);

	bt->pid=STARTPROC(TelnetCommand, &bt->rdfd, &bt->wrfd);
	if (bt->pid <= 0) {
		return(S_OOPS);
	}
	return(S_OK);
}

/*
 *	Reset the given host on this Stonith device.
 */
static int
baytech_reset_req(Stonith * s, int request, const char * host)
{
	int	rc = 0;
	int	lorc = 0;
	struct BayTech*	bt;

	if (!ISBAYTECH(s)) {
		syslog(LOG_ERR, "invalid argument to baytech_reset");
		return(S_OOPS);
	}
	if (!ISCONFIGED(s)) {
		syslog(LOG_ERR
		,	"unconfigured stonith object in baytech_reset");
		return(S_OOPS);
	}
	bt = (struct BayTech*) s->pinfo;


	if ((rc = RPCRobustLogin(bt)) != S_OK) {
		syslog(LOG_ERR, _("Cannot log into " DEVICE "."));
	}else{
		int	noutlet;
		noutlet = RPCNametoOutlet(bt, host);

		if (noutlet < 1) {
			syslog(LOG_WARNING, _("%s %s "
			"doesn't control host [%s]."), bt->idinfo
			,	bt->unitid, host);
			RPCkillcomm(bt);
			return(S_BADHOST);
		}
		switch(request) {

#if defined(ST_POWERON) && defined(ST_POWEROFF)
		case ST_POWERON:
		case ST_POWEROFF:
			rc = RPC_onoff(bt, noutlet, host, request);
			break;
#endif
		case ST_GENERIC_RESET:
			rc = RPCReset(bt, noutlet, host);
			break;
		default:
			rc = S_INVAL;
			break;
		}
	}

	lorc = RPCLogout(bt);
	RPCkillcomm(bt);

	return(rc != S_OK ? rc : lorc);
}

/*
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */
static int
baytech_set_config_file(Stonith* s, const char * configname)
{
	FILE *	cfgfile;

	char	RPCid[256];

	struct BayTech*	bt;

	if (!ISBAYTECH(s)) {
		syslog(LOG_ERR, "invalid argument to baytech_set");
		return(S_OOPS);
	}
	bt = (struct BayTech*) s->pinfo;

	if ((cfgfile = fopen(configname, "r")) == NULL)  {
		syslog(LOG_ERR, _("Cannot open %s"), configname);
		return(S_BADCONFIG);
	}
	while (fgets(RPCid, sizeof(RPCid), cfgfile) != NULL){
		if (*RPCid == '#' || *RPCid == '\n' || *RPCid == EOS) {
			continue;
		}
		return(RPC_parse_config_info(bt, RPCid));
	}
	return(S_BADCONFIG);
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
baytech_set_config_info(Stonith* s, const char * info)
{
	struct BayTech* bt;

	if (!ISBAYTECH(s)) {
		syslog(LOG_ERR, "baytech_set_config_info: invalid argument");
		return(S_OOPS);
	}
	bt = (struct BayTech *)s->pinfo;

	return(RPC_parse_config_info(bt, info));
}

static const char *
baytech_getinfo(Stonith * s, int reqtype)
{
	struct BayTech* bt;
	const char *		ret;

	if (!ISBAYTECH(s)) {
		syslog(LOG_ERR, "RPC_idinfo: invalid argument");
		return NULL;
	}
	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	bt = (struct BayTech *)s->pinfo;

	switch (reqtype) {

		case ST_DEVICEID:		/* Exactly what type of device? */
			ret = bt->idinfo;
			break;

		case ST_DEVICENAME:		/* Which particular individual device? */
			ret = bt->device;
			break;

		case ST_CONF_INFO_SYNTAX:
			ret = _("IP-address login password\n"
			"The IP-address and login are white-space delimited.");
			break;

		case ST_CONF_FILE_SYNTAX:
			ret = _("IP-address login password\n"
			"The IP-address and login are white-space delimited.  "
			"All three items must be on one line.  "
			"Blank lines and lines beginning with # are ignored");
			break;

		case ST_DEVICEDESCR:		/* Description of device type */
			ret = _("Bay Technical Associates (Baytech) RPC "
			"series power switches (via telnet).\n"
			"The RPC-5, RPC-3 and RPC-3A switches are well tested.");
			break;

		case ST_DEVICEURL:		/* Manufacturer's web site */
			ret = "http://www.baytech.net/";
			break;

		default:
			ret = NULL;
			break;
	}
	return ret;
}

/*
 *	Baytech Stonith destructor...
 */
static void
baytech_destroy(Stonith *s)
{
	struct BayTech* bt;

	if (!ISBAYTECH(s)) {
		syslog(LOG_ERR, "baytech_del: invalid argument");
		return;
	}
	bt = (struct BayTech *)s->pinfo;

	bt->BTid = NOTbtid;
	RPCkillcomm(bt);
	if (bt->rdfd >= 0) {
		close(bt->rdfd);
		bt->rdfd = -1;
	}
	if (bt->wrfd >= 0) {
		close(bt->wrfd);
		bt->wrfd = -1;
	}
	if (bt->device != NULL) {
		FREE(bt->device);
		bt->device = NULL;
	}
	if (bt->user != NULL) {
		FREE(bt->user);
		bt->user = NULL;
	}
	if (bt->passwd != NULL) {
		FREE(bt->passwd);
		bt->passwd = NULL;
	}
	if (bt->idinfo != NULL) {
		FREE(bt->idinfo);
		bt->idinfo = NULL;
	}
	if (bt->unitid != NULL) {
		FREE(bt->unitid);
		bt->unitid = NULL;
	}
}

/* Create a new BayTech Stonith device. */

static void *
baytech_new(void)
{
	struct BayTech*	bt = MALLOCT(struct BayTech);

	if (bt == NULL) {
		syslog(LOG_ERR, "out of memory");
		return(NULL);
	}
	memset(bt, 0, sizeof(*bt));
	bt->BTid = BTid;
	bt->pid = -1;
	bt->rdfd = -1;
	bt->wrfd = -1;
	bt->config = 0;
	bt->user = NULL;
	bt->device = NULL;
	bt->passwd = NULL;
	bt->idinfo = NULL;
	bt->unitid = NULL;
	REPLSTR(bt->idinfo, DEVICE);
	bt->modelinfo = &ModelInfo[0];

	return((void *)bt);
}
