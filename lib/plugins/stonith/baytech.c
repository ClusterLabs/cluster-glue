/* $Id: baytech.c,v 1.20 2004/10/24 13:00:14 lge Exp $ */
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

#define	DEVICE	"BayTech power switch"

#include "stonith_plugin_common.h"

#define PIL_PLUGIN              baytech
#define PIL_PLUGIN_S            "baytech"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

#include "stonith_signal.h"

static void *		baytech_new(void);
static void		baytech_destroy(Stonith *);
static int		baytech_set_config_file(Stonith *, const char * cfgname);
static int		baytech_set_config_info(Stonith *, const char * info);
static const char *	baytech_getinfo(Stonith * s, int InfoType);
static int		baytech_status(Stonith * );
static int		baytech_reset_req(Stonith * s, int request, const char * host);
static char **		baytech_hostlist(Stonith  *);

static struct stonith_ops baytechOps ={
	baytech_new,		/* Create new STONITH object	*/
	baytech_destroy,		/* Destroy STONITH object	*/
	baytech_set_config_file,	/* set configuration from file	*/
	baytech_set_config_info,	/* Get configuration from file	*/
	baytech_getinfo,		/* Return STONITH info string	*/
	baytech_status,			/* Return STONITH device status	*/
	baytech_reset_req,		/* Request a reset */
	baytech_hostlist,		/* Return list of supported hosts */
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug)
static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static StonithImports*		OurImports;
static void*			interfprivate;

#include "stonith_expect_helpers.h"

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
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*
 *	I have an RPC-5.  This code has been tested with this switch.
 *
 *	The BayTech switches are quite nice, but the dialogues are a bit of a
 *	pain for mechanical parsing.
 */

struct pluginDevice {
	const char *			pluginid;
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
	size_t		socklen;	/* Length of socket name string */
	struct Etoken *	expect;		/* Expect string before outlet list */
};

static int		parse_socket_line(struct pluginDevice*,const char *
,			int *, char *);

static const char * pluginid = "BayTech-Stonith";
static const char * NOTpluginID = "Hey, dummy this has been destroyed (BayTech)";

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

static int	RPC_connect_device(struct pluginDevice * bt);
static int	RPCLogin(struct pluginDevice * bt);
static int	RPCRobustLogin(struct pluginDevice * bt);
static int	RPCNametoOutlet(struct pluginDevice*, const char * name);
static int	RPCReset(struct pluginDevice*, int unitnum, const char * rebootid);
static int	RPCLogout(struct pluginDevice * bt);


static int	RPC_parse_config_info(struct pluginDevice* bt, const char * info);
#if defined(ST_POWERON) && defined(ST_POWEROFF)
static int	RPC_onoff(struct pluginDevice*, int unitnum, const char * unitid
,		int request);
#endif

/* Login to the Baytech Remote Power Controller (RPC) */

static int
RPCLogin(struct pluginDevice * bt)
{
	char		IDinfo[128];
	static char	IDbuf[128];
	char *		idptr = IDinfo;
	char *		delim;
	int		j;


	EXPECT(bt->rdfd, EscapeChar, 10);
	/* Look for the unit type info */
	if (EXPECT_TOK(bt->rdfd, BayTechAssoc, 2, IDinfo
	,	sizeof(IDinfo)) < 0) {
		LOG(PIL_CRIT,	 "%s",
			   _("No initial response from " DEVICE "."));
		Stonithkillcomm(&bt->rdfd, &bt->wrfd, &bt->pid);
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
	EXPECT(bt->rdfd, UnitId, 10);
	SNARF(bt->rdfd, IDbuf, 2);
	delim = IDbuf + strcspn(IDbuf, WHITESPACE);
	*delim = EOS;
	REPLSTR(bt->unitid, IDbuf);

	/* Expect "username>" */
	EXPECT(bt->rdfd, login, 2);

	SEND(bt->wrfd, bt->user);
	SEND(bt->wrfd, "\r");

	/* Expect "password>" */

	switch (StonithLookFor(bt->rdfd, password, 5)) {
		case 0:	/* Good! */
			break;

		case 1:	/* OOPS!  got another username prompt */
			LOG(PIL_CRIT,	"%s",
				   _("Invalid username for " DEVICE "."));
			return(S_ACCESS);

		default:
			return(errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS);
	}

	SEND(bt->wrfd, bt->passwd);
	SEND(bt->wrfd, "\r");

	/* Expect "RPC-x Menu" */

	switch (StonithLookFor(bt->rdfd, LoginOK, 5)) {

		case 0:	/* Good! */
			break;

		case 1:	/* Uh-oh - bad password */
			LOG(PIL_CRIT,	"%s",
				   _("Invalid password for " DEVICE "."));
			return(S_ACCESS);

		default:
			Stonithkillcomm(&bt->rdfd, &bt->wrfd, &bt->pid);
			return(errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS);
	}
	EXPECT(bt->rdfd, Menu, 2);

	return(S_OK);
}

static int
RPCRobustLogin(struct pluginDevice * bt)
{
	int	rc=S_OOPS;
	int	j;

	for (j=0; j < 20 && rc != S_OK; ++j) {

		if (bt->pid > 0) {
			Stonithkillcomm(&bt->rdfd, &bt->wrfd, &bt->pid);
		}

		if (RPC_connect_device(bt) != S_OK) {
			Stonithkillcomm(&bt->rdfd, &bt->wrfd, &bt->pid);
			continue;
		}

		rc = RPCLogin(bt);
	}
	return rc;
}

/* Log out of the Baytech RPC */

static int
RPCLogout(struct pluginDevice* bt)
{
	int	rc;

	/* Make sure we're in the right menu... */
	SEND(bt->wrfd, "\r");

	/* Expect "Selection>" */
	rc = StonithLookFor(bt->rdfd, Selection, 5);

	/* Option 6 is Logout */
	SEND(bt->wrfd, "6\r");

	close(bt->wrfd);
	close(bt->rdfd);
	bt->wrfd = bt->rdfd = -1;
	Stonithkillcomm(&bt->rdfd, &bt->wrfd, &bt->pid);
	return(rc >= 0 ? S_OK : (errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS));
}

/* Reset (power-cycle) the given outlet number */
static int
RPCReset(struct pluginDevice* bt, int unitnum, const char * rebootid)
{
	char		unum[32];


	SEND(bt->wrfd, "\r");

	/* Make sure we're in the top level menu */

	/* Expect "RPC-x Menu" */
	EXPECT(bt->rdfd, RPC, 5);
	EXPECT(bt->rdfd, Menu, 5);

	/* OK.  Request sub-menu 1 (Outlet Control) */
	SEND(bt->wrfd, "1\r");

	/* Verify that we're in the sub-menu */

	/* Expect: "RPC-x>" */
	EXPECT(bt->rdfd, RPC, 5);
	EXPECT(bt->rdfd, GTSign, 5);


	/* Send REBOOT command for given outlet */
	snprintf(unum, sizeof(unum), "REBOOT %d\r", unitnum);
	SEND(bt->wrfd, unum);

	/* Expect "ebooting "... or "(Y/N)" (if confirmation turned on) */

	retry:
	switch (StonithLookFor(bt->rdfd, Rebooting, 5)) {
		case 0: /* Got "Rebooting" Do nothing */
			break;

		case 1: /* Got that annoying command confirmation :-( */
			SEND(bt->wrfd, "Y\r");
			goto retry;

		case 2:	/* Outlet is turned off */
			LOG(PIL_CRIT,	"%s: %s.",
				   _("Host is OFF"), rebootid);
			return(S_ISOFF);

		default:
			return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}
	LOG(PIL_INFO,	"%s: %s",
		   _("Host being rebooted"), rebootid);
	
	/* Expect "ower applied to outlet" */
	if (StonithLookFor(bt->rdfd, PowerApplied, 30) < 0) {
		return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}

	/* All Right!  Power is back on.  Life is Good! */
	
	LOG(PIL_INFO,	"%s: %s",
		   _("Power restored to host"), rebootid);

	/* Expect: "RPC-x>" */
	EXPECT(bt->rdfd, RPC,5);
	EXPECT(bt->rdfd, GTSign, 5);

	/* Pop back to main menu */
	SEND(bt->wrfd, "MENU\r");
	return(S_OK);
}

#if defined(ST_POWERON) && defined(ST_POWEROFF)
static int
RPC_onoff(struct pluginDevice* bt, int unitnum, const char * unitid, int req)
{
	char		unum[32];

	const char *	onoff = (req == ST_POWERON ? "on" : "off");
	int	rc;


	if ((rc = RPCRobustLogin(bt) != S_OK)) {
		LOG(PIL_CRIT,	"%s",
			   _("Cannot log into " DEVICE "."));
		return(rc);
	}
	SEND(bt->wrfd, "\r");

	/* Make sure we're in the top level menu */

	/* Expect "RPC-x Menu" */
	EXPECT(bt->rdfd, RPC, 5);
	EXPECT(bt->rdfd, Menu, 5);

	/* OK.  Request sub-menu 1 (Outlet Control) */
	SEND(bt->wrfd, "1\r");

	/* Verify that we're in the sub-menu */

	/* Expect: "RPC-x>" */
	EXPECT(bt->rdfd, RPC, 5);
	EXPECT(bt->rdfd, GTSign, 5);


	/* Send ON/OFF command for given outlet */
	snprintf(unum, sizeof(unum), "%s %d\r"
	,	onoff, unitnum);
	SEND(bt->wrfd, unum);

	/* Expect "RPC->x "... or "(Y/N)" (if confirmation turned on) */

	if (StonithLookFor(bt->rdfd, RPC, 10) == 1) {
		/* They've turned on that annoying command confirmation :-( */
		SEND(bt->wrfd, "Y\r");
		EXPECT(bt->rdfd, RPC, 10);
	}

	EXPECT(bt->rdfd, GTSign, 10);

	/* All Right!  Command done. Life is Good! */
	LOG(PIL_INFO, "%s %s %s %s",
		   _("Power to host"), unitid, _("turned"), onoff);
	/* Pop back to main menu */
	SEND(bt->wrfd, "MENU\r");
	return(S_OK);
}
#endif /* defined(ST_POWERON) && defined(ST_POWEROFF) */

/*
 *	Map the given host name into an (AC) Outlet number on the power strip
 */

static int
RPCNametoOutlet(struct pluginDevice* bt, const char * name)
{
	char	NameMapping[128];
	int	sockno;
	char	sockname[32];
	int	ret = -1;



	/* Verify that we're in the top-level menu */
	SEND(bt->wrfd, "\r");

	/* Expect "RPC-x Menu" */
	EXPECT(bt->rdfd, RPC, 5);
	EXPECT(bt->rdfd, Menu, 5);


	/* OK.  Request sub-menu 1 (Outlet Control) */
	SEND(bt->wrfd, "1\r");

	/* Verify that we're in the sub-menu */

	/* Expect: "RPC-x>" */
	EXPECT(bt->rdfd, RPC, 5);
	EXPECT(bt->rdfd, GTSign, 5);

	/* The status command output contains mapping of hosts to outlets */
	SEND(bt->wrfd, "STATUS\r");

	/* Expect: "emperature:" so we can skip over it... */
/*  	EXPECT(bt->rdfd, bt->modelinfo->expect, 5); */
/*  	EXPECT(bt->rdfd, CRNL, 5); */

	/* Looks Good!  Parse the status output */

	do {
		char *	last;
		NameMapping[0] = EOS;
		SNARF(bt->rdfd, NameMapping, 5);

		if (!parse_socket_line(bt, NameMapping, &sockno, sockname)) {
			continue;
		}

		last = sockname+bt->modelinfo->socklen;
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
		g_strdown(sockname);
		if (strcmp(name, sockname) == 0) {
			ret = sockno;
		}
	} while (strlen(NameMapping) > 2 && ret < 0);

	/* Pop back out to the top level menu */
	SEND(bt->wrfd, "MENU\r");
	return(ret);
}

static int
baytech_status(Stonith  *s)
{
	struct pluginDevice*	bt;
	int	rc;

	ERRIFNOTCONFIGED(s,S_OOPS);

	bt = (struct pluginDevice*) s->pinfo;
	
	if ((rc = RPCRobustLogin(bt) != S_OK)) {
		LOG(PIL_CRIT,	 "%s", 
			    _("Cannot log into " DEVICE "."));
		return(rc);
	}

	/* Verify that we're in the top-level menu */
	SEND(bt->wrfd, "\r");

	/* Expect "RPC-x Menu" */
	EXPECT(bt->rdfd, RPC, 5);
	EXPECT(bt->rdfd, Menu, 5);

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
	struct pluginDevice*	bt;

	ERRIFNOTCONFIGED(s,NULL);

	bt = (struct pluginDevice*) s->pinfo;
	
	if (RPCRobustLogin(bt) != S_OK) {
		LOG(PIL_CRIT,	"%s",
			   _("Cannot log into " DEVICE "."));
		return(NULL);
	}

	/* Verify that we're in the top-level menu */
	SEND(bt->wrfd, "\r");

	/* Expect "RPC-x Menu" */
	NULLEXPECT(bt->rdfd, RPC, 5);
	NULLEXPECT(bt->rdfd, Menu, 5);

	/* OK.  Request sub-menu 1 (Outlet Control) */
	SEND(bt->wrfd, "1\r");

	/* Verify that we're in the sub-menu */

	/* Expect: "RPC-x>" */
	NULLEXPECT(bt->rdfd, RPC, 5);
	NULLEXPECT(bt->rdfd, GTSign, 5);

	/* The status command output contains mapping of hosts to outlets */
	SEND(bt->wrfd, "STATUS\r");

	/* Expect: "emperature:" so we can skip over it... */
	NULLEXPECT(bt->rdfd, bt->modelinfo->expect, 5);
	NULLEXPECT(bt->rdfd, CRNL, 5);

	/* Looks Good!  Parse the status output */

	do {
		int	sockno;
		char	sockname[64];
		char *	last;
		char *	nm;

		NameMapping[0] = EOS;

		NULLSNARF(bt->rdfd, NameMapping, 5);

		if (!parse_socket_line(bt, NameMapping, &sockno, sockname)) {
			continue;
		}

		last = sockname+bt->modelinfo->socklen;
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
		if ((nm = (char*)STRDUP(sockname)) == NULL) {
			LOG(PIL_CRIT,	"%s",
				   _("out of memory"));
			return(NULL);
		}
		g_strdown(nm);
		NameList[numnames] = nm;
		++numnames;
		NameList[numnames] = NULL;
	} while (strlen(NameMapping) > 2);

	/* Pop back out to the top level menu */
	SEND(bt->wrfd, "MENU\r");
	if (numnames >= 1) {
		ret = (char **)MALLOC((numnames+1)*sizeof(char*));
		if (ret == NULL) {
			LOG(PIL_CRIT,	"%s",
				   _("out of memory"));
		}else{
			memcpy(ret, NameList, (numnames+1)*sizeof(char*));
		}
	}
	(void)RPCLogout(bt);
	return(ret);
}

/*
 *	Parse the given configuration information, and stash it away...
 */

static int
RPC_parse_config_info(struct pluginDevice* bt, const char * info)
{
	static char dev[1024];
	static char user[1024];
	static char passwd[1024];

	if (bt->config) {
		return(S_OOPS);
	}

	if (sscanf(info, "%s %s %[^\n\r\t]", dev, user, passwd) == 3
	&&	strlen(passwd) > 1) {

		if ((bt->device = STRDUP(dev)) == NULL) {
			LOG(PIL_CRIT,	"%s", 
				   _("out of memory"));
			return(S_OOPS);
		}
		if ((bt->user = STRDUP(user)) == NULL) {
			FREE(bt->device);
			bt->device=NULL;
			LOG(PIL_CRIT,	"%s",
				   _("out of memory"));
			return(S_OOPS);
		}
		if ((bt->passwd = STRDUP(passwd)) == NULL) {
			FREE(bt->user);
			bt->user=NULL;
			FREE(bt->device);
			bt->device=NULL;
			LOG(PIL_CRIT,	"%s",
				   _("out of memory"));
			return(S_OOPS);
		}
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
RPC_connect_device(struct pluginDevice * bt)
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
	struct pluginDevice*	bt;

	ERRIFNOTCONFIGED(s,S_OOPS);

	bt = (struct pluginDevice*) s->pinfo;

	if ((rc = RPCRobustLogin(bt)) != S_OK) {
		LOG(PIL_CRIT, "%s",
			   _("Cannot log into " DEVICE "."));
	}else{
		int	noutlet;
		noutlet = RPCNametoOutlet(bt, host);

		if (noutlet < 1) {
			LOG(PIL_WARN,	"%s %s %s [%s]",
					bt->idinfo, bt->unitid, _("doesn't control hot"), host);
			Stonithkillcomm(&bt->rdfd, &bt->wrfd, &bt->pid);
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
	Stonithkillcomm(&bt->rdfd, &bt->wrfd, &bt->pid);

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

	struct pluginDevice*	bt;

	ERRIFWRONGDEV(s,S_OOPS);

	bt = (struct pluginDevice*) s->pinfo;

	if ((cfgfile = fopen(configname, "r")) == NULL)  {
		LOG(PIL_CRIT,	"%s %s",
			   _("Cannot open"), configname);
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
	struct pluginDevice* bt;

	ERRIFWRONGDEV(s,S_OOPS);

	bt = (struct pluginDevice *)s->pinfo;

	return(RPC_parse_config_info(bt, info));
}

static const char *
baytech_getinfo(Stonith * s, int reqtype)
{
	struct pluginDevice* bt;
	const char *		ret;

	ERRIFWRONGDEV(s,NULL);

	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	bt = (struct pluginDevice *)s->pinfo;

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
	struct pluginDevice* bt;

	VOIDERRIFWRONGDEV(s);

	bt = (struct pluginDevice *)s->pinfo;

	bt->pluginid = NOTpluginID;
	Stonithkillcomm(&bt->rdfd, &bt->wrfd, &bt->pid);
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
	struct pluginDevice*	bt = MALLOCT(struct pluginDevice);

	if (bt == NULL) {
		LOG(PIL_CRIT,	"%s",
			   _("out of memory"));
		return(NULL);
	}
	memset(bt, 0, sizeof(*bt));
	bt->pluginid = pluginid;
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

static int
parse_socket_line(struct pluginDevice * bt,	const char *NameMapping
,	int *sockno, char *sockname)
{
#if 0
	char format[64];
	snprintf(format, sizeof(format), "%%7d       %%%dc"
	,	bt->modelinfo->socklen);
	/* 7 digits, 7 blanks, then 'socklen' characters */
	/* [0-6]: digits, NameMapping[13] begins the sockname */
	/* NameMapping strlen must be >= socklen + 14 */

	if (sscanf(NameMapping, format, sockno, sockname) != 2) {
		return FALSE;
	}
#else
#	define	OFFSET 14

	if (sscanf(NameMapping, "%7d", sockno) != 1
	||	strlen(NameMapping) < OFFSET+bt->modelinfo->socklen) {
		return FALSE;
	}
	strncpy(sockname, NameMapping+OFFSET, bt->modelinfo->socklen);
	sockname[bt->modelinfo->socklen] = EOS;
#endif
	return TRUE;
}
