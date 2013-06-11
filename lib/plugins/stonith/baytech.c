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

#include <lha_internal.h>
#define	DEVICE	"BayTech power switch"

#define DOESNT_USE_STONITHKILLCOMM	1

#include "stonith_plugin_common.h"

#define PIL_PLUGIN              baytech
#define PIL_PLUGIN_S            "baytech"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

#include "stonith_signal.h"

static StonithPlugin *	baytech_new(const char *);
static void		baytech_destroy(StonithPlugin *);
static int		baytech_set_config(StonithPlugin *, StonithNVpair *);
static const char * const *	baytech_get_confignames(StonithPlugin * s);
static const char *	baytech_get_info(StonithPlugin * s, int InfoType);
static int		baytech_status(StonithPlugin *);
static int		baytech_reset_req(StonithPlugin * s, int request, const char * host);
static char **		baytech_hostlist(StonithPlugin  *);

static struct stonith_ops baytechOps ={
	baytech_new,			/* Create new STONITH object	*/
	baytech_destroy,		/* Destroy STONITH object	*/
	baytech_get_info,		/* Return STONITH info string	*/
	baytech_get_confignames,	/* Return STONITH config vars */
	baytech_set_config,		/* set configuration from vars	*/
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

#define	MAXOUTLET		32

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
	StonithPlugin			sp;
	const char *			pluginid;
	char *				idinfo;
	char *				unitid;
	const struct BayTechModelInfo*	modelinfo;
	pid_t				pid;
	int				rdfd;
	int				wrfd;
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
static const char * NOTpluginID = "BayTech device has been destroyed";

/*
 *	Different expect strings that we get from the Baytech
 *	Remote Power Controllers...
 */

#define BAYTECHASSOC	"Bay Technical Associates"

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
static struct Etoken Break[] =		{ {"Status", 0, 0}
					,	{NULL,0,0}};
static struct Etoken PowerApplied[] =	{ {"ower applied to outlet", 0, 0}
					,	{NULL,0,0}};

/* We may get a notice about rebooting, or a request for confirmation */
static struct Etoken Rebooting[] =	{ {"ebooting selected outlet", 0, 0}
					,	{"(Y/N)>", 1, 0}
					,	{"already off.", 2, 0}
					,	{NULL,0,0}};

static struct Etoken TurningOnOff[] =	{ {"RPC", 0, 0}
					,	{"(Y/N)>", 1, 0}
					,	{"already ", 2, 0}
					,	{NULL,0,0}};


static struct BayTechModelInfo ModelInfo [] = {
	{"BayTech RPC-5",	18, Temp},/* This first model will be the default */
	{"BayTech RPC-3",	10, Break},	
	{"BayTech RPC-3A",	10, Break},
	{NULL,		0,  NULL},
};

#include "stonith_config_xml.h"

static const char *baytechXML = 
  XML_PARAMETERS_BEGIN
    XML_IPADDR_PARM
    XML_LOGIN_PARM
    XML_PASSWD_PARM
  XML_PARAMETERS_END;

static int	RPC_connect_device(struct pluginDevice * bt);
static int	RPCLogin(struct pluginDevice * bt);
static int	RPCRobustLogin(struct pluginDevice * bt);
static int	RPCNametoOutletList(struct pluginDevice*, const char * name
,		int outletlist[]);
static int	RPCReset(struct pluginDevice*, int unitnum, const char * rebootid);
static int	RPCLogout(struct pluginDevice * bt);


static int	RPC_onoff(struct pluginDevice*, int unitnum, const char * unitid
,		int request);

/* Login to the Baytech Remote Power Controller (RPC) */

static int
RPCLogin(struct pluginDevice * bt)
{
	char		IDinfo[128];
	static char	IDbuf[128];
	char *		idptr = IDinfo;
	char *		delim;
	int		j;

	EXPECT(bt->rdfd, RPC, 10);

	/* Look for the unit type info */
	if (EXPECT_TOK(bt->rdfd, BayTechAssoc, 2, IDinfo
	,	sizeof(IDinfo), Debug) < 0) {
		LOG(PIL_CRIT, "No initial response from %s.", bt->idinfo);
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
	snprintf(IDbuf, sizeof(IDbuf), "BayTech RPC%s", idptr);
	REPLSTR(bt->idinfo, IDbuf);
	if (bt->idinfo == NULL) {
		return(S_OOPS);
	}

	bt->modelinfo = &ModelInfo[0];

	for (j=0; ModelInfo[j].type != NULL; ++j) {
		/*
		 * TIMXXX - 
		 * Look at device ID as this really describes the model.
		 */
		if (strcasecmp(ModelInfo[j].type, IDbuf) == 0) {
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
	if (bt->unitid == NULL) {
		return(S_OOPS);
	}

	/* Expect "username>" */
	EXPECT(bt->rdfd, login, 2);

	SEND(bt->wrfd, bt->user);
	SEND(bt->wrfd, "\r");

	/* Expect "password>" */

	switch (StonithLookFor(bt->rdfd, password, 5)) {
		case 0:	/* Good! */
			break;

		case 1:	/* OOPS!  got another username prompt */
			LOG(PIL_CRIT, "Invalid username for %s.", bt->idinfo);
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
			LOG(PIL_CRIT, "Invalid password for %s.", bt->idinfo);
			return(S_ACCESS);

		default:
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


		if (RPC_connect_device(bt) != S_OK) {
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
			LOG(PIL_CRIT, "Host is OFF: %s.", rebootid);
			return(S_ISOFF);

		default:
			return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}
	LOG(PIL_INFO,	"Host %s (outlet %d) being rebooted."
	,	rebootid, unitnum);
	
	/* Expect "ower applied to outlet" */
	if (StonithLookFor(bt->rdfd, PowerApplied, 30) < 0) {
		return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}

	/* All Right!  Power is back on.  Life is Good! */
	
	LOG(PIL_INFO,	"Power restored to host %s (outlet %d)."
	,	rebootid, unitnum);

	/* Expect: "RPC-x>" */
	EXPECT(bt->rdfd, RPC,5);
	EXPECT(bt->rdfd, GTSign, 5);

	/* Pop back to main menu */
	SEND(bt->wrfd, "MENU\r");
	return(S_OK);
}

static int
RPC_onoff(struct pluginDevice* bt, int unitnum, const char * unitid, int req)
{
	char		unum[32];

	const char *	onoff = (req == ST_POWERON ? "on" : "off");
	int	rc;


	if ((rc = RPCRobustLogin(bt) != S_OK)) {
		LOG(PIL_CRIT, "Cannot log into %s."
		,	bt->idinfo ? bt->idinfo : DEVICE);
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

	if (StonithLookFor(bt->rdfd, TurningOnOff, 10) == 1) {
		/* They've turned on that annoying command confirmation :-( */
		SEND(bt->wrfd, "Y\r");
		EXPECT(bt->rdfd, TurningOnOff, 10);
	}

	EXPECT(bt->rdfd, GTSign, 10);

	/* All Right!  Command done. Life is Good! */
	LOG(PIL_INFO, "Power to host %s (outlet %d) turned %s."
	,	unitid, unitnum, onoff);
	/* Pop back to main menu */
	SEND(bt->wrfd, "MENU\r");
	return(S_OK);
}

/*
 *	Map the given host name into an (AC) Outlet number on the power strip
 */

static int
RPCNametoOutletList(struct pluginDevice* bt, const char * name
,		int outletlist[])
{
	char	NameMapping[128];
	int	sockno;
	char	sockname[32];
	int	maxfound = 0;



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
 	EXPECT(bt->rdfd, bt->modelinfo->expect, 5);
 	EXPECT(bt->rdfd, CRNL, 5);

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
		if (strcasecmp(name, sockname) == 0) {
			outletlist[maxfound] = sockno;
			++maxfound;
		}
	} while (strlen(NameMapping) > 2  && maxfound < MAXOUTLET);

	/* Pop back out to the top level menu */
	SEND(bt->wrfd, "MENU\r");
	return(maxfound);
}

static int
baytech_status(StonithPlugin  *s)
{
	struct pluginDevice*	bt;
	int	rc;

	ERRIFNOTCONFIGED(s,S_OOPS);

	bt = (struct pluginDevice*) s;
	
	if ((rc = RPCRobustLogin(bt) != S_OK)) {
		LOG(PIL_CRIT, "Cannot log into %s."
		,	bt->idinfo ? bt->idinfo : DEVICE);
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
baytech_hostlist(StonithPlugin  *s)
{
	char		NameMapping[128];
	char*		NameList[64];
	unsigned int	numnames = 0;
	char **		ret = NULL;
	struct pluginDevice*	bt;
	unsigned int	i;

	ERRIFNOTCONFIGED(s,NULL);

	bt = (struct pluginDevice*) s;
	
	if (RPCRobustLogin(bt) != S_OK) {
		LOG(PIL_CRIT, "Cannot log into %s."
		,	bt->idinfo ? bt->idinfo : DEVICE);
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
			goto out_of_memory;
		}
		strdown(nm);
		NameList[numnames] = nm;
		++numnames;
		NameList[numnames] = NULL;
	} while (strlen(NameMapping) > 2);

	/* Pop back out to the top level menu */
	SEND(bt->wrfd, "MENU\r");
	if (numnames >= 1) {
		ret = (char **)MALLOC((numnames+1)*sizeof(char*));
		if (ret == NULL) {
			goto out_of_memory;
		}else{
			memcpy(ret, NameList, (numnames+1)*sizeof(char*));
		}
	}
	(void)RPCLogout(bt);
	return(ret);

out_of_memory:
	LOG(PIL_CRIT, "out of memory");
	for (i=0; i<numnames; i++) {
		FREE(NameList[i]);
	}
	return(NULL);
}

/*
 *	Connect to the given BayTech device.
 *	We should add serial support here eventually...
 */
static int
RPC_connect_device(struct pluginDevice * bt)
{
	int fd = OurImports->OpenStreamSocket(bt->device
	,	TELNET_PORT, TELNET_SERVICE);

	if (fd < 0) {
		return(S_OOPS);
	}
	bt->rdfd = bt->wrfd = fd;
	return(S_OK);
}

/*
 *	Reset the given host on this Stonith device.
 */
static int
baytech_reset_req(StonithPlugin * s, int request, const char * host)
{
	int	rc = S_OK;
	int	lorc = 0;
	struct pluginDevice*	bt;

	ERRIFNOTCONFIGED(s,S_OOPS);

	bt = (struct pluginDevice*) s;

	if ((rc = RPCRobustLogin(bt)) != S_OK) {
		LOG(PIL_CRIT, "Cannot log into %s."
		,	bt->idinfo ? bt->idinfo : DEVICE);
	}else{
		int	noutlets;
		int	outlets[MAXOUTLET];
		int	j;
		noutlets = RPCNametoOutletList(bt, host, outlets);

		if (noutlets < 1) {
			LOG(PIL_CRIT,	"%s %s doesn't control host [%s]"
			,	bt->idinfo, bt->unitid, host);
			return(S_BADHOST);
		}
		switch(request) {

		case ST_POWERON:
		case ST_POWEROFF:
			for (j=0; rc == S_OK && j < noutlets;++j) {
				rc = RPC_onoff(bt, outlets[j], host, request);
			}
			break;
		case ST_GENERIC_RESET:
			/*
			 * Our strategy here:
			 *   1. Power off all outlets except the last one
			 *   2. reset the last outlet
			 *   3. power the other outlets back on
			 */

			for (j=0; rc == S_OK && j < noutlets-1; ++j) {
				rc = RPC_onoff(bt,outlets[j],host
				,	ST_POWEROFF);
			}
			if (rc == S_OK) {
				rc = RPCReset(bt, outlets[j], host); 
			}
			for (j=0; rc == S_OK && j < noutlets-1; ++j) {
				rc = RPC_onoff(bt, outlets[j], host
				,	ST_POWERON);
			}
			break;
		default:
			rc = S_INVAL;
			break;
		}
	}

	lorc = RPCLogout(bt);

	return(rc != S_OK ? rc : lorc);
}

static const char * const *
baytech_get_confignames(StonithPlugin * s)
{
	static const char * ret[] = {ST_IPADDR, ST_LOGIN, ST_PASSWD, NULL};
	return ret;
}


/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
baytech_set_config(StonithPlugin* s, StonithNVpair* list)
{
	struct pluginDevice* bt = (struct pluginDevice *)s;
	int		rc;
	StonithNamesToGet	namestocopy [] =
	{	{ST_IPADDR,	NULL}
	,	{ST_LOGIN,	NULL}
	,	{ST_PASSWD,	NULL}
	,	{NULL,		NULL}
	};

	ERRIFWRONGDEV(s, S_OOPS);
	if (bt->sp.isconfigured) {
		return S_OOPS;
	}

	if ((rc =OurImports->CopyAllValues(namestocopy, list)) != S_OK) {
		return rc;
	}
	bt->device = namestocopy[0].s_value;
	bt->user = namestocopy[1].s_value;
	bt->passwd = namestocopy[2].s_value;

	return(S_OK);
}

static const char *
baytech_get_info(StonithPlugin * s, int reqtype)
{
	struct pluginDevice* bt;
	const char *		ret;

	ERRIFWRONGDEV(s,NULL);

	bt = (struct pluginDevice *)s;

	switch (reqtype) {

		case ST_DEVICEID:		/* What type of device? */
			ret = bt->idinfo;
			break;

		case ST_DEVICENAME:		/* Which particular device? */
			ret = bt->device;
			break;

		case ST_DEVICEDESCR:		/* Description of dev type */
			ret = "Bay Technical Associates (Baytech) RPC "
			"series power switches (via telnet).\n"
			"The RPC-5, RPC-3 and RPC-3A switches are well tested"
			".";
			break;

		case ST_DEVICEURL:		/* Manufacturer's web site */
			ret = "http://www.baytech.net/";
			break;

		case ST_CONF_XML:		/* XML metadata */
			ret = baytechXML;
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
baytech_destroy(StonithPlugin *s)
{
	struct pluginDevice* bt;

	VOIDERRIFWRONGDEV(s);

	bt = (struct pluginDevice *)s;

	bt->pluginid = NOTpluginID;
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
	FREE(bt);
}

/* Create a new BayTech Stonith device. */

static StonithPlugin *
baytech_new(const char *subplugin)
{
	struct pluginDevice*	bt = ST_MALLOCT(struct pluginDevice);

	if (bt == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(bt, 0, sizeof(*bt));
	bt->pluginid = pluginid;
	bt->pid = -1;
	bt->rdfd = -1;
	bt->wrfd = -1;
	REPLSTR(bt->idinfo, DEVICE);
	if (bt->idinfo == NULL) {
		FREE(bt);
		return(NULL);
	}
	bt->modelinfo = &ModelInfo[0];
	bt->sp.s_ops = &baytechOps;

	return &(bt->sp);	/* same as "bt" */
}

static int
parse_socket_line(struct pluginDevice * bt, const char *NameMapping
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
