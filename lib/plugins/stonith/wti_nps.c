/*
 *
 *  Copyright 2001 Mission Critical Linux, Inc.
 *
 *  All Rights Reserved.
 */
/*
 *	Stonith module for WTI Network Power Switch Devices (NPS-xxx)
 *	Also supports the WTI Telnet Power Switch Devices (TPS-xxx)
 *
 *  Copyright 2001 Mission Critical Linux, Inc.
 *  author: mike ledoux <mwl@mclinux.com>
 *  author: Todd Wheeling <wheeling@mclinux.com>
 *  Mangled by Zhaokai <zhaokai@cn.ibm.com>, IBM, 2005
 *  Further hurt by Lon <lhh@redhat.com>, Red Hat, 2005
 *
 *  Supported WTI devices:
 *     NPS-115
 *     NPS-230
 *     IPS-15
 *     IPS-800
 *     IPS-800-CE
 *     NBB-1600
 *     NBB-1600-CE
 *     TPS-2
 *
 *  Based strongly on original code from baytech.c by Alan Robertson.
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

/*                          Observations/Notes
 * 
 * 1. The WTI Network Power Switch, unlike the BayTech network power switch,
 *    accpets only one (telnet) connection/session at a time. When one
 *    session is active, any subsequent attempt to connect to the NPS will
 *    result in a connection refused/closed failure. In a cluster environment
 *    or other environment utilizing polling/monitoring of the NPS
 *    (from multiple nodes), this can clearly cause problems. Obviously the
 *    more nodes and the shorter the polling interval, the more frequently such
 *    errors/collisions may occur.
 *
 * 2. We observed that on busy networks where there may be high occurances
 *    of broadcasts, the NPS became unresponsive.  In some 
 *    configurations this necessitated placing the power switch onto a 
 *    private subnet.
 */

#include <lha_internal.h>
#define	DEVICE	"WTI Network Power Switch"

#define DOESNT_USE_STONITHKILLCOMM	1

#include "stonith_plugin_common.h"

#define PIL_PLUGIN              wti_nps
#define PIL_PLUGIN_S            "wti_nps"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#define MAX_WTIPLUGINID		256

#include <pils/plugin.h>

#include "stonith_signal.h"

static StonithPlugin *	wti_nps_new(const char *);
static void		wti_nps_destroy(StonithPlugin *);
static const char * const *	wti_nps_get_confignames(StonithPlugin *);
static int		wti_nps_set_config(StonithPlugin * , StonithNVpair * );
static const char *	wti_nps_get_info(StonithPlugin * s, int InfoType);
static int		wti_nps_status(StonithPlugin * );
static int		wti_nps_reset_req(StonithPlugin * s, int request, const char * host);
static char **		wti_nps_hostlist(StonithPlugin  *);

static struct stonith_ops wti_npsOps ={
	wti_nps_new,		/* Create new STONITH object		*/
	wti_nps_destroy,	/* Destroy STONITH object		*/
	wti_nps_get_info,	/* Return STONITH info string		*/
	wti_nps_get_confignames,/* Return configration parameters	*/
	wti_nps_set_config,	/* set configration			*/
	wti_nps_status,		/* Return STONITH device status		*/
	wti_nps_reset_req,	/* Request a reset 			*/
	wti_nps_hostlist,	/* Return list of supported hosts 	*/
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
	,	&wti_npsOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*
 *	I have a NPS-110.  This code has been tested with this switch.
 *	(Tested with NPS-230 and TPS-2 by lmb)
 */

struct pluginDevice {
	StonithPlugin	sp;
	const char *	pluginid;
	const char *	idinfo;
	pid_t		pid;
	int		rdfd;
	int		wrfd;
	char *		device;
	char *		passwd;
};

static const char * pluginid = "WTINPS-Stonith";
static const char * NOTnpsid = "WTINPS device has been destroyed";

#include "stonith_config_xml.h"

static const char *wti_npsXML = 
  XML_PARAMETERS_BEGIN
    XML_IPADDR_PARM
    XML_PASSWD_PARM
  XML_PARAMETERS_END;


/*
 *	Different expect strings that we get from the WTI
 *	Network Power Switch
 */

#define WTINPSSTR	" Power Switch"
#define WTINBBSTR	"Boot Bar"
 
static struct Etoken password[] =	{ {"Password:", 0, 0}, {NULL,0,0}};
static struct Etoken Prompt[] =		{ {"PS>", 0, 0}
					, {"IPS>", 0, 0}
					, {"BB>", 0, 0}
					, {NULL,0,0}};
static struct Etoken LoginOK[] =	{ {WTINPSSTR, 0, 0}
					, {WTINBBSTR, 0, 0}
					, {"Invalid password", 1, 0}
					, {NULL,0,0} };
static struct Etoken Separator[] =	{ {"-----+", 0, 0} ,{NULL,0,0}};

/* We may get a notice about rebooting, or a request for confirmation */
static struct Etoken Processing[] =	{ {"rocessing - please wait", 0, 0}
				,	{"(Y/N):", 1, 0}
				,	{NULL,0,0}};

static int	NPS_connect_device(struct pluginDevice * nps);
static int	NPSLogin(struct pluginDevice * nps);
static int	NPSNametoOutlet(struct pluginDevice*, const char * name, char **outlets);
static int	NPSReset(struct pluginDevice*, char * outlets, const char * rebootid);
static int	NPSLogout(struct pluginDevice * nps);

#if defined(ST_POWERON) && defined(ST_POWEROFF)
static int	NPS_onoff(struct pluginDevice*, const char * outlets, const char * unitid
,		int request);
#endif

/* Attempt to login up to 20 times... */
static int
NPSRobustLogin(struct pluginDevice * nps)
{
	int rc = S_OOPS;
	int j = 0;

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	for ( ; ; ) {
		if (NPS_connect_device(nps) == S_OK) {	
			rc = NPSLogin(nps);
			if (rc == S_OK) { 
				break;
			}
		}
		if ((++j) == 20) { 
			break;
		}
		else {
			sleep(1);
		}
	}

	return rc;
}

/* Login to the WTI Network Power Switch (NPS) */
static int
NPSLogin(struct pluginDevice * nps)
{
	char		IDinfo[128];
	char *		idptr = IDinfo;

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	/* Look for the unit type info */
	if (EXPECT_TOK(nps->rdfd, password, 2, IDinfo
	,	sizeof(IDinfo), Debug) < 0) {
		LOG(PIL_CRIT, "No initial response from %s.", nps->idinfo);
 		return(errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS);
	}
	idptr += strspn(idptr, WHITESPACE);
	/*
	 * We should be looking at something like this:
	 *	Enter Password: 
	 */

	SEND(nps->wrfd, nps->passwd);
	SEND(nps->wrfd, "\r");
	/* Expect "Network Power Switch vX.YY" */

	switch (StonithLookFor(nps->rdfd, LoginOK, 5)) {

		case 0:	/* Good! */
			LOG(PIL_INFO, "Successful login to %s.", nps->idinfo);
			break;

		case 1:	/* Uh-oh - bad password */
			LOG(PIL_CRIT, "Invalid password for %s.", nps->idinfo);
			return(S_ACCESS);

		default:
			return(errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS);
	}
	return(S_OK);
}

/* Log out of the WTI NPS */

static int
NPSLogout(struct pluginDevice* nps)
{
	int	rc;

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	/* Send "/h" help command and expect back prompt */
	/*
	SEND(nps->wrfd, "/h\r");
	*/
	/* Expect "PS>" */
	rc = StonithLookFor(nps->rdfd, Prompt, 5);

	/* "/x" is Logout, "/x,y" auto-confirms */
	SEND(nps->wrfd, "/x,y\r");

	close(nps->wrfd);
	close(nps->rdfd);
	nps->wrfd = nps->rdfd = -1;

	return(rc >= 0 ? S_OK : (errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS));
}

/* Reset (power-cycle) the given outlets */
static int
NPSReset(struct pluginDevice* nps, char * outlets, const char * rebootid)
{
	char		unum[32];

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	/* Send "/h" help command and expect back prompt */
	SEND(nps->wrfd, "/h\r");
	/* Expect "PS>" */
	EXPECT(nps->rdfd, Prompt, 5);
	
	/* Send REBOOT command for given outlets */
	snprintf(unum, sizeof(unum), "/BOOT %s,y\r", outlets);
	SEND(nps->wrfd, unum);
	
	/* Expect "Processing "... or "(Y/N)" (if confirmation turned on) */

	retry:
	switch (StonithLookFor(nps->rdfd, Processing, 5)) {
		case 0: /* Got "Processing" Do nothing */
			break;

		case 1: /* Got that annoying command confirmation :-( */
			SEND(nps->wrfd, "Y\r");
			goto retry;

		default: 
			return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}
	LOG(PIL_INFO, "Host is being rebooted: %s", rebootid);

	/* Expect "PS>" */
	if (StonithLookFor(nps->rdfd, Prompt, 60) < 0) {
		return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}

	/* All Right!  Power is back on.  Life is Good! */

	LOG(PIL_INFO, "Power restored to host: %s", rebootid);
	SEND(nps->wrfd, "/h\r");
	return(S_OK);
}

#if defined(ST_POWERON) && defined(ST_POWEROFF)
static int
NPS_onoff(struct pluginDevice* nps, const char * outlets, const char * unitid, int req)
{
	char		unum[32];

	const char *	onoff = (req == ST_POWERON ? "/On" : "/Off");

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	/* Send "/h" help command and expect prompt back */
	SEND(nps->wrfd, "/h\r");
	/* Expect "PS>" */
	EXPECT(nps->rdfd, Prompt, 5);

	/* Send ON/OFF command for given outlet */
	snprintf(unum, sizeof(unum), "%s %s,y\r", onoff, outlets);
	SEND(nps->wrfd, unum);

	/* Expect "Processing"... or "(Y/N)" (if confirmation turned on) */

	if (StonithLookFor(nps->rdfd, Processing, 5) == 1) {
		/* They've turned on that annoying command confirmation :-( */
		SEND(nps->wrfd, "Y\r");
	}
	EXPECT(nps->rdfd, Prompt, 60);

	/* All Right!  Command done. Life is Good! */
	LOG(PIL_INFO, "Power to NPS outlet(s) %s turned %s", outlets, onoff);

	SEND(nps->wrfd, "/h\r");
	return(S_OK);
}
#endif /* defined(ST_POWERON) && defined(ST_POWEROFF) */

/*
 *	Map the given host name into an (AC) Outlet number on the power strip
 */

static int
NPSNametoOutlet(struct pluginDevice* nps, const char * name, char **outlets)
{
  	char	NameMapping[128];
  	int	sockno;
  	char	sockname[32];
        char buf[32];
        int left = 17;
  	int ret = -1;
	
	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}
        
        if ((*outlets = (char *)MALLOC(left*sizeof(char))) == NULL) {
                LOG(PIL_CRIT, "out of memory");
                return(-1);
        }
	
        strncpy(*outlets, "", left);
        left = left - 1;        /* ensure terminating '\0' */
  	/* Expect "PS>" */
  	EXPECT(nps->rdfd, Prompt, 5);
	
  	/* The status command output contains mapping of hosts to outlets */ 
    	SEND(nps->wrfd, "/s\r");

 	/* Expect: "-----+" so we can skip over it... */
    	EXPECT(nps->rdfd, Separator, 5); 
	
  	do {
  		NameMapping[0] = EOS;
  		SNARF(nps->rdfd, NameMapping, 5);
  		
  		if (sscanf(NameMapping
  		,	"%d | %16c",&sockno, sockname) == 2) {
  
  			char *	last = sockname+16;
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
  			if (strncasecmp(name, sockname, 16) == 0) {
  				ret = sockno;
  				snprintf(buf, sizeof(buf), "%d ", sockno);
  				strncat(*outlets, buf, left);
  				left = left - strlen(buf);
  			}
  		}
  	} while (strlen(NameMapping) > 2 && left > 0);

  	return(ret);
}

static int
wti_nps_status(StonithPlugin  *s)
{
	struct pluginDevice*	nps;
	int	rc;

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	ERRIFNOTCONFIGED(s,S_OOPS);

	nps = (struct pluginDevice*) s;

       	if ((rc = NPSRobustLogin(nps) != S_OK)) {
		LOG(PIL_CRIT, "Cannot log into %s.", nps->idinfo);
		return(rc);
	}

	/* Send "/h" help command and expect back prompt */
	SEND(nps->wrfd, "/h\r");
	/* Expect "PS>" */
	EXPECT(nps->rdfd, Prompt, 5);

	return(NPSLogout(nps));
}

/*
 *	Return the list of hosts (outlet names) for the devices on this NPS unit
 */

static char **
wti_nps_hostlist(StonithPlugin  *s)
{
	char		NameMapping[128];
	char*		NameList[64];
	unsigned int	numnames = 0;
	char **		ret = NULL;
	struct pluginDevice*	nps;
	unsigned int	i;

	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	ERRIFNOTCONFIGED(s,NULL);

	nps = (struct pluginDevice*) s;
	if (NPSRobustLogin(nps) != S_OK) {
		LOG(PIL_CRIT, "Cannot log into %s.", nps->idinfo);
		return(NULL);
	}
	
	/* Expect "PS>" */
	NULLEXPECT(nps->rdfd, Prompt, 5);
	
	/* The status command output contains mapping of hosts to outlets */
	SEND(nps->wrfd, "/s\r");

	/* Expect: "-----" so we can skip over it... */
	NULLEXPECT(nps->rdfd, Separator, 5);
	NULLEXPECT(nps->rdfd, CRNL, 5);
	
	/* Looks Good!  Parse the status output */

	do {
		int	sockno;
		char	sockname[64];
		NameMapping[0] = EOS;
		NULLSNARF(nps->rdfd, NameMapping, 5);
		if (sscanf(NameMapping
		,	"%d | %16c",&sockno, sockname) == 2) {

			char *	last = sockname+16;
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
			if (!strcmp(sockname,"(undefined)") ||
			    !strcmp(sockname,"---")) {
				/* lhh - skip undefined */
				continue;
			}
			if ((nm = STRDUP(sockname)) == NULL) {
				goto out_of_memory;
			}
			strdown(nm);
			NameList[numnames] = nm;
			++numnames;
			NameList[numnames] = NULL;
		}
	} while (strlen(NameMapping) > 2);

	if (numnames >= 1) {
		ret = (char **)MALLOC((numnames+1)*sizeof(char*));
		if (ret == NULL) {
			goto out_of_memory;
		}else{
			memset(ret, 0, (numnames+1)*sizeof(char*));
			memcpy(ret, NameList, (numnames+1)*sizeof(char*));
		}
	}
	(void)NPSLogout(nps);
	
	return(ret);
	
out_of_memory:
	LOG(PIL_CRIT, "out of memory");
	for (i=0; i<numnames; i++) {
		FREE(NameList[i]);
	}

	return (NULL);
}

/*
 *	Connect to the given NPS device.  We should add serial support here
 *	eventually...
 */
static int
NPS_connect_device(struct pluginDevice * nps)
{
	int fd = OurImports->OpenStreamSocket(nps->device
	,	TELNET_PORT, TELNET_SERVICE);

	if (fd < 0) {
		return(S_OOPS);
	}
	nps->rdfd = nps->wrfd = fd;
	return(S_OK);
}

/*
 *	Reset the given host on this Stonith device.  
 */
static int
wti_nps_reset_req(StonithPlugin * s, int request, const char * host)
{
	int	rc = 0;
	int	lorc = 0;
	struct pluginDevice*	nps;
	
	if (Debug) {
		LOG(PIL_DEBUG, "%s:called.", __FUNCTION__);
	}

	ERRIFNOTCONFIGED(s,S_OOPS);

	nps = (struct pluginDevice*) s;

        if ((rc = NPSRobustLogin(nps)) != S_OK) {
		LOG(PIL_CRIT, "Cannot log into %s.", nps->idinfo);
        }else{
	        char *outlets;
		int noutlet;
     
		outlets = NULL;
		noutlet = NPSNametoOutlet(nps, host, &outlets);

		if (noutlet < 1) {
			LOG(PIL_WARN, "%s doesn't control host [%s]"
			,	nps->device, host);
			if (outlets != NULL) {
			  FREE(outlets);
			  outlets = NULL;
			}
			return(S_BADHOST);
		}
		switch(request) {

#if defined(ST_POWERON) && defined(ST_POWEROFF)
		case ST_POWERON:
		case ST_POWEROFF:
			rc = NPS_onoff(nps, outlets, host, request);
			if (outlets != NULL) {
			  FREE(outlets);
			  outlets = NULL;
			}
			break;
#endif
		case ST_GENERIC_RESET:
			rc = NPSReset(nps, outlets, host);
			if (outlets != NULL) {
			  FREE(outlets);
			  outlets = NULL;
			}
			break;
		default:
			rc = S_INVAL;			
			if (outlets != NULL) {
			  FREE(outlets);
			  outlets = NULL;
			}
			break;
		}
	}

	lorc = NPSLogout(nps);
	return(rc != S_OK ? rc : lorc);
}

/*
 *	Parse the information in the given string,
 *	and stash it away...
 */
static int
wti_nps_set_config(StonithPlugin * s, StonithNVpair *list)
{
	struct pluginDevice*	nps;
	StonithNamesToGet	namestocopy [] =
	{	{ST_IPADDR,	NULL}
	,	{ST_PASSWD,	NULL}
	,	{NULL,		NULL}
	};
	int	rc;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.\n", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,S_OOPS);

	nps = (struct pluginDevice*) s;

	if ((rc = OurImports->CopyAllValues(namestocopy, list)) != S_OK) {
		return rc;
	}
	nps->device = namestocopy[0].s_value;
	nps->passwd = namestocopy[1].s_value;
	return S_OK;	
}


/*
 * Return the Stonith plugin configuration parameter 
 *
 */
static const char * const *
wti_nps_get_confignames(StonithPlugin * p)
{
	static	const char * names[] =  { ST_IPADDR , ST_PASSWD , NULL};
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}
	return names;
}

/*
 * Get info about  the stonith device 
 *
 */
static const char *
wti_nps_get_info(StonithPlugin * s, int reqtype)
{
	struct pluginDevice* nps;
	const char *	ret;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,NULL);

	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	nps = (struct pluginDevice *)s;

	switch (reqtype) {

		case ST_DEVICEID:
			ret = nps->idinfo;
			break;
		case ST_DEVICENAME:
			ret = nps->device;
			break;
		case ST_DEVICEDESCR:
			ret = "Western Telematic (WTI) Network Power Switch Devices (NPS-xxx)\n"
 			"Also supports the WTI Telnet Power Switch Devices (TPS-xxx)\n"
 			"NOTE: The WTI Network Power Switch, accepts only "
			"one (telnet) connection/session at a time.";
			break;
		case ST_DEVICEURL:
			ret = "http://www.wti.com/";
			break;
		case ST_CONF_XML:		/* XML metadata */
			ret = wti_npsXML;
			break;
		default:
			ret = NULL;
			break;
	}
	return ret;
}

/*
 *	WTI NPS Stonith destructor...
 */
static void
wti_nps_destroy(StonithPlugin *s)
{
	struct pluginDevice* nps;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	VOIDERRIFWRONGDEV(s);

	nps = (struct pluginDevice *)s;

	nps->pluginid = NOTnpsid;
	if (nps->rdfd >= 0) {
		close(nps->rdfd);
		nps->rdfd = -1;
	}
	if (nps->wrfd >= 0) {
		close(nps->wrfd);
		nps->wrfd = -1;
	}
	if (nps->device != NULL) {
		FREE(nps->device);
		nps->device = NULL;
	}
	if (nps->passwd != NULL) {
		FREE(nps->passwd);
		nps->passwd = NULL;
	}
	FREE(nps);
}

/* Create a new BayTech Stonith device. */

static StonithPlugin *
wti_nps_new(const char *subplugin)
{
	struct pluginDevice*	nps = ST_MALLOCT(struct pluginDevice);

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	if (nps == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(nps, 0, sizeof(*nps));
	nps->pluginid = pluginid;
	nps->pid = -1;
	nps->rdfd = -1;
	nps->wrfd = -1;
	nps->device = NULL;
	nps->passwd = NULL;
	nps->idinfo = DEVICE;
	nps->sp.s_ops = &wti_npsOps;

	return &(nps->sp);
}

