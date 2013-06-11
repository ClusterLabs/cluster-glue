/*
*
*  Copyright 2001 Mission Critical Linux, Inc.
*
*  All Rights Reserved.
*/
/*
 *	Stonith module for APC Master Switch (AP9211)
 *
 *  Copyright (c) 2001 Mission Critical Linux, Inc.
 *  author: mike ledoux <mwl@mclinux.com>
 *  author: Todd Wheeling <wheeling@mclinux.com>
 *  mangled by Sun Jiang Dong, <sunjd@cn.ibm.com>, IBM, 2005
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
 * 1. The APC MasterSwitch, unlike the BayTech network power switch,
 *    accepts only one (telnet) connection/session at a time. When one
 *    session is active, any subsequent attempt to connect to the MasterSwitch 
 *    will result in a connection refused/closed failure. In a cluster 
 *    environment or other environment utilizing polling/monitoring of the 
 *    MasterSwitch (from multiple nodes), this can clearly cause problems. 
 *    Obviously the more nodes and the shorter the polling interval, the more 
 *    frequently such errors/collisions may occur.
 *
 * 2. We observed that on busy networks where there may be high occurances
 *    of broadcasts, the MasterSwitch became unresponsive.  In some 
 *    configurations this necessitated placing the power switch onto a 
 *    private subnet.
 */

#include <lha_internal.h>

#define	DEVICE	"APC MasterSwitch"

#define DOESNT_USE_STONITHKILLCOMM	1

#include "stonith_plugin_common.h"

#define PIL_PLUGIN              apcmaster
#define PIL_PLUGIN_S            "apcmaster"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

#include "stonith_signal.h"

static StonithPlugin *	apcmaster_new(const char *);
static void		apcmaster_destroy(StonithPlugin *);
static const char * const *	apcmaster_get_confignames(StonithPlugin *);
static int		apcmaster_set_config(StonithPlugin *, StonithNVpair *);
static const char *	apcmaster_getinfo(StonithPlugin * s, int InfoType);
static int		apcmaster_status(StonithPlugin * );
static int		apcmaster_reset_req(StonithPlugin * s, int request, const char * host);
static char **		apcmaster_hostlist(StonithPlugin  *);

static struct stonith_ops apcmasterOps ={
	apcmaster_new,		/* Create new STONITH object	*/
	apcmaster_destroy,		/* Destroy STONITH object	*/
	apcmaster_getinfo,		/* Return STONITH info string	*/
	apcmaster_get_confignames,	/* Get configuration parameters */
	apcmaster_set_config,		/* Set configuration */
	apcmaster_status,		/* Return STONITH device status	*/
	apcmaster_reset_req,		/* Request a reset */
	apcmaster_hostlist,		/* Return list of supported hosts */
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
	,	&apcmasterOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*
 *	I have an AP9211.  This code has been tested with this switch.
 */

struct pluginDevice {
	StonithPlugin	sp;
	const char *	pluginid;
	const char *	idinfo;
	pid_t		pid;
	int		rdfd;
	int		wrfd;
	char *		device;
        char *		user;
	char *		passwd;
};

static const char * pluginid = "APCMS-Stonith";
static const char * NOTpluginID = "APCMS device has been destroyed";

/*
 *	Different expect strings that we get from the APC MasterSwitch
 */

#define APCMSSTR	"American Power Conversion"

static struct Etoken EscapeChar[] =	{ {"Escape character is '^]'.", 0, 0}
					,	{NULL,0,0}};
static struct Etoken login[] = 		{ {"User Name :", 0, 0}, {NULL,0,0}};
static struct Etoken password[] =	{ {"Password  :", 0, 0} ,{NULL,0,0}};
static struct Etoken Prompt[] =	{ {"> ", 0, 0} ,{NULL,0,0}};
static struct Etoken LoginOK[] =	{ {APCMSSTR, 0, 0}
                    , {"User Name :", 1, 0} ,{NULL,0,0}};
static struct Etoken Separator[] =	{ {"-----", 0, 0} ,{NULL,0,0}};

/* We may get a notice about rebooting, or a request for confirmation */
static struct Etoken Processing[] =	{ {"Press <ENTER> to continue", 0, 0}
				,	{"Enter 'YES' to continue", 1, 0}
				,	{NULL,0,0}};

#include "stonith_config_xml.h"

static const char *apcmasterXML = 
  XML_PARAMETERS_BEGIN
    XML_IPADDR_PARM
    XML_LOGIN_PARM
    XML_PASSWD_PARM
  XML_PARAMETERS_END;

static int	MS_connect_device(struct pluginDevice * ms);
static int	MSLogin(struct pluginDevice * ms);
static int	MSRobustLogin(struct pluginDevice * ms);
static int	MSNametoOutlet(struct pluginDevice*, const char * name);
static int	MSReset(struct pluginDevice*, int outletNum, const char * host);
static int	MSLogout(struct pluginDevice * ms);

#if defined(ST_POWERON) && defined(ST_POWEROFF)
static int	apcmaster_onoff(struct pluginDevice*, int outletnum, const char * unitid
,		int request);
#endif

/* Login to the APC Master Switch */

static int
MSLogin(struct pluginDevice * ms)
{
        EXPECT(ms->rdfd, EscapeChar, 10);

  	/* 
	 * We should be looking at something like this:
         *	User Name :
	 */
	EXPECT(ms->rdfd, login, 10);
	SEND(ms->wrfd, ms->user);       
	SEND(ms->wrfd, "\r");

	/* Expect "Password  :" */
	EXPECT(ms->rdfd, password, 10);
	SEND(ms->wrfd, ms->passwd);
	SEND(ms->wrfd, "\r");
 
	switch (StonithLookFor(ms->rdfd, LoginOK, 30)) {

		case 0:	/* Good! */
			LOG(PIL_INFO, "Successful login to %s.", ms->idinfo); 
			break;

		case 1:	/* Uh-oh - bad password */
			LOG(PIL_CRIT, "Invalid password for %s.", ms->idinfo);
			return(S_ACCESS);

		default:
			return(errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS);
	} 

	return(S_OK);
}

/* Attempt to login up to 20 times... */

static int
MSRobustLogin(struct pluginDevice * ms)
{
	int rc = S_OOPS;
	int j = 0;

	for ( ; ; ) {
	  if (MS_connect_device(ms) == S_OK) {	
		rc = MSLogin(ms);
		if( rc == S_OK ) {
			break;
	    	}
	  }
	  if ((++j) == 20) {
		break;
	  } else {
		sleep(1);
	  }
	}

	return rc;
}

/* Log out of the APC Master Switch */

static 
int MSLogout(struct pluginDevice* ms)
{
	int	rc;

	/* Make sure we're in the right menu... */
 	/*SEND(ms->wrfd, "\033\033\033\033\033\033\033"); */
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "\033");
	
	/* Expect "> " */
	rc = StonithLookFor(ms->rdfd, Prompt, 5);

	/* "4" is logout */
	SEND(ms->wrfd, "4\r");

	close(ms->wrfd);
	close(ms->rdfd);
	ms->wrfd = ms->rdfd = -1;

	return(rc >= 0 ? S_OK : (errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS));
}
/* Reset (power-cycle) the given outlets */
static int
MSReset(struct pluginDevice* ms, int outletNum, const char *host)
{
  	char		unum[32];

	/* Make sure we're in the top level menu */
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "\033");
	
	/* Expect ">" */
	EXPECT(ms->rdfd, Prompt, 5);

	/* Request menu 1 (Device Control) */
	SEND(ms->wrfd, "1\r");

	/* Select requested outlet */
	EXPECT(ms->rdfd, Prompt, 5);
	snprintf(unum, sizeof(unum), "%i\r", outletNum);
  	SEND(ms->wrfd, unum);

	/* Select menu 1 (Control Outlet) */
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "1\r");

	/* Select menu 3 (Immediate Reboot) */
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "3\r");

	/* Expect "Press <ENTER> " or "Enter 'YES'" (if confirmation turned on) */
	retry:
	switch (StonithLookFor(ms->rdfd, Processing, 5)) {
		case 0: /* Got "Press <ENTER>" Do so */
			SEND(ms->wrfd, "\r");
			break;

		case 1: /* Got that annoying command confirmation :-( */
			SEND(ms->wrfd, "YES\r");
			goto retry;

		default: 
			return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}

	
	LOG(PIL_INFO, "Host being rebooted: %s", host); 

	/* Expect ">" */
	if (StonithLookFor(ms->rdfd, Prompt, 10) < 0) {
		return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}

	/* All Right!  Power is back on.  Life is Good! */

	LOG(PIL_INFO, "Power restored to host: %s", host);

	/* Return to top level menu */
	SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "\033");

	return(S_OK);
}

#if defined(ST_POWERON) && defined(ST_POWEROFF)
static int
apcmaster_onoff(struct pluginDevice* ms, int outletNum, const char * unitid, int req)
{
	char		unum[32];

	const char *	onoff = (req == ST_POWERON ? "1\r" : "2\r");
	int	rc;

	if ((rc = MSRobustLogin(ms) != S_OK)) {
		LOG(PIL_CRIT, "Cannot log into %s.", ms->idinfo);
		return(rc);
	}
	
	/* Make sure we're in the top level menu */
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
        SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "\033");

	/* Expect ">" */
	EXPECT(ms->rdfd, Prompt, 5);

	/* Request menu 1 (Device Control) */
	SEND(ms->wrfd, "1\r");

	/* Select requested outlet */
  	snprintf(unum, sizeof(unum), "%d\r", outletNum); 
  	SEND(ms->wrfd, unum); 

	/* Select menu 1 (Control Outlet) */
	SEND(ms->wrfd, "1\r");

	/* Send ON/OFF command for given outlet */
	SEND(ms->wrfd, onoff);

	/* Expect "Press <ENTER> " or "Enter 'YES'" (if confirmation turned on) */
	retry:
	switch (StonithLookFor(ms->rdfd, Processing, 5)) {
		case 0: /* Got "Press <ENTER>" Do so */
			SEND(ms->wrfd, "\r");
			break;

		case 1: /* Got that annoying command confirmation :-( */
			SEND(ms->wrfd, "YES\r");
			goto retry;

		default: 
			return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}
	
	EXPECT(ms->rdfd, Prompt, 10);

	/* All Right!  Command done. Life is Good! */
	LOG(PIL_INFO, "Power to MS outlet(s) %d turned %s", outletNum, onoff);
	/* Pop back to main menu */
	SEND(ms->wrfd, "\033\033\033\033\033\033\033\r");
	return(S_OK);
}
#endif /* defined(ST_POWERON) && defined(ST_POWEROFF) */

/*
 *	Map the given host name into an (AC) Outlet number on the power strip
 */

static int
MSNametoOutlet(struct pluginDevice* ms, const char * name)
{
	char	NameMapping[128];
	int	sockno;
	char	sockname[32];
	int times = 0;
	int ret = -1;

	/* Verify that we're in the top-level menu */
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "\033");	
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "\033");

	/* Expect ">" */
	EXPECT(ms->rdfd, Prompt, 5);
	
	/* Request menu 1 (Device Control) */
	SEND(ms->wrfd, "1\r");

	/* Expect: "-----" so we can skip over it... */
	EXPECT(ms->rdfd, Separator, 5);
	EXPECT(ms->rdfd, CRNL, 5);
	EXPECT(ms->rdfd, CRNL, 5);

	/* Looks Good!  Parse the status output */

	do {
		times++;
		NameMapping[0] = EOS;
		SNARF(ms->rdfd, NameMapping, 5);
		if (sscanf(NameMapping
		,	"%d- %23c",&sockno, sockname) == 2) {

			char *	last = sockname+23;
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
				ret = sockno;
			}
		}
	} while (strlen(NameMapping) > 2 && times < 8);

	/* Pop back out to the top level menu */
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "\033");	
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "\033");
	EXPECT(ms->rdfd, Prompt, 5);
	SEND(ms->wrfd, "\033");
	return(ret);
}

static int
apcmaster_status(StonithPlugin  *s)
{
	struct pluginDevice*	ms;
	int	rc;

	ERRIFNOTCONFIGED(s,S_OOPS);

	ms = (struct pluginDevice*) s;

	if ((rc = MSRobustLogin(ms) != S_OK)) {
		LOG(PIL_CRIT, "Cannot log into %s.", ms->idinfo);
		return(rc);
	}

	/* Expect ">" */
	SEND(ms->wrfd, "\033\r");
	EXPECT(ms->rdfd, Prompt, 5);

	return(MSLogout(ms));
}

/*
 *	Return the list of hosts (outlet names) for the devices on this MS unit
 */

static char **
apcmaster_hostlist(StonithPlugin  *s)
{
	char		NameMapping[128];
	char*		NameList[64];
	unsigned int	numnames = 0;
	char **		ret = NULL;
	struct pluginDevice*	ms;
	unsigned int	i;

	ERRIFNOTCONFIGED(s,NULL);

	ms = (struct pluginDevice*) s;
		
	if (MSRobustLogin(ms) != S_OK) {
		LOG(PIL_CRIT, "Cannot log into %s.", ms->idinfo);
		return(NULL);
	}

	/* Expect ">" */
	NULLEXPECT(ms->rdfd, Prompt, 10);

	/* Request menu 1 (Device Control) */
	SEND(ms->wrfd, "1\r");

	/* Expect: "-----" so we can skip over it... */
	NULLEXPECT(ms->rdfd, Separator, 5);
	NULLEXPECT(ms->rdfd, CRNL, 5);
	NULLEXPECT(ms->rdfd, CRNL, 5);

	/* Looks Good!  Parse the status output */
	do {
		int	sockno;
		char	sockname[64];
		NameMapping[0] = EOS;
		NULLSNARF(ms->rdfd, NameMapping, 5);
		if (sscanf(NameMapping
		,	"%d- %23c",&sockno, sockname) == 2) {

			char *	last = sockname+23;
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
			if ((nm = (char*)STRDUP(sockname)) == NULL) {
				goto out_of_memory;
			}
			strdown(nm);
			NameList[numnames] = nm;
			++numnames;
			NameList[numnames] = NULL;
		}
	} while (strlen(NameMapping) > 2);

	/* Pop back out to the top level menu */
    	SEND(ms->wrfd, "\033");
        NULLEXPECT(ms->rdfd, Prompt, 10);
    	SEND(ms->wrfd, "\033");
        NULLEXPECT(ms->rdfd, Prompt, 10);
    	SEND(ms->wrfd, "\033");
        NULLEXPECT(ms->rdfd, Prompt, 10);
    	SEND(ms->wrfd, "\033");
	NULLEXPECT(ms->rdfd, Prompt, 10);
      

	if (numnames >= 1) {
		ret = (char **)MALLOC((numnames+1)*sizeof(char*));
		if (ret == NULL) {
			goto out_of_memory;
		}else{
			memcpy(ret, NameList, (numnames+1)*sizeof(char*));
		}
	}
	(void)MSLogout(ms);
	return(ret);

out_of_memory:
	LOG(PIL_CRIT, "out of memory");
	for (i=0; i<numnames; i++) {
		FREE(NameList[i]);
	}
	return(NULL);
}

/*
 *	Connect to the given MS device.  We should add serial support here
 *	eventually...
 */
static int
MS_connect_device(struct pluginDevice * ms)
{
	int fd = OurImports->OpenStreamSocket(ms->device
	,	TELNET_PORT, TELNET_SERVICE);

	if (fd < 0) {
		return(S_OOPS);
	}
	ms->rdfd = ms->wrfd = fd;
	return(S_OK);
}

/*
 *	Reset the given host on this StonithPlugin device.  
 */
static int
apcmaster_reset_req(StonithPlugin * s, int request, const char * host)
{
	int	rc = 0;
	int	lorc = 0;
	struct pluginDevice*	ms;

	ERRIFNOTCONFIGED(s,S_OOPS);

	ms = (struct pluginDevice*) s;

	if ((rc = MSRobustLogin(ms)) != S_OK) {
		LOG(PIL_CRIT, "Cannot log into %s.", ms->idinfo);
		return(rc);
	}else{
		int noutlet; 
		noutlet = MSNametoOutlet(ms, host);
		if (noutlet < 1) {
			LOG(PIL_WARN, "%s doesn't control host [%s]"
			,	ms->device, host);
			return(S_BADHOST);
		}
		switch(request) {

#if defined(ST_POWERON) && defined(ST_POWEROFF)
		case ST_POWERON:
		        rc = apcmaster_onoff(ms, noutlet, host, request);
			break;
		case ST_POWEROFF:
			rc = apcmaster_onoff(ms, noutlet, host, request);
			break;
#endif
		case ST_GENERIC_RESET:
			rc = MSReset(ms, noutlet, host);
			break;
		default:
			rc = S_INVAL;
			break;
		}
	}

	lorc = MSLogout(ms);
	return(rc != S_OK ? rc : lorc);
}

/*
 *	Get the configuration parameters names
 */
static const char * const *
apcmaster_get_confignames(StonithPlugin * s)
{
	static const char * ret[] = {ST_IPADDR, ST_LOGIN, ST_PASSWD, NULL};
	return ret;
}

/*
 *	Set the configuration parameters
 */
static int
apcmaster_set_config(StonithPlugin * s, StonithNVpair * list)
{
	struct pluginDevice* sd = (struct pluginDevice *)s;
	int		rc;
	StonithNamesToGet	namestocopy [] =
	{	{ST_IPADDR,	NULL}
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
	sd->device = namestocopy[0].s_value;
	sd->user = namestocopy[1].s_value;
	sd->passwd = namestocopy[2].s_value;

	return(S_OK);
}

static const char *
apcmaster_getinfo(StonithPlugin * s, int reqtype)
{
	struct pluginDevice* ms;
	const char *		ret;

	ERRIFWRONGDEV(s,NULL);

	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	ms = (struct pluginDevice *)s;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = ms->idinfo;
			break;

		case ST_DEVICENAME:		/* Which particular device? */
			ret = ms->device;
			break;

		case ST_DEVICEDESCR:
			ret = "APC MasterSwitch (via telnet)\n"
 			"NOTE: The APC MasterSwitch accepts only one (telnet)\n"
			"connection/session a time. When one session is active,\n"
			"subsequent attempts to connect to the MasterSwitch"
			" will fail.";
			break;

		case ST_DEVICEURL:
			ret = "http://www.apc.com/";
			break;

		case ST_CONF_XML:		/* XML metadata */
			ret = apcmasterXML;
			break;

		default:
			ret = NULL;
			break;
	}
	return ret;
}

/*
 *	APC MasterSwitch StonithPlugin destructor...
 */
static void
apcmaster_destroy(StonithPlugin *s)
{
	struct pluginDevice* ms;

	VOIDERRIFWRONGDEV(s);

	ms = (struct pluginDevice *)s;

	ms->pluginid = NOTpluginID;
	if (ms->rdfd >= 0) {
		close(ms->rdfd);
		ms->rdfd = -1;
	}
	if (ms->wrfd >= 0) {
		close(ms->wrfd);
		ms->wrfd = -1;
	}
	if (ms->device != NULL) {
		FREE(ms->device);
		ms->device = NULL;
	}
	if (ms->user != NULL) {
		FREE(ms->user);
		ms->user = NULL;
	}
	if (ms->passwd != NULL) {
		FREE(ms->passwd);
		ms->passwd = NULL;
	}
	FREE(ms);
}

/* Create a new APC Master Switch StonithPlugin device. */

static StonithPlugin *
apcmaster_new(const char *subplugin)
{
	struct pluginDevice*	ms = ST_MALLOCT(struct pluginDevice);

	if (ms == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(ms, 0, sizeof(*ms));
	ms->pluginid = pluginid;
	ms->pid = -1;
	ms->rdfd = -1;
	ms->wrfd = -1;
	ms->user = NULL;
	ms->device = NULL;
	ms->passwd = NULL;
	ms->idinfo = DEVICE;
	ms->sp.s_ops = &apcmasterOps;

	return(&(ms->sp));
}
