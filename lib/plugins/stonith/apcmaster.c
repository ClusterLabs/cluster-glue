/* $Id: apcmaster.c,v 1.16 2004/10/06 10:55:18 lars Exp $ */
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

/*
 * Version string that is filled in by CVS
 */
static const char *version __attribute__ ((unused)) = "$Revision: 1.16 $"; 

#define	DEVICE	"APC MasterSwitch"

#include "stonith_plugin_common.h"

#define PIL_PLUGIN              apcmaster
#define PIL_PLUGIN_S            "apcmaster"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

#include "stonith_signal.h"

static void *		apcmaster_new(void);
static void		apcmaster_destroy(Stonith *);
static int		apcmaster_set_config_file(Stonith *, const char * cfgname);
static int		apcmaster_set_config_info(Stonith *, const char * info);
static const char *	apcmaster_getinfo(Stonith * s, int InfoType);
static int		apcmaster_status(Stonith * );
static int		apcmaster_reset_req(Stonith * s, int request, const char * host);
static char **		apcmaster_hostlist(Stonith  *);

static struct stonith_ops apcmasterOps ={
	apcmaster_new,		/* Create new STONITH object	*/
	apcmaster_destroy,		/* Destroy STONITH object	*/
	apcmaster_set_config_file,	/* set configuration from file	*/
	apcmaster_set_config_info,	/* Get configuration from file	*/
	apcmaster_getinfo,		/* Return STONITH info string	*/
	apcmaster_status,		/* Return STONITH device status	*/
	apcmaster_reset_req,		/* Request a reset */
	apcmaster_hostlist,		/* Return list of supported hosts */
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug);

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
	const char *	pluginid;
	char *		idinfo;
	char *		unitid;
	pid_t		pid;
	int		rdfd;
	int		wrfd;
	int		config;
	char *		device;
        char *		user;
	char *		passwd;
};

static const char * pluginid = "APCMS-Stonith";
static const char * NOTpluginID = "Hey dummy, this has been destroyed (APCMS)";

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

static int	MS_connect_device(struct pluginDevice * ms);
static int	MSLogin(struct pluginDevice * ms);
static int	MSRobustLogin(struct pluginDevice * ms);
static int	MSNametoOutlet(struct pluginDevice*, const char * name);
static int	MSReset(struct pluginDevice*, int outletNum, const char * host);
static int	MSLogout(struct pluginDevice * ms);

static int	apcmaster_parse_config_info(struct pluginDevice* ms, const char * info);

#if defined(ST_POWERON) && defined(ST_POWEROFF)
static int	apcmaster_onoff(struct pluginDevice*, int outletnum, const char * unitid
,		int request);
#endif
static void	apcmaster_destroy(Stonith *);
static void *	apcmaster_new(void);

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
			LOG(PIL_INFO, "%s", _("Successful login to " DEVICE ".")); 
			break;

		case 1:	/* Uh-oh - bad password */
			LOG(PIL_CRIT,"%s", _("Invalid password for " DEVICE "."));
			return(S_ACCESS);

		default:
			Stonithkillcomm(&ms->rdfd,&ms->wrfd,&ms->pid);
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
	  if (ms->pid > 0)
	    Stonithkillcomm(&ms->rdfd,&ms->wrfd,&ms->pid);
	  if (MS_connect_device(ms) != S_OK) {	
	    Stonithkillcomm(&ms->rdfd,&ms->wrfd,&ms->pid);
	  }
	  else {
	    rc = MSLogin(ms);
	    if( rc == S_OK ) break;
	  }
	  if ((++j) == 20) break;
	  else sleep(1);
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

	Stonithkillcomm(&ms->rdfd,&ms->wrfd,&ms->pid);
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

	
	LOG(PIL_INFO, "%s: %s", _("Host being rebooted"), host); 

	/* Expect ">" */
	if (StonithLookFor(ms->rdfd, Prompt, 10) < 0) {
		return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}

	/* All Right!  Power is back on.  Life is Good! */

	LOG(PIL_INFO, "%s: %s", _("Power restored to host"), host);

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
		LOG(PIL_CRIT, "%s", _("Cannot log into " DEVICE "."));
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
	LOG(PIL_INFO, "%s %d %s %s", _("Power to MS outlet(s)"), outletNum, _("turned"), onoff);
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
			g_strdown(sockname);
			if (strcmp(name, sockname) == 0) {
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
apcmaster_status(Stonith  *s)
{
	struct pluginDevice*	ms;
	int	rc;

	ERRIFNOTCONFIGED(s,S_OOPS);

	ms = (struct pluginDevice*) s->pinfo;

	if ((rc = MSRobustLogin(ms) != S_OK)) {
		LOG(PIL_CRIT, "%s", _("Cannot log into " DEVICE "."));
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
apcmaster_hostlist(Stonith  *s)
{
	char		NameMapping[128];
	char*		NameList[64];
	unsigned int	numnames = 0;
	char **		ret = NULL;
	struct pluginDevice*	ms;

	ERRIFNOTCONFIGED(s,NULL);

	ms = (struct pluginDevice*) s->pinfo;
		
	if (MSRobustLogin(ms) != S_OK) {
		LOG(PIL_CRIT, "%s", _("Cannot log into " DEVICE "."));
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
				LOG(PIL_CRIT, "out of memory");
				return(NULL);
			}
			g_strdown(nm);
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
			LOG(PIL_CRIT, "out of memory");
		}else{
			memcpy(ret, NameList, (numnames+1)*sizeof(char*));
		}
	}
	(void)MSLogout(ms);
	return(ret);
}

/*
 *	Parse the given configuration information, and stash it away...
 */

static int
apcmaster_parse_config_info(struct pluginDevice* ms, const char * info)
{
	static char dev[1024];
	static char user[1024];
	static char passwd[1024];

	if (ms->config) {
		return(S_OOPS);
	}

	if (sscanf(info, "%s %s %[^\n\r\t]", dev, user, passwd) == 3
	&&	strlen(passwd) > 1) {

		if ((ms->device = STRDUP(dev)) == NULL) {
			LOG(PIL_CRIT, "out of memory");
			return(S_OOPS);
		}
		if ((ms->user = STRDUP(user)) == NULL) {
			FREE(ms->device);
			ms->device=NULL;
			LOG(PIL_CRIT, "out of memory");
			return(S_OOPS);
		}
		if ((ms->passwd = STRDUP(passwd)) == NULL) {
			FREE(ms->device);
			ms->device=NULL;
			FREE(ms->user);
			ms->user=NULL;
			LOG(PIL_CRIT, "out of memory");
			return(S_OOPS);
		}
		ms->config = 1;
		return(S_OK);
	}
	return(S_BADCONFIG);
}

/*
 *	Connect to the given MS device.  We should add serial support here
 *	eventually...
 */
static int
MS_connect_device(struct pluginDevice * ms)
{
	char	TelnetCommand[256];

	snprintf(TelnetCommand, sizeof(TelnetCommand)
	,	"exec telnet %s 2>/dev/null", ms->device);

	ms->pid=STARTPROC(TelnetCommand, &ms->rdfd, &ms->wrfd);
	if (ms->pid <= 0) {
		return(S_OOPS);
	}
	return(S_OK);
}

/*
 *	Reset the given host on this Stonith device.  
 */
static int
apcmaster_reset_req(Stonith * s, int request, const char * host)
{
	int	rc = 0;
	int	lorc = 0;
	struct pluginDevice*	ms;

	ERRIFNOTCONFIGED(s,S_OOPS);

	ms = (struct pluginDevice*) s->pinfo;

	if ((rc = MSRobustLogin(ms)) != S_OK) {
		LOG(PIL_CRIT, "%s", _("Cannot log into " DEVICE "."));
		return(rc);
	}else{
		int noutlet; 
		noutlet = MSNametoOutlet(ms, host);
		if (noutlet < 1) {
			LOG(PIL_WARN, "%s %s %s [%s]"
			, ms->idinfo ,ms->unitid, _("doesn't control host"), host);
			Stonithkillcomm(&ms->rdfd,&ms->wrfd,&ms->pid);
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
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */
static int
apcmaster_set_config_file(Stonith* s, const char * configname)
{
	FILE *	cfgfile;
	char	APCMSid[256];

	struct pluginDevice*	ms;
	
	ERRIFWRONGDEV(s,S_OOPS);

	ms = (struct pluginDevice*) s->pinfo;

	if ((cfgfile = fopen(configname, "r")) == NULL)  {
		LOG(PIL_CRIT, "%s %s", _("Cannot open"), configname);
		return(S_BADCONFIG);
	}
	while (fgets(APCMSid, sizeof(APCMSid), cfgfile) != NULL){
		if (*APCMSid == '#' || *APCMSid == '\n' || *APCMSid == EOS) {
			continue;
		}
		return(apcmaster_parse_config_info(ms, APCMSid));
	}
	return(S_BADCONFIG);
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
apcmaster_set_config_info(Stonith* s, const char * info)
{
	struct pluginDevice* ms;

	ERRIFWRONGDEV(s,S_OOPS);

	ms = (struct pluginDevice *)s->pinfo;

	return(apcmaster_parse_config_info(ms, info));
}
static const char *
apcmaster_getinfo(Stonith * s, int reqtype)
{
	struct pluginDevice* ms;
	const char *		ret;

	ERRIFWRONGDEV(s,NULL);

	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	ms = (struct pluginDevice *)s->pinfo;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = ms->idinfo;
			break;

		case ST_CONF_INFO_SYNTAX:
			ret = _("IP-address login password\n"
			"The IP-address, login and password are white-space delimited.");
			break;

		case ST_CONF_FILE_SYNTAX:
			ret = _("IP-address login password\n"
			"The IP-address, login and password are white-space delimited.  "
			"All three items must be on one line.  "
			"Blank lines and lines beginning with # are ignored");
			break;

		case ST_DEVICEDESCR:
			ret = _("APC MasterSwitch (via telnet)\n"
 			"NOTE: The APC MasterSwitch accepts only one (telnet)\n"
			"connection/session a time. When one session is active,\n"
			"subsequent attempt to connect to the MasterSwitch"
			" will fail.");
			break;

		case ST_DEVICEURL:
			ret = "http://www.apc.com/";
			break;

		default:
			ret = NULL;
			break;
	}
	return ret;
}

/*
 *	APC MasterSwitch Stonith destructor...
 */
static void
apcmaster_destroy(Stonith *s)
{
	struct pluginDevice* ms;

	VOIDERRIFWRONGDEV(s);

	ms = (struct pluginDevice *)s->pinfo;

	ms->pluginid = NOTpluginID;
	Stonithkillcomm(&ms->rdfd,&ms->wrfd,&ms->pid);
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
	if (ms->idinfo != NULL) {
		FREE(ms->idinfo);
		ms->idinfo = NULL;
	}
	if (ms->unitid != NULL) {
		FREE(ms->unitid);
		ms->unitid = NULL;
	}
}

/* Create a new APC Master Switch Stonith device. */

static void *
apcmaster_new(void)
{
	struct pluginDevice*	ms = MALLOCT(struct pluginDevice);

	if (ms == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(ms, 0, sizeof(*ms));
	ms->pluginid = pluginid;
	ms->pid = -1;
	ms->rdfd = -1;
	ms->wrfd = -1;
	ms->config = 0;
	ms->user = NULL;
	ms->device = NULL;
	ms->passwd = NULL;
	ms->idinfo = NULL;
	ms->unitid = NULL;
	REPLSTR(ms->idinfo, DEVICE);
	REPLSTR(ms->unitid, "unknown");

	return((void *)ms);
}














