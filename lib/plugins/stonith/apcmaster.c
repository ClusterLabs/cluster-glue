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
static const char *version __attribute__ ((unused)) = "$Revision: 1.4 $"; 

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
#define PIL_PLUGIN              apcmaster
#define PIL_PLUGIN_S            "apcmaster"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

#include "stonith_signal.h"

/*
 * apcmasterclose is called as part of unloading the apcmaster STONITH plugin.
 * If there was any global data allocated, or file descriptors opened, etc.
 * which is associated with the plugin, and not a single interface
 * in particular, here's our chance to clean it up.
 */

static void
apcmasterclosepi(PILPlugin*pi)
{
}


/*
 * apcmastercloseintf called as part of shutting down the apcmaster STONITH
 * interface.  If there was any global data allocated, or file descriptors
 * opened, etc.  which is associated with the apcmaster implementation,
 * here's our chance to clean it up.
 */
static PIL_rc
apcmastercloseintf(PILInterface* pi, void* pd)
{
	return PIL_OK;
}

static void *		apcmaster_new(void);
static void		apcmaster_destroy(Stonith *);
static int		apcmaster_set_config_file(Stonith *, const char * cfgname);
static int		apcmaster_set_config_info(Stonith *, const char * info);
static const char *	apcmaster_getinfo(Stonith * s, int InfoType);
static int		apcmaster_status(Stonith * );
static int		apcmaster_reset_req(Stonith * s, int request, const char * host);
static char **		apcmaster_hostlist(Stonith  *);
static void		apcmaster_free_hostlist(char **);

static struct stonith_ops apcmasterOps ={
	apcmaster_new,		/* Create new STONITH object	*/
	apcmaster_destroy,		/* Destroy STONITH object	*/
	apcmaster_set_config_file,	/* set configuration from file	*/
	apcmaster_set_config_info,	/* Get configuration from file	*/
	apcmaster_getinfo,		/* Return STONITH info string	*/
	apcmaster_status,		/* Return STONITH device status	*/
	apcmaster_reset_req,		/* Request a reset */
	apcmaster_hostlist,		/* Return list of supported hosts */
	apcmaster_free_hostlist	/* free above list */
};

PIL_PLUGIN_BOILERPLATE("1.0", Debug, apcmasterclosepi);
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
	,	&apcmasterOps
	,	apcmastercloseintf		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

#define	DEVICE	"APC MasterSwitch"

#define N_(text)	(text)
#define _(text)		dgettext(ST_TEXTDOMAIN, text)

/*
 *	I have an AP9211.  This code has been tested with this switch.
 */

struct APCMS {
	const char *	MSid;
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

static const char * MSid = "APCMS-Stonith";
static const char * NOTmsid = "Hey dummy, this has been destroyed (APCMS)";

#define	ISAPCMS(i)	(((i)!= NULL && (i)->pinfo != NULL)	\
	&& ((struct APCMS *)(i->pinfo))->MSid == MSid)

#define	ISCONFIGED(i)	(ISAPCMS(i) && ((struct APCMS *)(i->pinfo))->config)

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
/* Accept either a CR/NL or an NL/CR */
static struct Etoken CRNL[] =		{ {"\n\r",0,0},{"\r\n",0,0},{NULL,0,0}};

/* We may get a notice about rebooting, or a request for confirmation */
static struct Etoken Processing[] =	{ {"Press <ENTER> to continue", 0, 0}
				,	{"Enter 'YES' to continue", 1, 0}
				,	{NULL,0,0}};

static int	MSLookFor(struct APCMS* ms, struct Etoken * tlist, int timeout);
static int	MS_connect_device(struct APCMS * ms);
static int	MSLogin(struct APCMS * ms);
static int	MSRobustLogin(struct APCMS * ms);
static int	MSNametoOutlet(struct APCMS*, const char * name);
static int	MSReset(struct APCMS*, int outletNum, const char * host);
static int	MSScanLine(struct APCMS* ms, int timeout, char * buf, int max);
static int	MSLogout(struct APCMS * ms);
static void	MSkillcomm(struct APCMS * ms);

static int	apcmaster_parse_config_info(struct APCMS* ms, const char * info);

#if defined(ST_POWERON) && defined(ST_POWEROFF)
static int	apcmaster_onoff(struct APCMS*, int outletnum, const char * unitid
,		int request);
#endif
void	apcmaster_destroy(Stonith *);
void *	apcmaster_new(void);

/*
 *	We do these things a lot.  Here are a few shorthand macros.
 */

#define	SEND(s)         (write(ms->wrfd, (s), strlen(s)))

#define	EXPECT(p,t)	{						\
			if (MSLookFor(ms, p, t) < 0)			\
				return(errno == ETIMEDOUT			\
			?	S_TIMEOUT : S_OOPS);			\
			}

#define	NULLEXPECT(p,t)	{						\
				if (MSLookFor(ms, p, t) < 0)		\
					return(NULL);			\
			}

#define	SNARF(s, to)	{						\
				if (MSScanLine(ms,to,(s),sizeof(s))	\
				!=	S_OK)				\
					return(S_OOPS);			\
			}

#define	NULLSNARF(s, to)	{					\
				if (MSScanLine(ms,to,(s),sizeof(s))	\
				!=	S_OK)				\
					return(NULL);			\
				}

/* Look for any of the given patterns.  We don't care which */

static int
MSLookFor(struct APCMS* ms, struct Etoken * tlist, int timeout)
{
	int	rc;
	if ((rc = EXPECT_TOK(ms->rdfd, tlist, timeout, NULL, 0)) < 0) {
		syslog(LOG_ERR, _("Did not find string: '%s' from" DEVICE ".")
		,	tlist[0].string);
		MSkillcomm(ms);
	}
	return(rc);
}

/* Read and return the rest of the line */

static int
MSScanLine(struct APCMS* ms, int timeout, char * buf, int max)
{
	if (EXPECT_TOK(ms->rdfd, CRNL, timeout, buf, max) < 0) {
		syslog(LOG_ERR, ("Could not read line from " DEVICE "."));
		MSkillcomm(ms);
		return(S_OOPS);
	}
	return(S_OK);
}

/* Login to the APC Master Switch */

static int
MSLogin(struct APCMS * ms)
{
        EXPECT(EscapeChar, 10);

  	/* 
	 * We should be looking at something like this:
         *	User Name :
	 */
	EXPECT(login, 10);
	SEND(ms->user);       
	SEND("\r");

	/* Expect "Password  :" */
	EXPECT(password, 10);
	SEND(ms->passwd);
	SEND("\r");
 
	switch (MSLookFor(ms, LoginOK, 30)) {

		case 0:	/* Good! */
			break;

		case 1:	/* Uh-oh - bad password */
			syslog(LOG_ERR, _("Invalid password for " DEVICE "."));
			return(S_ACCESS);

		default:
			MSkillcomm(ms);
			return(errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS);
	} 

	return(S_OK);
}

/* Attempt to login up to 20 times... */

static int
MSRobustLogin(struct APCMS * ms)
{
	int	rc=S_OOPS;
	int	j;

	for (j=0; j < 20 && rc != S_OK; ++j) {

	  if (ms->pid > 0) {
			MSkillcomm(ms);
		}

		if (MS_connect_device(ms) != S_OK) {	
		        MSkillcomm(ms);
			continue;
		}

		rc = MSLogin(ms);
	}
	return rc;
}

/* Log out of the APC Master Switch */

static 
int MSLogout(struct APCMS* ms)
{
	int	rc;

	/* Make sure we're in the right menu... */
 	/*SEND("\033\033\033\033\033\033\033"); */
        SEND("\033");
	EXPECT(Prompt, 5);
        SEND("\033");
	EXPECT(Prompt, 5);
        SEND("\033");
	EXPECT(Prompt, 5);
        SEND("\033");
	EXPECT(Prompt, 5);
	SEND("\033");
	
	/* Expect "> " */
	rc = MSLookFor(ms, Prompt, 5);

	/* "4" is logout */
	SEND("4\r");

	MSkillcomm(ms);
	return(rc >= 0 ? S_OK : (errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS));
}
static void
MSkillcomm(struct APCMS* ms)
{
        if (ms->rdfd >= 0) {
		close(ms->rdfd);
		ms->rdfd = -1;
	}
	if (ms->wrfd >= 0) {
		close(ms->wrfd);
		ms->wrfd = -1;
	}
	if (ms->pid > 0) {
		STONITH_KILL(ms->pid, SIGKILL);
		(void)waitpid(ms->pid, NULL, 0);
		ms->pid = -1;
	}
}

/* Reset (power-cycle) the given outlets */
static int
MSReset(struct APCMS* ms, int outletNum, const char *host)
{
  	char		unum[32];


	/* Make sure we're in the top level menu */
        SEND("\033");
	EXPECT(Prompt, 5);
        SEND("\033");
	EXPECT(Prompt, 5);
        SEND("\033");
	EXPECT(Prompt, 5);
        SEND("\033");
	EXPECT(Prompt, 5);
	SEND("\033");
	
	/* Expect ">" */
	EXPECT(Prompt, 5);

	/* Request menu 1 (Device Control) */
	SEND("1\r");

	/* Select requested outlet */
	EXPECT(Prompt, 5);
	snprintf(unum, sizeof(unum), "%i\r", outletNum);
  	SEND(unum);

	/* Select menu 1 (Control Outlet) */
	EXPECT(Prompt, 5);
	SEND("1\r");

	/* Select menu 3 (Immediate Reboot) */
	EXPECT(Prompt, 5);
	SEND("3\r");

	/* Expect "Press <ENTER> " or "Enter 'YES'" (if confirmation turned on) */
	retry:
	switch (MSLookFor(ms, Processing, 5)) {
		case 0: /* Got "Press <ENTER>" Do so */
			SEND("\r");
			break;

		case 1: /* Got that annoying command confirmation :-( */
			SEND("YES\r");
			goto retry;

		default: 
			return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}
	syslog(LOG_INFO, _("Host %s being rebooted."), host);

	/* Expect ">" */
	if (MSLookFor(ms, Prompt, 10) < 0) {
		return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}

	/* All Right!  Power is back on.  Life is Good! */

	syslog(LOG_INFO, _("Power restored to host %s."), host);

	/* Return to top level menu */
	SEND("\033");
	EXPECT(Prompt, 5);
        SEND("\033");
	EXPECT(Prompt, 5);
        SEND("\033");
	EXPECT(Prompt, 5);
        SEND("\033");
	EXPECT(Prompt, 5);
	SEND("\033");
	EXPECT(Prompt, 5);
	SEND("\033");

	return(S_OK);
}

#if defined(ST_POWERON) && defined(ST_POWEROFF)
static int
apcmaster_onoff(struct APCMS* ms, int outletNum, const char * unitid, int req)
{
	char		unum[32];

	const char *	onoff = (req == ST_POWERON ? "1\r" : "2\r");
	int	rc;

	if ((rc = MSRobustLogin(ms) != S_OK)) {
		syslog(LOG_ERR, _("Cannot log into " DEVICE "."));
		return(rc);
	}
	
	/* Make sure we're in the top level menu */
        SEND("\033");
	EXPECT(Prompt, 5);
        SEND("\033");
	EXPECT(Prompt, 5);
        SEND("\033");
	EXPECT(Prompt, 5);
        SEND("\033");
	EXPECT(Prompt, 5);
	SEND("\033");

	/* Expect ">" */
	EXPECT(Prompt, 5);

	/* Request menu 1 (Device Control) */
	SEND("1\r");

	/* Select requested outlet */
  	snprintf(unum, sizeof(unum), "%d\r", outletNum); 
  	SEND(unum); 

	/* Select menu 1 (Control Outlet) */
	SEND("1\r");

	/* Send ON/OFF command for given outlet */
	SEND(onoff);

	/* Expect "Press <ENTER> " or "Enter 'YES'" (if confirmation turned on) */
	retry:
	switch (MSLookFor(ms, Processing, 5)) {
		case 0: /* Got "Press <ENTER>" Do so */
			SEND("\r");
			break;

		case 1: /* Got that annoying command confirmation :-( */
			SEND("YES\r");
			goto retry;

		default: 
			return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}
	
	EXPECT(Prompt, 10);

	/* All Right!  Command done. Life is Good! */
	syslog(LOG_NOTICE, _("Power to MS outlet(s) %d turned %s."), outletNum, onoff);
	/* Pop back to main menu */
	SEND("\033\033\033\033\033\033\033\r");
	return(S_OK);
}
#endif /* defined(ST_POWERON) && defined(ST_POWEROFF) */

/*
 *	Map the given host name into an (AC) Outlet number on the power strip
 */

static int
MSNametoOutlet(struct APCMS* ms, const char * name)
{
	char	NameMapping[128];
	int	sockno;
	char	sockname[32];
	int times = 0;
	int ret = -1;

	/* Verify that we're in the top-level menu */
	EXPECT(Prompt, 5);
	SEND("\033");
	EXPECT(Prompt, 5);
	SEND("\033");	
	EXPECT(Prompt, 5);
	SEND("\033");
	EXPECT(Prompt, 5);
	SEND("\033");

	/* Expect ">" */
	EXPECT(Prompt, 5);
	
	/* Request menu 1 (Device Control) */
	SEND("1\r");

	/* Expect: "-----" so we can skip over it... */
	EXPECT(Separator, 5);
	EXPECT(CRNL, 5);
	EXPECT(CRNL, 5);

	/* Looks Good!  Parse the status output */

	do {
		times++;
		NameMapping[0] = EOS;
		SNARF(NameMapping, 5);
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
			if (strcmp(name, sockname) == 0) {
				ret = sockno;
			}
		}
	} while (strlen(NameMapping) > 2 && times < 8);

	/* Pop back out to the top level menu */
	EXPECT(Prompt, 5);
	SEND("\033");
	EXPECT(Prompt, 5);
	SEND("\033");	
	EXPECT(Prompt, 5);
	SEND("\033");
	EXPECT(Prompt, 5);
	SEND("\033");
	return(ret);
}

int
apcmaster_status(Stonith  *s)
{
	struct APCMS*	ms;
	int	rc;

	if (!ISAPCMS(s)) {
		syslog(LOG_ERR, "invalid argument to apcmaster_status");
		return(S_OOPS);
	}
	if (!ISCONFIGED(s)) {
		syslog(LOG_ERR
		,	"unconfigured stonith object in apcmaster_status");
		return(S_OOPS);
	}
	ms = (struct APCMS*) s->pinfo;

	if ((rc = MSRobustLogin(ms) != S_OK)) {
		syslog(LOG_ERR, _("Cannot log into " DEVICE "."));
		return(rc);
	}


	/* Expect ">" */
	SEND("\033\r");
	EXPECT(Prompt, 5);

	return(MSLogout(ms));
}

/*
 *	Return the list of hosts (outlet names) for the devices on this MS unit
 */

char **
apcmaster_hostlist(Stonith  *s)
{
	char		NameMapping[128];
	char*		NameList[64];
	unsigned int	numnames = 0;
	char **		ret = NULL;
	struct APCMS*	ms;


	if (!ISAPCMS(s)) {
		syslog(LOG_ERR, "invalid argument to apcmaster_list_hosts");
		return(NULL);
	}
	
	if (!ISCONFIGED(s)) {
		syslog(LOG_ERR
		,	"unconfigured stonith object in apcmaster_list_hosts");
		return(NULL);
	}

	ms = (struct APCMS*) s->pinfo;
		
	if (MSRobustLogin(ms) != S_OK) {
		syslog(LOG_ERR, _("Cannot log into " DEVICE "."));
		return(NULL);
	}


	/* Expect ">" */
	NULLEXPECT(Prompt, 10);

	/* Request menu 1 (Device Control) */
	SEND("1\r");
	

	/* Expect: "-----" so we can skip over it... */
	NULLEXPECT(Separator, 5);
	NULLEXPECT(CRNL, 5);
	NULLEXPECT(CRNL, 5);

	/* Looks Good!  Parse the status output */
	do {
		int	sockno;
		char	sockname[64];
		NameMapping[0] = EOS;
		NULLSNARF(NameMapping, 5);
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
			if ((nm = (char*)MALLOC(strlen(sockname)+1)) == NULL) {
				syslog(LOG_ERR, "out of memory");
				return(NULL);
			}
			memset(nm, 0, strlen(sockname)+1);
			strcpy(nm, sockname);
			NameList[numnames] = nm;
			++numnames;
			NameList[numnames] = NULL;
		}
	} while (strlen(NameMapping) > 2);

	/* Pop back out to the top level menu */
    	SEND("\033");
        NULLEXPECT(Prompt, 10);
    	SEND("\033");
        NULLEXPECT(Prompt, 10);
    	SEND("\033");
        NULLEXPECT(Prompt, 10);
    	SEND("\033");
	NULLEXPECT(Prompt, 10);
      

	if (numnames >= 1) {
		ret = (char **)MALLOC((numnames+1)*sizeof(char*));
		if (ret == NULL) {
			syslog(LOG_ERR, "out of memory");
		}else{
			memcpy(ret, NameList, (numnames+1)*sizeof(char*));
		}
	}
	(void)MSLogout(ms);
	return(ret);
}

void
apcmaster_free_hostlist (char ** hlist)
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
apcmaster_parse_config_info(struct APCMS* ms, const char * info)
{
	static char dev[1024];
	static char user[1024];
	static char passwd[1024];

	if (ms->config) {
		return(S_OOPS);
	}


	if (sscanf(info, "%s %s %[^\n\r\t]", dev, user, passwd) == 3
	&&	strlen(passwd) > 1) {

		if ((ms->device = (char *)MALLOC(strlen(dev)+1)) == NULL) {
			syslog(LOG_ERR, "out of memory");
			return(S_OOPS);
		}
		if ((ms->user = (char *)MALLOC(strlen(user)+1)) == NULL) {
			free(ms->device);
			ms->device=NULL;
			syslog(LOG_ERR, "out of memory");
			return(S_OOPS);
		}
		if ((ms->passwd = (char *)MALLOC(strlen(passwd)+1)) == NULL) {
			free(ms->device);
			ms->device=NULL;
			free(ms->user);
			ms->user=NULL;
			syslog(LOG_ERR, "out of memory");
			return(S_OOPS);
		}
		strcpy(ms->device, dev);
		strcpy(ms->user, user);
		strcpy(ms->passwd, passwd);
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
MS_connect_device(struct APCMS * ms)
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
int
apcmaster_reset_req(Stonith * s, int request, const char * host)
{
	int	rc = 0;
	int	lorc = 0;
	struct APCMS*	ms;

	if (!ISAPCMS(s)) {
		syslog(LOG_ERR, "invalid argument to apcmaster_reset_req");
		return(S_OOPS);
	}
	if (!ISCONFIGED(s)) {
		syslog(LOG_ERR
		,	"unconfigured stonith object in apc_master_reset_req");
		return(S_OOPS);
	}
	ms = (struct APCMS*) s->pinfo;

	if ((rc = MSRobustLogin(ms)) != S_OK) {
		syslog(LOG_ERR, _("Cannot log into " DEVICE "."));
		return(rc);
	}else{
		int noutlet; 
		noutlet = MSNametoOutlet(ms, host);
		if (noutlet < 1) {
			syslog(LOG_WARNING, _("%s %s "
			"doesn't control host [%s]."), ms->idinfo
			,	ms->unitid, host);
			MSkillcomm(ms);
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
int
apcmaster_set_config_file(Stonith* s, const char * configname)
{
	FILE *	cfgfile;

	char	APCMSid[256];

	struct APCMS*	ms;

	if (!ISAPCMS(s)) {
		syslog(LOG_ERR, "invalid argument to apcmaster_set_config_file");
		return(S_OOPS);
	}
	ms = (struct APCMS*) s->pinfo;

	if ((cfgfile = fopen(configname, "r")) == NULL)  {
		syslog(LOG_ERR, _("Cannot open %s"), configname);
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
int
apcmaster_set_config_info(Stonith* s, const char * info)
{
	struct APCMS* ms;

	if (!ISAPCMS(s)) {
		syslog(LOG_ERR, "apcmaster_set_config_info: invalid argument");
		return(S_OOPS);
	}
	ms = (struct APCMS *)s->pinfo;

	return(apcmaster_parse_config_info(ms, info));
}
const char *
apcmaster_getinfo(Stonith * s, int reqtype)
{
	struct APCMS* ms;
	const char *		ret;

	if (!ISAPCMS(s)) {
		syslog(LOG_ERR, "MS_idinfo: invalid argument");
		return NULL;
	}
	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	ms = (struct APCMS *)s->pinfo;

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
void
apcmaster_destroy(Stonith *s)
{
	struct APCMS* ms;

	if (!ISAPCMS(s)) {
		syslog(LOG_ERR, "apcms_del: invalid argument");
		return;
	}
	ms = (struct APCMS *)s->pinfo;

	ms->MSid = NOTmsid;
	MSkillcomm(ms);
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

void *
apcmaster_new(void)
{
	struct APCMS*	ms = MALLOCT(struct APCMS);

	if (ms == NULL) {
		syslog(LOG_ERR, "out of memory");
		return(NULL);
	}
	memset(ms, 0, sizeof(*ms));
	ms->MSid = MSid;
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














