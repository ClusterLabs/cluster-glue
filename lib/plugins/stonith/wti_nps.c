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


/*
 * Version string that is filled in by CVS
 */
static const char *version __attribute__ ((unused)) = "$Revision: 1.3 $"; 

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
#define PIL_PLUGIN              wti_nps
#define PIL_PLUGIN_S            "wti_nps"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>
#include <clplumbing/cl_signal.h>

/*
 * wti_npsclose is called as part of unloading the wti_nps STONITH plugin.
 * If there was any global data allocated, or file descriptors opened, etc.
 * which is associated with the plugin, and not a single interface
 * in particular, here's our chance to clean it up.
 */

static void
wti_npsclosepi(PILPlugin*pi)
{
}


/*
 * wti_npscloseintf called as part of shutting down the wti_nps STONITH
 * interface.  If there was any global data allocated, or file descriptors
 * opened, etc.  which is associated with the wti_nps implementation,
 * here's our chance to clean it up.
 */
static PIL_rc
wti_npscloseintf(PILInterface* pi, void* pd)
{
	return PIL_OK;
}

static void *		wti_nps_new(void);
static void		wti_nps_destroy(Stonith *);
static int		wti_nps_set_config_file(Stonith *, const char * cfgname);
static int		wti_nps_set_config_info(Stonith *, const char * info);
static const char *	wti_nps_getinfo(Stonith * s, int InfoType);
static int		wti_nps_status(Stonith * );
static int		wti_nps_reset_req(Stonith * s, int request, const char * host);
static char **		wti_nps_hostlist(Stonith  *);
static void		wti_nps_free_hostlist(char **);

static struct stonith_ops wti_npsOps ={
	wti_nps_new,		/* Create new STONITH object	*/
	wti_nps_destroy,		/* Destroy STONITH object	*/
	wti_nps_set_config_file,	/* set configuration from file	*/
	wti_nps_set_config_info,	/* Get configuration from file	*/
	wti_nps_getinfo,		/* Return STONITH info string	*/
	wti_nps_status,		/* Return STONITH device status	*/
	wti_nps_reset_req,		/* Request a reset */
	wti_nps_hostlist,		/* Return list of supported hosts */
	wti_nps_free_hostlist	/* free above list */
};

PIL_PLUGIN_BOILERPLATE("1.0", Debug, wti_npsclosepi);
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
	,	&wti_npsOps
	,	wti_npscloseintf		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}
#define	DEVICE	"WTI Network Power Switch"

#define N_(text)	(text)
#define _(text)		dgettext(ST_TEXTDOMAIN, text)

/*
 *	I have a NPS-110.  This code has been tested with this switch.
 *	(Tested with NPS-230 and TPS-2 by lmb)
 */

struct WTINPS {
	const char *	NPSid;
	char *		idinfo;
	char *		unitid;
	pid_t		pid;
	int		rdfd;
	int		wrfd;
	int		config;
	char *		device;
	char *		passwd;
};

static const char * NPSid = "WTINPS-Stonith";
static const char * NOTnpsid = "Hey, dummy this has been destroyed (WTINPS)";

#define	ISWTINPS(i)	(((i)!= NULL && (i)->pinfo != NULL)	\
	&& ((struct WTINPS *)(i->pinfo))->NPSid == NPSid)

#define	ISCONFIGED(i)	(ISWTINPS(i) && ((struct WTINPS *)(i->pinfo))->config)

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
 *	Different expect strings that we get from the WTI
 *	Network Power Switch
 */

#define WTINPSSTR	" Power Switch"

static struct Etoken EscapeChar[] =	{ {"Escape character is '^]'.", 0, 0}
					,	{NULL,0,0}};
static struct Etoken password[] =	{ {"Password:", 0, 0} ,{NULL,0,0}};
static struct Etoken Prompt[] =	{ {"PS>", 0, 0} ,{NULL,0,0}};
static struct Etoken LoginOK[] =	{ {WTINPSSTR, 0, 0}
                    , {"Invalid password", 1, 0} ,{NULL,0,0}};
static struct Etoken Separator[] =	{ {"-----+", 0, 0} ,{NULL,0,0}};
/* Accept either a CR/NL or an NL/CR */
static struct Etoken CRNL[] =		{ {"\n\r",0,0},{"\r\n",0,0},{NULL,0,0}};

/* We may get a notice about rebooting, or a request for confirmation */
static struct Etoken Processing[] =	{ {"rocessing - please wait", 0, 0}
				,	{"(Y/N):", 1, 0}
				,	{NULL,0,0}};

static int	NPSLookFor(struct WTINPS* nps, struct Etoken * tlist, int timeout);
static int	NPS_connect_device(struct WTINPS * nps);
static int	NPSLogin(struct WTINPS * nps);
static int	NPSNametoOutlet(struct WTINPS*, const char * name, char **outlets);
static int	NPSReset(struct WTINPS*, char * outlets, const char * rebootid);
static int	NPSScanLine(struct WTINPS* nps, int timeout, char * buf, int max);
static int	NPSLogout(struct WTINPS * nps);
static void	NPSkillcomm(struct WTINPS * nps);

static int	NPS_parse_config_info(struct WTINPS* nps, const char * info);
#if defined(ST_POWERON) && defined(ST_POWEROFF)
static int	NPS_onoff(struct WTINPS*, const char * outlets, const char * unitid
,		int request);
#endif

/*
 *	We do these things a lot.  Here are a few shorthand macros.
 */

#define	SEND(s) (write(nps->wrfd, (s), strlen(s)))


#define	EXPECT(p,t)	{						\
			if (NPSLookFor(nps, p, t) < 0)			\
				return(errno == ETIMEDOUT			\
			?	S_TIMEOUT : S_OOPS);			\
			}

#define	NULLEXPECT(p,t)	{						\
				if (NPSLookFor(nps, p, t) < 0)		\
					return(NULL);			\
			}

#define	SNARF(s, to)	{						\
				if (NPSScanLine(nps,to,(s),sizeof(s))	\
				!=	S_OK)				\
					return(S_OOPS);			\
			}

#define	NULLSNARF(s, to)	{					\
				if (NPSScanLine(nps,to,(s),sizeof(s))	\
				!=	S_OK)				\
					return(NULL);			\
				}

/* Look for any of the given patterns.  We don't care which */

static int
NPSLookFor(struct WTINPS* nps, struct Etoken * tlist, int timeout)
{
	int	rc;
	if ((rc = EXPECT_TOK(nps->rdfd, tlist, timeout, NULL, 0)) < 0) {
		syslog(LOG_ERR, _("Did not find string: '%s' from" DEVICE ".")
		,	tlist[0].string);
		NPSkillcomm(nps);
	}
	return(rc);
}

/* Read and return the rest of the line */

static int
NPSScanLine(struct WTINPS* nps, int timeout, char * buf, int max)
{
	if (EXPECT_TOK(nps->rdfd, CRNL, timeout, buf, max) < 0) {
		syslog(LOG_ERR, ("Could not read line from " DEVICE "."));
		NPSkillcomm(nps);
		return(S_OOPS);
	}
	return(S_OK);
}


/* Attempt to login up to 20 times... */
static int
NPSRobustLogin(struct WTINPS * nps)
{
	int	rc=S_OOPS;
	int	j;

	for (j=0; j < 20 && rc != S_OK; ++j) {

	  if (nps->pid > 0) {
			NPSkillcomm(nps);
		}

	  if (NPS_connect_device(nps) != S_OK) {	
	      NPSkillcomm(nps);
	      continue;
	  }

	  rc = NPSLogin(nps);
	}
	return rc;
}

/* Login to the WTI Network Power Switch (NPS) */
static int
NPSLogin(struct WTINPS * nps)
{
	char		IDinfo[128];
	char *		idptr = IDinfo;

	EXPECT(EscapeChar, 10);
	/* Look for the unit type info */
	if (EXPECT_TOK(nps->rdfd, password, 2, IDinfo
	,	sizeof(IDinfo)) < 0) {
		syslog(LOG_ERR, _("No initial response from " DEVICE "."));
		NPSkillcomm(nps);
 		return(errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS);
	}
	idptr += strspn(idptr, WHITESPACE);
	/*
	 * We should be looking at something like this:
	 *	Enter Password: 
	 */

	SEND(nps->passwd);
	SEND("\r");
	/* Expect "Network Power Switch vX.YY" */

	switch (NPSLookFor(nps, LoginOK, 5)) {

		case 0:	/* Good! */
			break;

		case 1:	/* Uh-oh - bad password */
			syslog(LOG_ERR, _("Invalid password for " DEVICE "."));
			return(S_ACCESS);

		default:
			NPSkillcomm(nps);
			return(errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS);
	}
	return(S_OK);
}

/* Log out of the WTI NPS */

static int
NPSLogout(struct WTINPS* nps)
{
	int	rc;
	
	/* Send "/h" help command and expect back prompt */
	//SEND("/h\r");
	/* Expect "PS>" */
	rc = NPSLookFor(nps, Prompt, 5);

	/* "/x" is Logout, "/x,y" auto-confirms */
	SEND("/x,y\r");

	NPSkillcomm(nps);
	return(rc >= 0 ? S_OK : (errno == ETIMEDOUT ? S_TIMEOUT : S_OOPS));
}
static void
NPSkillcomm(struct WTINPS* nps)
{
        if (nps->rdfd >= 0) {
	        close(nps->rdfd);
	        nps->rdfd = -1;
	}
	if (nps->wrfd >= 0) {
	        close(nps->wrfd);
  	        nps->wrfd = -1;
	}
        if (nps->pid > 0) {
	        CL_KILL(nps->pid, SIGKILL);		
		(void)waitpid(nps->pid, NULL, 0);
		nps->pid = -1;
	}
}

/* Reset (power-cycle) the given outlets */
static int
NPSReset(struct WTINPS* nps, char * outlets, const char * rebootid)
{
	char		unum[32];

	/* Send "/h" help command and expect back prompt */
	SEND("/h\r");
	/* Expect "PS>" */
	EXPECT(Prompt, 5);
	
	/* Send REBOOT command for given outlets */
	snprintf(unum, sizeof(unum), "/BOOT %s,y\r", outlets);
	SEND(unum);
	
	/* Expect "Processing "... or "(Y/N)" (if confirmation turned on) */

	retry:
	switch (NPSLookFor(nps, Processing, 5)) {
		case 0: /* Got "Processing" Do nothing */
			break;

		case 1: /* Got that annoying command confirmation :-( */
			SEND("Y\r");
			goto retry;

		default: 
			return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}
	syslog(LOG_INFO, _("Host %s being rebooted."), rebootid);

	/* Expect "PS>" */
	if (NPSLookFor(nps, Prompt, 10) < 0) {
		return(errno == ETIMEDOUT ? S_RESETFAIL : S_OOPS);
	}

	/* All Right!  Power is back on.  Life is Good! */

	syslog(LOG_INFO, _("Power restored to host %s."), rebootid);
	SEND("/h\r");
	return(S_OK);
}

#if defined(ST_POWERON) && defined(ST_POWEROFF)
static int
NPS_onoff(struct WTINPS* nps, const char * outlets, const char * unitid, int req)
{
	char		unum[32];

	const char *	onoff = (req == ST_POWERON ? "/On" : "/Off");
	int	rc;

	if ((rc = NPSRobustLogin(nps) != S_OK)) {
		syslog(LOG_ERR, _("Cannot log into " DEVICE "."));
		return(rc);
	}
       
	/* Send "/h" help command and expect prompt back */
	SEND("/h\r");
	/* Expect "PS>" */
	EXPECT(Prompt, 5);

	/* Send ON/OFF command for given outlet */
	snprintf(unum, sizeof(unum), "%s %s,y\r", onoff, outlets);
	SEND(unum);

	/* Expect "Processing"... or "(Y/N)" (if confirmation turned on) */

	if (NPSLookFor(nps, Processing, 5) == 1) {
		/* They've turned on that annoying command confirmation :-( */
		SEND("Y\r");
	}
	EXPECT(Prompt, 10);

	/* All Right!  Command done. Life is Good! */
	syslog(LOG_NOTICE, _("Power to NPS outlet(s) %s turned %s."), outlets, onoff);
	return(S_OK);
}
#endif /* defined(ST_POWERON) && defined(ST_POWEROFF) */

/*
 *	Map the given host name into an (AC) Outlet number on the power strip
 */

static int
NPSNametoOutlet(struct WTINPS* nps, const char * name, char **outlets)
{
  	char	NameMapping[128];
  	int	sockno;
  	char	sockname[32];
  	int times = 0;
        char buf[32];
        int left = 17;
  	int ret = -1;
	
        
        if ((*outlets = (char *)MALLOC(left*sizeof(char))) == NULL) {
                syslog(LOG_ERR, "out of memory");
                return(-1);
        }
	
        strncpy(*outlets, "", left);
        left = left - 1;        /* ensure terminating '\0' */
  	/* Expect "PS>" */
  	EXPECT(Prompt, 5);
	
  	/* The status command output contains mapping of hosts to outlets */ 
    	SEND("/s\r");

 	/* Expect: "-----+" so we can skip over it... */
    	EXPECT(Separator, 5); 
	
  	do {
  		times++;
  		NameMapping[0] = EOS;
  		SNARF(NameMapping, 5);
  		
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
  			if (strcmp(name, sockname) == 0) {
  				ret = sockno;
  				sprintf(buf, "%d ", sockno);
  				strncat(*outlets, buf, left);
  				left = left - 2;
  			}
  		}
  	} while (strlen(NameMapping) > 2 && times < 8 && left > 0);

  	return(ret);
}

static int
wti_nps_status(Stonith  *s)
{
	struct WTINPS*	nps;
	int	rc;

	if (!ISWTINPS(s)) {
		syslog(LOG_ERR, "invalid argument to NPS_status");
		return(S_OOPS);
	}
	if (!ISCONFIGED(s)) {
		syslog(LOG_ERR
		,	"unconfigured stonith object in NPS_status");
		return(S_OOPS);
	}
	nps = (struct WTINPS*) s->pinfo;

       	if ((rc = NPSRobustLogin(nps) != S_OK)) {
		syslog(LOG_ERR, _("Cannot log into " DEVICE "."));
		return(rc);
	}

	/* Send "/h" help command and expect back prompt */
	SEND("/h\r");
	/* Expect "PS>" */
	EXPECT(Prompt, 5);

	return(NPSLogout(nps));
}

/*
 *	Return the list of hosts (outlet names) for the devices on this NPS unit
 */

static char **
wti_nps_hostlist(Stonith  *s)
{
	char		NameMapping[128];
	char*		NameList[64];
	unsigned int		numnames = 0;
	char **		ret = NULL;
	struct WTINPS*	nps;


	if (!ISWTINPS(s)) {
		syslog(LOG_ERR, "invalid argument to NPS_list_hosts");
		return(NULL);
	}
	if (!ISCONFIGED(s)) {
		syslog(LOG_ERR
		,	"unconfigured stonith object in NPS_list_hosts");
		return(NULL);
	}
	nps = (struct WTINPS*) s->pinfo;
	if (NPS_connect_device(nps) != S_OK) {
		return(NULL);
	}
 
	if (NPSRobustLogin(nps) != S_OK) {
		syslog(LOG_ERR, _("Cannot log into " DEVICE "."));
		return(NULL);
	}
	
	/* Expect "PS>" */
	NULLEXPECT(Prompt, 5);
	
	/* The status command output contains mapping of hosts to outlets */
	SEND("/s\r");

	/* Expect: "-----" so we can skip over it... */
	NULLEXPECT(Separator, 5);
	NULLEXPECT(CRNL, 5);
	
	/* Looks Good!  Parse the status output */

	do {
		int	sockno;
		char	sockname[64];
		NameMapping[0] = EOS;
		NULLSNARF(NameMapping, 5);
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

	if (numnames >= 1) {
		ret = (char **)MALLOC((numnames+1)*sizeof(char*));
		if (ret == NULL) {
			syslog(LOG_ERR, "out of memory");
		}else{
			memset(ret, 0, (numnames+1)*sizeof(char*));
			memcpy(ret, NameList, (numnames+1)*sizeof(char*));
		}
	}
	(void)NPSLogout(nps);
	
	return(ret);
	
}

static void
wti_nps_free_hostlist (char ** hlist)
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
NPS_parse_config_info(struct WTINPS* nps, const char * info)
{
	static char dev[1024];
	static char passwd[1024];

	if (nps->config) {
		return(S_OOPS);
	}


	if (sscanf(info, "%s %[^\n\r\t]", dev, passwd) == 2
	&&	strlen(passwd) > 1) {

		if ((nps->device = (char *)MALLOC(strlen(dev)+1)) == NULL) {
			syslog(LOG_ERR, "out of memory");
			return(S_OOPS);
		}
		if ((nps->passwd = (char *)MALLOC(strlen(passwd)+1)) == NULL) {
			free(nps->device);
			nps->device=NULL;
			syslog(LOG_ERR, "out of memory");
			return(S_OOPS);
		}
		strcpy(nps->device, dev);
		strcpy(nps->passwd, passwd);
		nps->config = 1;
		return(S_OK);
	}
	return(S_BADCONFIG);
}

/*
 *	Connect to the given NPS device.  We should add serial support here
 *	eventually...
 */
static int
NPS_connect_device(struct WTINPS * nps)
{
	char	TelnetCommand[256];

	snprintf(TelnetCommand, sizeof(TelnetCommand)
	,	"exec telnet %s 2>/dev/null", nps->device);
	
	nps->pid=STARTPROC(TelnetCommand, &nps->rdfd, &nps->wrfd);
	if (nps->pid <= 0) {	
		return(S_OOPS);
	}
	return(S_OK);
}

/*
 *	Reset the given host on this Stonith device.  
 */
static int
wti_nps_reset_req(Stonith * s, int request, const char * host)
{
	int	rc = 0;
	int	lorc = 0;
	struct WTINPS*	nps;

	if (!ISWTINPS(s)) {
		syslog(LOG_ERR, "invalid argument to NPS_reset_host");
		return(S_OOPS);
	}
	if (!ISCONFIGED(s)) {
		syslog(LOG_ERR
		,	"unconfigured stonith object in NPS_reset_host");
		return(S_OOPS);
	}
	nps = (struct WTINPS*) s->pinfo;

        if ((rc = NPSRobustLogin(nps)) != S_OK) {
		syslog(LOG_ERR, _("Cannot log into " DEVICE "."));
        }else{
	        char *outlets;
		int noutlet;
     
		noutlet = NPSNametoOutlet(nps, host, &outlets);
		    
		if (noutlet < 1) {
			syslog(LOG_WARNING, _("%s %s "
			"doesn't control host [%s]."), nps->idinfo
			,	nps->unitid, host);
			NPSkillcomm(nps);
			return(S_BADHOST);
		}
		switch(request) {

#if defined(ST_POWERON) && defined(ST_POWEROFF)
		case ST_POWERON:
		case ST_POWEROFF:
			rc = NPS_onoff(nps, outlets, host, request);
			if (outlets != NULL) {
			  free(outlets);
			  outlets = NULL;
			}
			break;
#endif
		case ST_GENERIC_RESET:
			rc = NPSReset(nps, outlets, host);
			break;
			if (outlets != NULL) {
			  free(outlets);
			  outlets = NULL;
			}
		default:
			rc = S_INVAL;			
			if (outlets != NULL) {
			  free(outlets);
			  outlets = NULL;
			}
			break;
		}
	}

	lorc = NPSLogout(nps);
	return(rc != S_OK ? rc : lorc);
}

/*
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */
static int
wti_nps_set_config_file(Stonith* s, const char * configname)
{
	FILE *	cfgfile;

	char	WTINPSid[256];

	struct WTINPS*	nps;

	if (!ISWTINPS(s)) {
		syslog(LOG_ERR, "invalid argument to NPS_set_configfile");
		return(S_OOPS);
	}
	nps = (struct WTINPS*) s->pinfo;

	if ((cfgfile = fopen(configname, "r")) == NULL)  {
		syslog(LOG_ERR, _("Cannot open %s"), configname);
		return(S_BADCONFIG);
	}
	while (fgets(WTINPSid, sizeof(WTINPSid), cfgfile) != NULL){
		if (*WTINPSid == '#' || *WTINPSid == '\n' || *WTINPSid == EOS) {
			continue;
		}
		return(NPS_parse_config_info(nps, WTINPSid));
	}
	return(S_BADCONFIG);
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
wti_nps_set_config_info(Stonith* s, const char * info)
{
	struct WTINPS* nps;

	if (!ISWTINPS(s)) {
		syslog(LOG_ERR, "NPS_provide_config_info: invalid argument");
		return(S_OOPS);
	}
	nps = (struct WTINPS *)s->pinfo;

	return(NPS_parse_config_info(nps, info));
}

static const char *
wti_nps_getinfo(Stonith * s, int reqtype)
{
	struct WTINPS* nps;
	const char *	ret;

	if (!ISWTINPS(s)) {
		syslog(LOG_ERR, "NPS_idinfo: invalid argument");
		return NULL;
	}
	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	nps = (struct WTINPS *)s->pinfo;

	switch (reqtype) {

		case ST_DEVICEID:
			ret = nps->idinfo;
			break;

		case ST_CONF_INFO_SYNTAX:
			ret = _("IP-address password\n"
			"The IP-address and password are white-space delimited.");
			break;

		case ST_CONF_FILE_SYNTAX:
			ret = _("IP-address password\n"
			"The IP-address and password are white-space delimited.  "
			"All three items must be on one line.  "
			"Blank lines and lines beginning with # are ignored");
			break;

		case ST_DEVICEDESCR:
			ret = _("Western Telematic (WTI) Network Power Switch Devices (NPS-xxx)\n"
 			"Also supports the WTI Telnet Power Switch Devices (TPS-xxx)\n"
 			"NOTE: The WTI Network Power Switch, accepts only "
			"one (telnet) connection/session at a time.");
			break;

		case ST_DEVICEURL:
			ret = "http://www.wti.com/";
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
wti_nps_destroy(Stonith *s)
{
	struct WTINPS* nps;

	if (!ISWTINPS(s)) {
		syslog(LOG_ERR, "wtinps_del: invalid argument");
		return;
	}
	nps = (struct WTINPS *)s->pinfo;

	nps->NPSid = NOTnpsid;
	NPSkillcomm(nps);
	if (nps->device != NULL) {
		FREE(nps->device);
		nps->device = NULL;
	}
	if (nps->passwd != NULL) {
		FREE(nps->passwd);
		nps->passwd = NULL;
	}
	if (nps->idinfo != NULL) {
		FREE(nps->idinfo);
		nps->idinfo = NULL;
	}
	if (nps->unitid != NULL) {
		FREE(nps->unitid);
		nps->unitid = NULL;
	}
}

/* Create a new BayTech Stonith device. */

static void *
wti_nps_new(void)
{
	struct WTINPS*	nps = MALLOCT(struct WTINPS);

	if (nps == NULL) {
		syslog(LOG_ERR, "out of memory");
		return(NULL);
	}
	memset(nps, 0, sizeof(*nps));
	nps->NPSid = NPSid;
	nps->pid = -1;
	nps->rdfd = -1;
	nps->wrfd = -1;
	nps->config = 0;
	nps->device = NULL;
	nps->passwd = NULL;
	nps->idinfo = NULL;
	nps->unitid = NULL;
	REPLSTR(nps->idinfo, DEVICE);
	REPLSTR(nps->unitid, "unknown");

	return((void *)nps);
}





