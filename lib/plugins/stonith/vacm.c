
/******************************************************************************
*
*    Copyright 2000 Sistina Software, Inc.
*    Tiny bits Copyright 2000 Alan Robertson <alanr@unix.sh>
*    Tiny bits Copyright 2000 Zac Sprackett, VA Linux Systems
*    Tiny bits Copyright 2005 International Business Machines
*    Significantly Mangled by Sun Jiang Dong <sunjd@cn.ibm.com>, IBM, 2005	
*
*    This is free software released under the GNU General Public License.
*    There is no warranty for this software.  See the file COPYING for
*    details.
*
*    See the file CONTRIBUTORS for a list of contributors.
*
*    This file is maintained by:
*      Michael C Tilstra <conrad@sistina.com>
*
*    Becasue I have no device to test, now I just make it pass the compiling
*    with vacm-2.0.5a. Please review before using.
*		Sun Jiang Dong <sunjd@cn.ibm.com>, IBM, 2005
*
*    This module provides a driver for the VA Linux Cluster Manager.
*    For more information on VACM, see http://vacm.sourceforge.net/
*
*    This module is rather poorly commented.  But if you've read the
*    VACM Manual, and looked at the code example they have, this
*    should make pretty clean sense. (You obiviously should have
*    looked at the other stonith source too)
* 
*/

/*
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
 
#define DEVICE			"VA Linux Cluster Manager"

#include "stonith_plugin_common.h"
#include "vacmclient_api.h"

#define PIL_PLUGIN              vacm
#define PIL_PLUGIN_S            "vacm"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

static StonithPlugin *	vacm_new(const char *);
static void		vacm_destroy(StonithPlugin *);
static const char * const *	vacm_get_confignames(StonithPlugin *);
static int		vacm_set_config(StonithPlugin *, StonithNVpair *);
static const char *	vacm_getinfo(StonithPlugin * s, int InfoType);
static int		vacm_status(StonithPlugin * );
static int		vacm_reset_req(StonithPlugin * s, int request, const char * host);
static char **		vacm_hostlist(StonithPlugin  *);

static struct stonith_ops vacmOps ={
	vacm_new,		/* Create new STONITH object	*/
	vacm_destroy,		/* Destroy STONITH object	*/
	vacm_getinfo,		/* Return STONITH info string	*/
	vacm_get_confignames,	/* Return configuration parameters */
	vacm_set_config,	/* Set configuration		*/
	vacm_status,		/* Return STONITH device status	*/
	vacm_reset_req,		/* Request a reset */
	vacm_hostlist,		/* Return list of supported hosts */
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug);
static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static StonithImports*		OurImports;
static void*			interfprivate;

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
	,	&vacmOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*structs*/
struct pluginDevice {
	StonithPlugin sp; 
	const char * pluginid;
	const char * idinfo;
	void *h; /* a handle to the nexxus. */
	char *	nexxus;
	char *	user;
	char *	passwd;
};

#define ST_NEXXUS   "nexxus"

static const char * pluginid = "VACMDevice-Stonith";
static const char * NOTpluginid = "VACM device has been destroyed";

#include "stonith_config_xml.h"

#define XML_NEXXUS_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	ST_NEXXUS \
	XML_PARM_SHORTDESC_END

#define XML_NEXXUS_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The Nexxus component of the VA Cluster Manager" \
	XML_PARM_LONGDESC_END

#define XML_NEXXUS_PARM \
	XML_PARAMETER_BEGIN(ST_NEXXUS, "string", "1", "1") \
	  XML_NEXXUS_SHORTDESC \
	  XML_NEXXUS_LONGDESC \
	XML_PARAMETER_END

static const char *vacmXML = 
  XML_PARAMETERS_BEGIN
    XML_NEXXUS_PARM
    XML_LOGIN_PARM
    XML_PASSWD_PARM
  XML_PARAMETERS_END;

/*funcs*/
int
vacm_status(StonithPlugin *s)
{
	struct pluginDevice *sd;
	char snd[] = "NEXXUS:VERSION";
	char *rcv, *tk;
	int rcvlen;

	ERRIFWRONGDEV(s,S_OOPS);
	sd = (struct pluginDevice*)s;

	/* If grabbing the nexxus version works, then the status must be ok.
	 * right?
	 */

	api_nexxus_send_ipc(sd->h, snd, strlen(snd)+1);
	while(1) {
		if (api_nexxus_wait_for_data(sd->h, &rcv, &rcvlen, 20)<0) {
			break;
		}
		if (!(tk = strtok(rcv,":"))) { /*NEXXUS*/
			break;
		}else if (!(tk=strtok(NULL,":"))) { /* Job ID */
			break;
		}else if (!(tk=strtok(NULL,":"))) { /* one of the below */
			break;
		} else if ( !strcmp(tk, "JOB_COMPLETED")) {
			free(rcv);
			return S_OK; /* YEAH!! */
		}else if(!strcmp(tk, "JOB_STARTED")) {
			free(rcv);
			continue;
		}else if(!strcmp(tk, "JOB_ERROR")) {
			free(rcv);
			break;
		}else if(!strcmp(tk, "VERSION")) {
			free(rcv);
			continue;
		} else {
			LOG(PIL_CRIT, "Unexpected token \"%s\" in line \"%s\"\n"
			    , tk, rcv);
			break;
		}
	}

	return S_OOPS;
}

/* Better make sure the current group is correct. 
 * Can't think of a good way to do this.
 */
char **
vacm_hostlist(StonithPlugin *s)
{
   struct pluginDevice *sd;
   char snd[] = "NEXXUS:NODE_LIST";
   char *rcv,*tk;
   int rcvlen;
   char ** hlst=NULL;
   int hacnt=0, hrcnt=0;
#define MSTEP 20
   
   ERRIFWRONGDEV(s, NULL);
   sd = (struct pluginDevice*)s;

   hlst = (char **)MALLOC(MSTEP * sizeof(char*));
   if (hlst == NULL) {
      LOG(PIL_CRIT, "out of memory");
      return NULL;
   }
   hacnt=MSTEP;

   api_nexxus_send_ipc(sd->h, snd, strlen(snd)+1);
   while(1) {
      if(api_nexxus_wait_for_data(sd->h, &rcv, &rcvlen, 20)<0) {
         goto HL_cleanup;
      }
      if(!(tk=strtok(rcv, ":"))) { /* NEXXUS */
         goto HL_cleanup;
      }else if(!(tk=strtok(NULL,":"))) { /* Job ID */
         goto HL_cleanup;
      }else if(!(tk=strtok(NULL,":"))) { /* JOB_* or NODELIST */
         goto HL_cleanup;
      }else if( !strcmp(tk, "JOB_STARTED")) {
         free(rcv);
         continue;
      }else if( !strcmp(tk, "JOB_COMPLETED")) {
         free(rcv);
         return hlst;
      }else if( !strcmp(tk, "JOB_ERROR")) {
         free(rcv);
         break;
      }else if( !strcmp(tk, "NODELIST")) {
         if(!(tk = strtok(NULL,":"))) { /* group */
            goto HL_cleanup;
         }else if((tk = strtok(NULL," \t\n\r"))) { /*Finally, a machine name.*/
            if( hrcnt >= (hacnt-1)) { /* grow array. */
               char **oldhlst = hlst;
               hlst = (char **)REALLOC(hlst, (hacnt +MSTEP)*sizeof(char*));
               if( !hlst ) {
                  stonith_free_hostlist(oldhlst);
                  return NULL;
               }
               hacnt += MSTEP;
            }
            hlst[hrcnt] = STRDUP(tk); /* stuff the name. */
            hlst[hrcnt+1] = NULL; /* set next to NULL for looping */
            if (hlst[hrcnt] == NULL) {
               stonith_free_hostlist(hlst);
               return NULL;
	    }
            strdown(hlst[hrcnt]);
            hrcnt++;
         }
      }else {
         /* WTF?! */
         LOG(PIL_CRIT, "Unexpected token \"%s\" in line \"%s\"\n",tk,rcv);
         break;
      }
   }

HL_cleanup:
   stonith_free_hostlist(hlst); /* give the mem back */
   return NULL;
}

#define SND_SIZE 256
int
vacm_reset_req(StonithPlugin *s, int request, const char *host)
{
	struct pluginDevice *sd;
	char snd[SND_SIZE]; /* god forbid its bigger than this */
	char *rcv, *tk;
	int rcvlen;

	ERRIFWRONGDEV(s,S_OOPS);
	sd = (struct pluginDevice*)s;

	switch(request) {
#ifdef ST_POWERON
	case ST_POWERON:
		snprintf(snd, SND_SIZE, "EMP:POWER_ON:%s", host);
		break;
#endif /*ST_POWERON*/
#ifdef ST_POWEROFF
	case ST_POWEROFF:
		snprintf(snd, SND_SIZE, "EMP:POWER_OFF:%s", host);
		break;
#endif /*ST_POWEROFF*/
	case ST_GENERIC_RESET:
		snprintf(snd, SND_SIZE, "EMP:POWER_CYCLE:%s", host);
		break;
	default:
		return S_INVAL;
	}

	api_nexxus_send_ipc(sd->h, snd, strlen(snd)+1);
	while(1) {
		if (api_nexxus_wait_for_data(sd->h, &rcv, &rcvlen, 20)<0) {
			return S_RESETFAIL;
		}
		if (!(tk = strtok(rcv,":"))) { /*EMP*/
			break;
		}else if (!(tk=strtok(NULL,":"))) { /* Job ID */
			break;
		}else if (!(tk=strtok(NULL,":"))) { /* one of teh below */
			break;
		} else if ( !strcmp(tk, "JOB_COMPLETED")) {
			free(rcv);
			return S_OK;
		} else if(!strcmp(tk, "JOB_STARTED")) {
			free(rcv);
			continue;
		} else if(!strcmp(tk, "JOB_ERROR")) {
			free(rcv);
			return S_RESETFAIL;
		} else {
			/* WTF?! */
			LOG(PIL_CRIT, "Unexpected token \"%s\" in line \"%s\"\n"
			    , tk, rcv);
			break;
		}
	}

	return S_RESETFAIL;
}

/* list => "nexxus:username:password" */
static const char * const *
vacm_get_confignames(StonithPlugin * s)
{
	static const char * ret[] = {ST_NEXXUS, ST_LOGIN, ST_PASSWD, NULL};
	return ret;
}

static int
vacm_set_config(StonithPlugin *s, StonithNVpair * list)
{
	struct pluginDevice* sd = (struct pluginDevice *)s;
	int		rc;
	StonithNamesToGet	namestocopy [] =
	{	{ST_NEXXUS,	NULL}
	,	{ST_LOGIN,	NULL}
	,	{ST_PASSWD,	NULL}
	,	{NULL,		NULL}
	};
	char *rcv;
	int rcvlen;

	ERRIFWRONGDEV(s, S_OOPS);
	if (sd->sp.isconfigured) {
		return S_OOPS;
	}

	if ((rc=OurImports->CopyAllValues(namestocopy, list)) != S_OK) {
		return rc;
	}
	sd->nexxus = namestocopy[0].s_value;
	sd->user   = namestocopy[1].s_value;
	sd->passwd = namestocopy[2].s_value;
	/* When to initialize the sd->h */

	if (api_nexxus_connect(sd->nexxus, sd->user, sd->passwd, &sd->h)<0){
		return S_OOPS;
	}
	if (api_nexxus_wait_for_data(sd->h, &rcv, &rcvlen, 20)<0) {
		return S_OOPS;
	}
	if (strcmp(rcv, "NEXXUS_READY")) {
		rc = S_BADCONFIG;
	}else{
		rc = S_OK;
	}
	free(rcv);

	return(rc);
}

/*
 * The "vacmconf:" is in the conffile so that one file could be used for
 * multiple device configs.  This module will only look at the first line
 * that starts with this token.  All other line are ignored. (and thus
 * could contain configs for other modules.)
 *
 * I don't think any other stonith modules do this currently.
 */
const char *
vacm_getinfo(StonithPlugin *s, int reqtype)
{
	struct pluginDevice* sd = (struct pluginDevice *)s;
	const char *		ret;

   	ERRIFWRONGDEV(s, NULL);
	switch (reqtype) {

		case ST_DEVICEID:		/* What type of device? */
			ret = sd->idinfo;
			break;

		case ST_DEVICENAME:		/* Which particular device? */
			ret = dgettext(ST_TEXTDOMAIN, "VACM");
			break;

		case ST_DEVICEDESCR:		/* Description of dev type */
			ret = "A driver for the VA Linux Cluster Manager.";
			break;

		case ST_DEVICEURL:		/* VACM's web site */
			ret = "http://vacm.sourceforge.net/";
			break;

		case ST_CONF_XML:		/* XML metadata */
			ret = vacmXML;
			break;

		default:
			ret = NULL;
			break;
	}

	return ret;
}

void
vacm_destroy(StonithPlugin *s)
{
	struct pluginDevice *sd;

	VOIDERRIFWRONGDEV(s);
	sd = (struct pluginDevice*)s;

	if( sd->h ) {
		api_nexxus_disconnect(sd->h);
	}

	sd->pluginid = NOTpluginid;
	if (sd->nexxus != NULL) {
		FREE(sd->nexxus);
		sd->nexxus = NULL;
	}
	if (sd->user != NULL) {
		FREE(sd->user);
		sd->user = NULL;
	}
	if (sd->passwd != NULL) {
		FREE(sd->passwd);
		sd->passwd = NULL;
	}

	FREE(sd);
}

static StonithPlugin *
vacm_new(const char *subplugin)
{
	struct pluginDevice *sd;

	sd = MALLOC(sizeof(struct pluginDevice));
	if (sd == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(sd, 0, sizeof(*sd));
	sd->h = NULL;
	sd->pluginid = pluginid;
	sd->nexxus = NULL;
	sd->user = NULL;
	sd->passwd = NULL;
	sd->idinfo = DEVICE;
	sd->sp.s_ops = &vacmOps;
	return &(sd->sp);	/* same as "sd" */
}
