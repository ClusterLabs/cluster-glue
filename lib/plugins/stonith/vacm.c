/******************************************************************************
*
*    Copyright 2000 Sistina Software, Inc.
*    Tiny bits Copyright 2000 Alan Robertson <alanr@unix.sh>
*    Tiny bits Copyright 2000 Zac Sprackett, VA Linux Systems
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
*    You'll need to uncomment a line from the Makefile to get this
*    to compile and install with the normal stonith distribution.
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <libintl.h>
#include <stonith/stonith.h>
#include "vacmclient_api.h"

#define PIL_PLUGINTYPE          STONITH_TYPE
#define PIL_PLUGINTYPE_S        STONITH_TYPE_S
#define PIL_PLUGIN              vacm
#define PIL_PLUGIN_S            "vacm"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

/*
 * vacmclose is called as part of unloading the vacm STONITH plugin.
 * If there was any global data allocated, or file descriptors opened, etc.
 * which is associated with the plugin, and not a single interface
 * in particular, here's our chance to clean it up.
 */

static void
vacmclosepi(PILPlugin*pi)
{
}


/*
 * vacmcloseintf called as part of shutting down the vacm STONITH
 * interface.  If there was any global data allocated, or file descriptors
 * opened, etc.  which is associated with the vacm implementation,
 * here's our chance to clean it up.
 */
static PIL_rc
vacmcloseintf(PILInterface* pi, void* pd)
{
	return PIL_OK;
}

static void *		vacm_new(void);
static void		vacm_destroy(Stonith *);
static int		vacm_set_config_file(Stonith *, const char * cfgname);
static int		vacm_set_config_info(Stonith *, const char * info);
static const char *	vacm_getinfo(Stonith * s, int InfoType);
static int		vacm_status(Stonith * );
static int		vacm_reset_req(Stonith * s, int request, const char * host);
static char **		vacm_hostlist(Stonith  *);
static void		vacm_free_hostlist(char **);

static struct stonith_ops vacmOps ={
	vacm_new,		/* Create new STONITH object	*/
	vacm_destroy,		/* Destroy STONITH object	*/
	vacm_set_config_file,	/* set configuration from file	*/
	vacm_set_config_info,	/* Get configuration from file	*/
	vacm_getinfo,		/* Return STONITH info string	*/
	vacm_status,		/* Return STONITH device status	*/
	vacm_reset_req,		/* Request a reset */
	vacm_hostlist,		/* Return list of supported hosts */
	vacm_free_hostlist	/* free above list */
};

PIL_PLUGIN_BOILERPLATE("1.0", Debug, vacmclosepi);
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
	,	&vacmOps
	,	vacmcloseintf		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*structs*/
struct vac {
   unsigned int magic;
   void *h; /* a handle to the nexxus. */
};
#define VACMID_MAGIC 0x7661636d

#define IS_VACM(i) (((i)!=NULL) && ((i)->pinfo!=NULL) \
      && (((struct vac *)(i)->pinfo)->magic == VACMID_MAGIC))

#define log_err(fmt, arg...) fprintf(stderr, fmt, ## arg)


/*funcs*/
int
vacm_status(Stonith *s)
{
   struct vac *vc;
   char snd[] = "NEXXUS:VERSION";
   char *rcv, *tk;
   int rcvlen;

   if(!IS_VACM(s)) return (S_OOPS);
   vc = (struct vac*)s->pinfo;

   /* If grabbing the nexxus version works, then the stauts must be ok.
    * right?
    */

   api_nexxus_send_ipc(vc->h, snd, strlen(snd)+1);
   while(1) {
      if(api_nexxus_wait_for_data(vc->h, &rcv, &rcvlen, 20)<0)
         break;
      if(!(tk = strtok(rcv,":"))) { /*NEXXUS*/
         break;
      }else if(!(tk=strtok(NULL,":"))) { /* Job ID */
         break;
      }else if(!(tk=strtok(NULL,":"))) { /* one of the below */
         break;
      } else if( !strcmp(tk, "JOB_COMPLETED")) {
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
         log_err("Unexpected token \"%s\" in line \"%s\"\n",tk,rcv);
         break;
      }
   }

   return S_OOPS;
}

void
vacm_free_hostlist(char **hlist)
{
	char **	hl = hlist;
	if (hl == NULL) {
		return;
	}
	while (*hl) {
		free(*hl);
		*hl = NULL;
		++hl;
	}
	free(hlist);
}

/* Better make sure the current group is correct. 
 * Can't think of a good way to do this.
 */
char **
vacm_hostlist(Stonith *s)
{
   struct vac *vc;
   char snd[] = "NEXXUS:NODE_LIST";
   char *rcv,*tk;
   int rcvlen;
   char ** hlst=NULL;
   int hacnt=0, hrcnt=0;
#define MSTEP 20

   if(!IS_VACM(s)) return NULL;
   vc = (struct vac*)s->pinfo;

   hlst = (char **)malloc(MSTEP * sizeof(char*));
   hacnt=MSTEP;

   api_nexxus_send_ipc(vc->h, snd, strlen(snd)+1);
   while(1) {
      if(api_nexxus_wait_for_data(vc->h, &rcv, &rcvlen, 20)<0) {
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
               hlst = (char **)realloc(hlst, (hacnt +MSTEP)*sizeof(char*));
               if( !hlst ) return NULL; /* yeah, i know. possible leak */
               hacnt += MSTEP;
            }
            hlst[hrcnt++] = strdup(tk); /* stuff the name. */
            hlst[hrcnt] = NULL; /* set next to NULL for looping */
         }
      }else {
         /* WTF?! */
         log_err("Unexpected token \"%s\" in line \"%s\"\n",tk,rcv);
         break;
      }
   }

HL_cleanup:
   vacm_free_hostlist(hlst); /* give the mem back */
   return NULL;
}

#define SND_SIZE 256
int
vacm_reset(Stonith *s, int request, const char *host)
{
   struct vac *vc;
   char snd[SND_SIZE]; /* god forbid its bigger than this */
   char *rcv, *tk;
   int rcvlen;

   if(!IS_VACM(s)) return (S_OOPS);
   vc = (struct vac*)s->pinfo;

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
   api_nexxus_send_ipc(vc->h, snd, strlen(snd)+1);
   while(1) {
      if(api_nexxus_wait_for_data(vc->h, &rcv, &rcvlen, 20)<0)
         return S_RESETFAIL;
      if(!(tk = strtok(rcv,":"))) { /*EMP*/
         break;
      }else if(!(tk=strtok(NULL,":"))) { /* Job ID */
         break;
      }else if(!(tk=strtok(NULL,":"))) { /* one of teh below */
         break;
      } else if( !strcmp(tk, "JOB_COMPLETED")) {
         free(rcv);
         return S_OK;
      }else if(!strcmp(tk, "JOB_STARTED")) {
         free(rcv);
         continue;
      }else if(!strcmp(tk, "JOB_ERROR")) {
         free(rcv);
         return S_RESETFAIL;
      } else {
         /* WTF?! */
         log_err("Unexpected token \"%s\" in line \"%s\"\n",tk,rcv);
         break;
      }
   }

   return S_RESETFAIL;
}

int parse_conf_line(struct vac *vc, char *line)
{
   char *n=NULL, *u=NULL, *p=NULL;
   char *rcv;
   int rcvlen;

   n = line;
   u = strstr(n, ":");
   if(!u) return S_BADCONFIG;
   *u++ = '\0';
   p = strstr(u, ":");
   if(!p) return S_BADCONFIG;
   *p++ = '\0';

   if(api_nexxus_connect(n, u, p, &(vc->h))<0)
      return S_INVAL;
   if(api_nexxus_wait_for_data(vc->h, &rcv, &rcvlen, 20)<0)
      return S_INVAL;

   if(strcmp(rcv, "NEXXUS_READY"))
      return S_BADCONFIG;

   free(rcv);
   return S_OK;
}

int
vacm_set_config_file(Stonith *s, const char *cfn)
{
   struct vac *vc;
   int err=S_BADCONFIG;
   char line[512], *tk;
   FILE *fl;

   if(!IS_VACM(s)) return (S_OOPS);
   vc = (struct vac*)s->pinfo;

   if( (fl = fopen(cfn, "r")) == NULL) return S_BADCONFIG;

   while(fgets(line,512,fl) != NULL ) {
      switch(line[0]) {
         case '\0': case '\n': case '\r': case '#':
            continue;
      }
      if( !(tk = strtok(line, ":"))) break;
      if( !strcmp(tk, "vacmconf")) {
         if( !(tk = strtok(NULL, " \t\n\r"))) break;
         err = parse_conf_line(vc, tk);
         break;
      }

   }

   fclose(fl);
   return err;
}

/* info => "nexxus:username:password" */
int
vacm_set_config_info(Stonith *s, const char *info)
{
   struct vac *vc;
   int err = S_BADCONFIG;
   char *tmp = strdup(info);

   if(!IS_VACM(s)) return (S_OOPS);
   vc = (struct vac*)s->pinfo;

   err = parse_conf_line(vc, tmp);

   free(tmp);
   return err;
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
vacm_getinfo(Stonith *s, int reqtype)
{
   if(!IS_VACM(s)) return NULL;

   switch(reqtype){
      case ST_DEVICEID:
         return dgettext(ST_TEXTDOMAIN, "VACM");
      case ST_CONF_INFO_SYNTAX:
         return dgettext(ST_TEXTDOMAIN, "nexxus:username:password");
      case ST_CONF_FILE_SYNTAX:
         return dgettext(ST_TEXTDOMAIN, "vacmconf:nexxus:username:password");
      default:
         return NULL;
   }
}

void
vacm_destroy(Stonith *s)
{
   struct vac *vc;

   if(!IS_VACM(s)) return;
   vc = (struct vac*)s->pinfo;

   if( vc->h )
      api_nexxus_disconnect(vc->h);
   free(vc); vc = NULL;

}

void *
vacm_new(void)
{
   struct vac *vc;
   vc = malloc(sizeof(struct vac));
   vc->magic = VACMID_MAGIC;
   vc->h = NULL;
   return (void*)vc;
}
