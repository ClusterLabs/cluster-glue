/* $Id: apcmastersnmp.c,v 1.11 2004/07/07 07:01:35 lars Exp $ */
/*
 * Stonith module for APC Masterswitch (SNMP)
 * Copyright (c) 2001 Andreas Piesk <a.piesk@gmx.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.*
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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>
#include <libintl.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>

#ifdef HAVE_NET_SNMP_NET_SNMP_CONFIG_H
#       include <net-snmp/net-snmp-config.h>
#       include <net-snmp/net-snmp-includes.h>
#       include <net-snmp/agent/net-snmp-agent-includes.h>
#       define  INIT_AGENT()    init_master_agent()
#else
#       include <ucd-snmp/ucd-snmp-config.h>
#       include <ucd-snmp/ucd-snmp-includes.h>
#       include <ucd-snmp/ucd-snmp-agent-includes.h>
#       ifndef NETSNMP_DS_APPLICATION_ID
#               define NETSNMP_DS_APPLICATION_ID        DS_APPLICATION_ID
#       endif
#       ifndef NETSNMP_DS_AGENT_ROLE
#               define NETSNMP_DS_AGENT_ROLE    DS_AGENT_ROLE
#       endif
#       define netsnmp_ds_set_boolean   ds_set_boolean
#       define  INIT_AGENT()    init_master_agent(161, NULL, NULL)
#endif

#include <stonith/stonith.h>
#define PIL_PLUGINTYPE          STONITH_TYPE
#define PIL_PLUGINTYPE_S        STONITH_TYPE_S
#define PIL_PLUGIN              apcmastersnmp
#define PIL_PLUGIN_S            "apcmastersnmp"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

/*
 * apcmastersnmpclose is called as part of unloading the apcmastersnmp STONITH plugin.
 * If there was any global data allocated, or file descriptors opened, etc.
 * which is associated with the plugin, and not a single interface
 * in particular, here's our chance to clean it up.
 */

static void
apcmastersnmpclosepi(PILPlugin*pi)
{
}


/*
 * apcmastersnmpcloseintf called as part of shutting down the apcmastersnmp STONITH
 * interface.  If there was any global data allocated, or file descriptors
 * opened, etc.  which is associated with the apcmastersnmp implementation,
 * here's our chance to clean it up.
 */
static PIL_rc
apcmastersnmpcloseintf(PILInterface* pi, void* pd)
{
	return PIL_OK;
}

static void *		apcmastersnmp_new(void);
static void		apcmastersnmp_destroy(Stonith *);
static int		apcmastersnmp_set_config_file(Stonith *, const char * cfgname);
static int		apcmastersnmp_set_config_info(Stonith *, const char * info);
static const char *	apcmastersnmp_getinfo(Stonith * s, int InfoType);
static int		apcmastersnmp_status(Stonith * );
static int		apcmastersnmp_reset_req(Stonith * s, int request, const char * host);
static char **		apcmastersnmp_hostlist(Stonith  *);
static void		apcmastersnmp_free_hostlist(char **);

static struct stonith_ops apcmastersnmpOps ={
	apcmastersnmp_new,		/* Create new STONITH object	*/
	apcmastersnmp_destroy,		/* Destroy STONITH object	*/
	apcmastersnmp_set_config_file,	/* set configuration from file	*/
	apcmastersnmp_set_config_info,	/* Get configuration from file	*/
	apcmastersnmp_getinfo,		/* Return STONITH info string	*/
	apcmastersnmp_status,		/* Return STONITH device status	*/
	apcmastersnmp_reset_req,		/* Request a reset */
	apcmastersnmp_hostlist,		/* Return list of supported hosts */
	apcmastersnmp_free_hostlist	/* free above list */
};

PIL_PLUGIN_BOILERPLATE("1.0", Debug, apcmastersnmpclosepi);
static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static StonithImports*		OurImports;
static void*			interfprivate;

#define APC_MALLOC		PluginImports->alloc
#define APC_STRDUP  		PluginImports->mstrdup
#define APC_FREE		PluginImports->mfree

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
	,	&apcmastersnmpOps
	,	apcmastersnmpcloseintf		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*
 * APCMaster tested with APC Masterswitch 9212
 */

// device ID
#define	DEVICE				"APCMasterSNMP-Stonith"

// outlet commands / status codes
#define OUTLET_ON			1
#define OUTLET_OFF			2
#define OUTLET_REBOOT			3
#define OUTLET_NO_CMD_PEND		2

// oids
#define OID_IDENT			".1.3.6.1.4.1.318.1.1.4.1.4.0"
#define OID_NUM_OUTLETS			".1.3.6.1.4.1.318.1.1.4.4.1.0"
#define OID_OUTLET_NAMES		".1.3.6.1.4.1.318.1.1.4.5.2.1.3.%i"
#define OID_OUTLET_STATE		".1.3.6.1.4.1.318.1.1.4.4.2.1.3.%i"
#define OID_OUTLET_COMMAND_PENDING	".1.3.6.1.4.1.318.1.1.4.4.2.1.2.%i"
#define OID_OUTLET_REBOOT_DURATION	".1.3.6.1.4.1.318.1.1.4.5.2.1.5.%i"

// own defines
#define MAX_STRING			128

// structur of stonith object
struct APCDevice {
    const char *APCid;		// id of object
    struct snmp_session *sptr;	// != NULL -> session created
    char *hostname;		// masterswitch's hostname or ip address
    int port;			// snmp port
    char *community;		// snmp community (r/w access)
    int num_outlets;		// number of outlets
};

// for checking hardware (issue a warning if mismatch)
static const char* APC_tested_ident[] = {"AP9606","AP7920","AP_other_well_tested"};

// constant strings
static const char *APCid = DEVICE;
static const char *NOTapcID = "destroyed (APCMasterswitch)";

#ifndef MIN
// some macros
#	define MIN( i, j ) ( i > j ? j : i )
#endif

#define	ISAPCDEV(i) (((i)!= NULL && (i)->pinfo != NULL)	&& \
                    ((struct APCDevice *)(i->pinfo))->APCid == APCid)

#define ISCONFIGED(i) (((struct APCDevice *)(i->pinfo))->sptr != NULL )

#define _(text) dgettext(ST_TEXTDOMAIN, text)

#ifndef APC_MALLOCT
#  define APC_MALLOCT(t) ((t *)(APC_MALLOC(sizeof(t))))
#endif

/*
 * stonith prototypes 
 */


/*
 * own prototypes 
 */

struct snmp_session *APC_open(char *hostname, int port, char *community);
int APC_parse_config_info(struct APCDevice *ad, const char *info);
void *APC_read(struct snmp_session *sptr, const char *objname, int type);
int APC_write(struct snmp_session *sptr, const char *objname, char type,
	      char *value);

/*
 *  creates a snmp session
 */
struct snmp_session *APC_open(char *hostname, int port, char *community)
{
    static struct snmp_session session;
    struct snmp_session *sptr;

#ifdef APC_DEBUG
    int snmperr = 0;
    int cliberr = 0;
    char *errstr;
#endif

    // create session
    snmp_sess_init(&session);

    // fill session
    session.peername = hostname;
    session.version = SNMP_VERSION_1;
    session.remote_port = port;
    session.community = community;
    session.community_len = strlen(community);
    session.retries = 5;
    session.timeout = 1000000;

    // open session
    sptr = snmp_open(&session);

#ifdef APC_DEBUG
    if (sptr == NULL) {
	snmp_error(&session, &cliberr, &snmperr, &errstr);
	syslog(LOG_DEBUG,
	       "%s: open error (cliberr: %i / snmperr: %i / error: %s\n",
	       __FUNCTION__, cliberr, snmperr, errstr);
	free(errstr);
    }
#endif

    // return pointer to opened session
    return (sptr);
}

/*
 * parse config
 */

int
APC_parse_config_info(struct APCDevice *ad, const char *info)
{
    static char hostname[MAX_STRING];
    static int port;
    static char community[MAX_STRING];
    int *i;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (sscanf(info, "%s %i %s", hostname, &port, community) == 3) {

	ad->hostname = hostname;
	ad->port = port;
	ad->community = community;

	// try to resolve the hostname/ip-address
	if (gethostbyname(hostname) != NULL) {

        // init snmp library
        init_snmp("apcmastersnmp");

	    // now try to get a snmp session
	    if ((ad->sptr = APC_open(hostname, port, community)) != NULL) {

		// ok, get the number of outlets from the masterswitch
		if ((i = APC_read(ad->sptr, OID_NUM_OUTLETS, ASN_INTEGER))
		    == NULL) {
#ifdef APC_DEBUG
		    syslog(LOG_DEBUG, "%s: cannot read number of outlets.",
			   __FUNCTION__);
#endif
		    return (S_ACCESS);
		}
		// store the number of outlets
		ad->num_outlets = *i;
#ifdef APC_DEBUG
		syslog(LOG_DEBUG, "%s: number of outlets: %i",
			   __FUNCTION__, ad->num_outlets );
#endif


		// everythin went well
		return (S_OK);
	    }
#ifdef APC_DEBUG
	    syslog(LOG_DEBUG, "%s: cannot create snmp session",
		   __FUNCTION__);
#endif
	}
#ifdef APC_DEBUG
	syslog(LOG_DEBUG, "%s: cannot resolve hostname '%s'", __FUNCTION__,
	       hostname);
#endif
    }
    // no valid config
    return (S_BADCONFIG);
}

/*
 * read value of given oid and return it as string
 */
void *APC_read(struct snmp_session *sptr, const char *objname, int type)
{
    oid name[MAX_OID_LEN];
    size_t namelen = MAX_OID_LEN;
    struct variable_list *vars;
    struct snmp_pdu *pdu;
    struct snmp_pdu *resp;
    static char response_str[MAX_STRING];
    static int response_int;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: requested objname '%s'", __FUNCTION__, objname );
#endif

    // convert objname into oid; return NULL if invalid
    if (!read_objid(objname, name, &namelen))
	return (NULL);

    // create pdu
    if ((pdu = snmp_pdu_create(SNMP_MSG_GET)) != NULL) {

	// get-request have no values
	snmp_add_null_var(pdu, name, namelen);

	// send pdu and get response; return NULL if error
	if (snmp_synch_response(sptr, pdu, &resp) == SNMPERR_SUCCESS) {

	    // request succeed, got valid response ?
	    if (resp->errstat == SNMP_ERR_NOERROR) {

		// go through the returned vars
		for (vars = resp->variables; vars;
		     vars = vars->next_variable) {

		    // return response as string
		    if ((vars->type == type) && (type == ASN_OCTET_STR)) {
			memset(response_str, 0, MAX_STRING);
			strncpy(response_str, vars->val.string,
				MIN(vars->val_len, MAX_STRING));
			snmp_free_pdu(resp);
			return ((void *) response_str);
		    }
		    // return response as integer
		    if ((vars->type == type) && (type == ASN_INTEGER)) {
			response_int = *vars->val.integer;
			snmp_free_pdu(resp);
			return ((void *) &response_int);
		    }
		}

#ifdef APC_DEBUG
	    } else {
		syslog(LOG_DEBUG, "%s: Error in packet - Reason: %s", __FUNCTION__,
		       snmp_errstring(resp->errstat));
#endif
	    }
	}
	// free repsonse pdu (neccessary?)
	snmp_free_pdu(resp);
    }
    // error: return nothing
    return (NULL);
}

/*
 * write value of given oid
 */
int
APC_write(struct snmp_session *sptr, const char *objname, char type,
	  char *value)
{
    oid name[MAX_OID_LEN];
    size_t namelen = MAX_OID_LEN;
    struct snmp_pdu *pdu;
    struct snmp_pdu *resp;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: requested objname '%s'", __FUNCTION__, objname );
#endif

    // convert objname into oid; return NULL if invalid
    if (!read_objid(objname, name, &namelen))
	return (FALSE);

    // create pdu
    if ((pdu = snmp_pdu_create(SNMP_MSG_SET)) != NULL) {

	// add to be written value to pdu
	snmp_add_var(pdu, name, namelen, type, value);

	// send pdu and get response; return NULL if error
	if (snmp_synch_response(sptr, pdu, &resp) == STAT_SUCCESS) {

	    // go through the returned vars
	    if (resp->errstat == SNMP_ERR_NOERROR) {

		// request successful done
		snmp_free_pdu(resp);
		return (TRUE);

#ifdef APC_DEBUG
	    } else {
		syslog(LOG_DEBUG, "%s: Error in packet- Reason: %s", __FUNCTION__,
		       snmp_errstring(resp->errstat));
#endif
	    }
	}
	// free pdu (again: neccessary?)
	snmp_free_pdu(resp);
    }
    // error
    return (FALSE);
}

/*
 * return the status for this device 
 */

int apcmastersnmp_status(Stonith * s)
{
    struct APCDevice *ad;
    char *ident;
    int i;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (!ISAPCDEV(s)) {
	syslog(LOG_ERR, "%s: invalid argument.", __FUNCTION__);
	return (S_INVAL);
    }

    if (!ISCONFIGED(s)) {
	syslog(LOG_ERR, "%s: device is UNCONFIGURED!", __FUNCTION__);
	return (S_OOPS);
    }

    ad = (struct APCDevice *) s->pinfo;

    if ((ident = APC_read(ad->sptr, OID_IDENT, ASN_OCTET_STR)) == NULL) {
#ifdef APC_DEBUG
	syslog(LOG_DEBUG, "%s: cannot read ident.", __FUNCTION__);
#endif
	return (S_ACCESS);
    }

    // issue a warning if ident mismatches
    for(i=DIMOF(APC_tested_ident) -1; i >=0 ; i--)
      if (strcmp(ident, APC_tested_ident[i]) == 0) break;
    if (i<0) {
	syslog(LOG_WARNING,
	       "%s: module not tested with this hardware '%s'",
	       __FUNCTION__, ident);
    }
    // status ok
    return (S_OK);
}

/*
 * return the list of hosts configured for this device 
 */

char **
apcmastersnmp_hostlist(Stonith * s)
{
    char **hl;
    struct APCDevice *ad;
    int j, h, num_outlets;
    char *outlet_name;
    char objname[MAX_STRING];

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (!ISAPCDEV(s)) {
	syslog(LOG_ERR, "%s: invalid argument.", __FUNCTION__);
	return (NULL);
    }

    if (!ISCONFIGED(s)) {
	syslog(LOG_ERR, "%s: device is UNCONFIGURED!", __FUNCTION__);
	return (NULL);
    }

    ad = (struct APCDevice *) s->pinfo;

    // allocate memory for array of up to NUM_OUTLETS strings
    if ((hl = (char **) APC_MALLOC(ad->num_outlets * sizeof(char *))) == NULL) {
	syslog(LOG_ERR, "%s: out of memory.", __FUNCTION__);
	return (NULL);
    }
    // clear hostlist array
    memset(hl, 0, (ad->num_outlets + 1) * sizeof(char *));
    num_outlets = 0;

    // read NUM_OUTLETS values and put them into hostlist array
    for (j = 0; j < ad->num_outlets; ++j) {

	// prepare objname
	snprintf(objname, MAX_STRING, OID_OUTLET_NAMES, j + 1);

	// read outlet name
	if ((outlet_name = APC_read(ad->sptr, objname, ASN_OCTET_STR)) ==
	    NULL) {
	    apcmastersnmp_free_hostlist(hl);
	    hl = NULL;
	    return (hl);
	}

	// Check whether the host is already listed
	for (h = 0; h < num_outlets; ++h) {
		if (strcmp(hl[h],outlet_name) == 0)
			break;
	}

	if (h >= num_outlets) {
		// put outletname in hostlist
#ifdef APC_DEBUG
	        syslog(LOG_DEBUG, "%s: added %s to hostlist", __FUNCTION__,
				outlet_name);
#endif
		
		if ((hl[num_outlets] = APC_STRDUP(outlet_name)) == NULL) {
		    syslog(LOG_ERR, "%s: out of memory.", __FUNCTION__);
		    apcmastersnmp_free_hostlist(hl);
		    hl = NULL;
		    return (hl);
		}
		num_outlets++;
	}
    }


#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: %d unique hosts connected to %d outlets", 
		    __FUNCTION__, num_outlets, j);
#endif
    // return list
    return (hl);
}

/*
 * free the hostlist 
 */

void
apcmastersnmp_free_hostlist(char **hlist)
{
    char **hl = hlist;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    // empty list
    if (hl == NULL)
	return;

    // walk through the list and release the strings
    while (*hl) {
	APC_FREE(*hl);
	*hl = NULL;
	++hl;
    }

    // release the list itself
    APC_FREE(hlist);
    hlist = NULL;
}

/*
 * reset the host 
 */

int
apcmastersnmp_reset_req(Stonith * s, int request, const char *host)
{
    struct APCDevice *ad;
    char objname[MAX_STRING];
    char value[MAX_STRING];
    char *outlet_name;
    int i, h, num_outlets, outlet, reboot_duration, *state, bad_outlets;
    int outlets[8]; /* Assume that one node is connected to a 
		       maximum of 8 outlets */
    
#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (!ISAPCDEV(s)) {
	syslog(LOG_ERR, "%s: invalid argument.", __FUNCTION__);
	return (S_INVAL);
    }

    if (!ISCONFIGED(s)) {
	syslog(LOG_ERR, "%s: device is UNCONFIGURED!", __FUNCTION__);
	return (S_OOPS);
    }

    ad = (struct APCDevice *) s->pinfo;

    num_outlets = 0;
    reboot_duration = 0;
    bad_outlets = 0;

    // read max. as->num_outlets values
    for (outlet = 1; outlet <= ad->num_outlets; outlet++) {

	// prepare objname
	snprintf(objname, MAX_STRING, OID_OUTLET_NAMES, outlet);

	// read outlet name
	if ((outlet_name = APC_read(ad->sptr, objname, ASN_OCTET_STR)) ==
	    NULL) {
#ifdef APC_DEBUG
	    syslog(LOG_DEBUG, "%s: cannot read outlet_names.",
		   __FUNCTION__);
#endif
	    return (S_ACCESS);
	}
	
	// found one
	g_strdown(outlet_name);
	if (strcmp(outlet_name, host) == 0) {
#ifdef APC_DEBUG
	    	syslog(LOG_DEBUG, "%s: Found %s at outlet: %i",
		       __FUNCTION__, host, outlet);
#endif
		/* Check that the outlet is not administratively down */
		
		// prepare objname
		snprintf(objname, MAX_STRING, OID_OUTLET_STATE, outlet);

		// get outlet's state
		if ((state = APC_read(ad->sptr, objname, ASN_INTEGER)) == NULL) {
#ifdef APC_DEBUG
			syslog(LOG_DEBUG, "%s: cannot read outlet_state for outlet %d.", __FUNCTION__, outlet);
#endif
			return (S_ACCESS);
		}

		if (*state == OUTLET_OFF) {
#ifdef APC_DEBUG
			syslog(LOG_DEBUG, "%s: outlet %d is off.", __FUNCTION__, outlet);
#endif
			continue;
		}
		
	        // prepare oid
	        snprintf(objname, MAX_STRING, OID_OUTLET_REBOOT_DURATION, outlet);

	        // read reboot_duration of the port
	        if ((state = APC_read(ad->sptr, 
			objname, ASN_INTEGER)) == NULL) {
#ifdef APC_DEBUG
		   syslog(LOG_DEBUG, 
			"%s: cannot read outlet's reboot duration.",
		       __FUNCTION__);
#endif
		   return (S_ACCESS);
	        }
	        if (num_outlets == 0) {
		   // save the inital value of the first port
		   reboot_duration = *state;
	        } else if (reboot_duration != *state) {
		  syslog(LOG_WARNING, "%s: Outlet %d has a different reboot duration!", 
				__FUNCTION__, outlet);
	    	  if (reboot_duration < *state)
				reboot_duration = *state;
	        }
	    
		/* Ok, add it to the list of outlets to control */
		outlets[num_outlets]=outlet;
		num_outlets++;
	}
    }
#ifdef APC_DEBUG
	    syslog(LOG_DEBUG, "%s: outlet: %i",
		   __FUNCTION__, outlet);
#endif

    // host not found in outlet names
    if (num_outlets < 1) {
#ifdef APC_DEBUG
	syslog(LOG_DEBUG, "%s: no active outlet '%s'.", __FUNCTION__, host);
#endif
	return (S_BADHOST);
    }

    // Turn them all off

    for (outlet=outlets[0], i=0 ; i < num_outlets; i++, 
		    outlet = outlets[i]) {
	    // prepare objname
	    snprintf(objname, MAX_STRING, OID_OUTLET_COMMAND_PENDING, outlet);

	    // are there pending commands ?
	    if ((state = APC_read(ad->sptr, objname, ASN_INTEGER)) == NULL) {
#ifdef APC_DEBUG
		syslog(LOG_DEBUG, "%s: cannot read outlet_pending.", __FUNCTION__);
#endif
		return (S_ACCESS);
	    }

	    if (*state != OUTLET_NO_CMD_PEND) {
#ifdef APC_DEBUG
		syslog(LOG_DEBUG, "%s: command pending.", __FUNCTION__);
#endif
		return (S_RESETFAIL);
	    }
	    
	    // prepare objnames
	    snprintf(objname, MAX_STRING, OID_OUTLET_STATE, outlet);
	    snprintf(value, MAX_STRING, "%i", OUTLET_REBOOT);

	    // send reboot cmd
	    if (!APC_write(ad->sptr, objname, 'i', value)) {
#ifdef APC_DEBUG
		syslog(LOG_DEBUG, "%s: cannot send reboot cmd for outlet %d.", 
				__FUNCTION__, outlet);
#endif
		return (S_ACCESS);
	    }
    }
  
    // wait max. 2*reboot_duration for all outlets to go back on
    for (i = 0; i < reboot_duration << 1; i++) {
	    
	    sleep(1);

	    bad_outlets = 0;
	    for (outlet=outlets[0], h=0 ; h < num_outlets; h++, 
			    outlet = outlets[h]) {

		// prepare objname of the first outlet
		snprintf(objname, MAX_STRING, OID_OUTLET_STATE, outlet);
	    	// get outlet's state
		
		if ((state = APC_read(ad->sptr, objname, ASN_INTEGER)) == NULL) {
#ifdef APC_DEBUG
		    syslog(LOG_DEBUG, "%s: cannot read outlet_state of %d.",
			   __FUNCTION__, outlets[0]);
#endif
		    return (S_ACCESS);
		}

		if (*state != OUTLET_ON)
			bad_outlets++;
	     }
	     
	     if (bad_outlets == 0)
		return (S_OK);
    }
    
    if (bad_outlets == num_outlets) {
	    // reset failed
	    syslog(LOG_ERR, "%s: resetting host '%s' failed.", __FUNCTION__, host);
	    return (S_RESETFAIL);
    } else {
	    // Not all outlets back on, but at least one; implies the node was
	    // rebooted correctly
	    syslog(LOG_WARNING,"%s: Not all outlets came back online!", __FUNCTION__);
	    return (S_OK); 
    }
}

/*
 * parse the information in the given configuration file,
 * and stash it away... 
 */

int
apcmastersnmp_set_config_file(Stonith * s, const char *configname)
{
    FILE *cfgfile;
    char confline[MAX_STRING];
    struct APCDevice *ad;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (!ISAPCDEV(s)) {
	syslog(LOG_ERR, "%s: invalid argument.", __FUNCTION__);
	return (S_INVAL);
    }

    ad = (struct APCDevice *) s->pinfo;

    if ((cfgfile = fopen(configname, "r")) == NULL) {
	syslog(LOG_ERR, "Cannot open %s", configname);
	return (S_BADCONFIG);
    }

    while (fgets(confline, sizeof(confline), cfgfile) != NULL) {
	if (*confline == '#' || *confline == '\n' || *confline == EOS)
	    continue;
	return (APC_parse_config_info(ad, confline));
    }
    return (S_BADCONFIG);
}

/*
 * Parse the config information in the given string, and stash it away... 
 */

int
apcmastersnmp_set_config_info(Stonith * s, const char *info)
{
    struct APCDevice *ad;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: info: '%s'.", __FUNCTION__, info);
#endif

    if (!ISAPCDEV(s)) {
	syslog(LOG_ERR, "%s: invalid argument.", __FUNCTION__);
	return (S_INVAL);
    }

    ad = (struct APCDevice *) s->pinfo;

    return (APC_parse_config_info(ad, info));
}

/*
 * get info about the stonith device 
 */

const char *
apcmastersnmp_getinfo(Stonith * s, int reqtype)
{
    struct APCDevice *ad;
    const char *ret = NULL;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (!ISAPCDEV(s)) {
	syslog(LOG_ERR, "%s: invalid argument.", __FUNCTION__);
	return (NULL);
    }

    ad = (struct APCDevice *) s->pinfo;

    switch (reqtype) {
	    case ST_DEVICEID:
		ret = ad->APCid;
		break;

	    case ST_CONF_INFO_SYNTAX:
		ret = _("hostname/ip-address port community\n"
			"The hostname/IP-address, SNMP port and community string are white-space delimited.");
		break;

	    case ST_CONF_FILE_SYNTAX:
		ret = _("hostname/ip-address port community\n"
			"The hostname/IP-address, SNMP port and community string are white-space delimited.\n"
			"All items must be on one line.\n"
			"Blank lines and lines beginning with # are ignored.");
		break;

	    case ST_DEVICEDESCR:
		ret = _("APC MasterSwitch (via SNMP)\n"
			"The APC MasterSwitch can accept multiple simultaneous SNMP clients");
		break;

	    case ST_DEVICEURL:
		ret = "http://www.apc.com/";
		break;

	}
	return ret;
}


/*
 * APC Stonith destructor... 
 */

void
apcmastersnmp_destroy(Stonith * s)
{
    struct APCDevice *ad;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (!ISAPCDEV(s)) {
	syslog(LOG_ERR, "%s: invalid argument.", __FUNCTION__);
	return;
    }

    ad = (struct APCDevice *) s->pinfo;

    ad->APCid = NOTapcID;

    // release snmp session
    if (ad->sptr != NULL) {
	snmp_close(ad->sptr);
	ad->sptr = NULL;
    }

    // reset defaults
    ad->hostname = NULL;
    ad->community = NULL;
    ad->num_outlets = 0;

    APC_FREE(ad);
    /* Our caller will release the STONITH object itself */

}

/*
 * Create a new APC Stonith device.  Too bad this function can't be
 * static 
 */

void *
apcmastersnmp_new(void)
{
    struct APCDevice *ad = APC_MALLOCT(struct APCDevice);

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    // no memory for stonith-object
    if (ad == NULL) {
	syslog(LOG_ERR, "%s: out of memory.", __FUNCTION__);
	return (NULL);
    }

    // clear stonith-object
    memset(ad, 0, sizeof(*ad));

    // set defaults
    ad->APCid = APCid;
    ad->sptr = NULL;
    ad->hostname = NULL;
    ad->community = NULL;
    ad->num_outlets = 0;

    // return the object
    return ((void *) ad);
}
