/*
 * Stonith module for Cyclades AlterPath PM
 * Bases off the SSH plugin
 *
 * Copyright (c) 2004 Cyclades corp.
 *
 * Author: Jon Taylor <jon.taylor@cyclades.com>
 *
 * Rewritten from scratch using baytech.c structure and code 
 * and currently maintained by
 *       Marcelo Tosatti  <marcelo.tosatti@cyclades.com>
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

#define	DEVICE	"Cyclades AlterPath PM"

#define DOESNT_USE_STONITHSCANLINE

#include "stonith_plugin_common.h"

#define PIL_PLUGIN              cyclades 
#define PIL_PLUGIN_S            "cyclades"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

#include "stonith_signal.h"

static StonithPlugin *	cyclades_new(const char *);
static void		cyclades_destroy(StonithPlugin *);
static int		cyclades_set_config(StonithPlugin *, StonithNVpair *);
static const char * const *	cyclades_get_confignames(StonithPlugin * s);
static const char *	cyclades_get_info(StonithPlugin * s, int InfoType);
static int		cyclades_status(StonithPlugin *);
static int		cyclades_reset_req(StonithPlugin * s, int request, const char * host);
static char **		cyclades_hostlist(StonithPlugin *);



static struct stonith_ops cycladesOps ={
	cyclades_new,			/* Create new STONITH object	*/
	cyclades_destroy,		/* Destroy STONITH object	*/
	cyclades_get_info,		/* Return STONITH info string	*/
	cyclades_get_confignames,	/* Return STONITH config vars	*/
	cyclades_set_config,		/* set configuration from vars	*/
	cyclades_status,		/* Return STONITH device status	*/
	cyclades_reset_req,		/* Request a reset */
	cyclades_hostlist,		/* Return list of supported hosts */
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
	,	&cycladesOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*
 *    Cyclades STONITH device
 *
 */

struct pluginDevice {
	StonithPlugin	sp;
	const char *	pluginid;
	const char *	idinfo;
	char *		device;
	char *		user;

	int		serial_port;

	/* pid of ssh client process and its in/out file descriptors */
	pid_t		pid; 
	int 		rdfd, wrfd;		
};

static struct Etoken StatusOutput[] = { 
	{ "Outlet\t\tName\t\tStatus\t\tUsers\t\tInterval (s)", 1, 0},
	{ "Outlet\tName\t\t\tStatus\t\tInterval (s)\tUsers", 2, 0},
	{ "Outlet             Name             Status          Post-on Delay(s)", 3, 0},
	{ NULL, 0, 0} 
};

static struct Etoken CRNL[] =		{ {"\n\r",0,0},{"\r\n",0,0},{NULL,0,0}};


/* Commands of PM devices */
static char status_all[] = "status all";
static char cycle[] = "cycle";

static int CYC_robust_cmd(struct pluginDevice *, char *);

static const char * pluginid = "CycladesDevice-Stonith";
static const char * NOTpluginID = "Cyclades device has been destroyed";

#define MAX_OUTLETS	128

#define ST_SERIALPORT	"serialport"

#define ZEROEXPECT(fd,p,t)	{					\
                                if (StonithLookFor(fd, p, t) < 0)	\
                                        return(0);			\
                        }

#define RESETEXPECT(fd,p,t)	{					\
                        	if (StonithLookFor(fd, p, t) < 0) {	\
					FREE(outletstr);		\
                                	return(errno == ETIMEDOUT	\
	                        ?       S_RESETFAIL : S_OOPS);		\
				}					\
                        }

#include "stonith_config_xml.h"

#define XML_SERIALPORT_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	ST_SERIALPORT \
	XML_PARM_SHORTDESC_END

#define XML_SERIALPORT_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The serial port of the IPDU which can powercycle the node" \
	XML_PARM_LONGDESC_END

#define XML_SERIALPORT_PARM \
	XML_PARAMETER_BEGIN(ST_SERIALPORT, "string", "1", "0") \
	  XML_SERIALPORT_SHORTDESC \
	  XML_SERIALPORT_LONGDESC \
	XML_PARAMETER_END

static const char *cycladesXML = 
  XML_PARAMETERS_BEGIN
    XML_IPADDR_PARM
    XML_LOGIN_PARM
    XML_SERIALPORT_PARM
  XML_PARAMETERS_END;

static int
CYCScanLine(struct pluginDevice *sd, int timeout, char * buf, int max)
{
	if (EXPECT_TOK(sd->rdfd, CRNL, timeout, buf, max, Debug) < 0) {
		Stonithkillcomm(&sd->rdfd, &sd->wrfd, &sd->pid);
		return(S_OOPS);
	}
	return(S_OK);
}

static int
cyclades_status(StonithPlugin  *s)
{
	struct pluginDevice *sd;
	char *cmd = status_all;

	ERRIFNOTCONFIGED(s,S_OOPS);

	sd = (struct pluginDevice*) s;

	if (CYC_robust_cmd(sd, cmd) != S_OK) {
		LOG(PIL_CRIT, "can't run status all command");
		return(S_OOPS);
	}

	EXPECT(sd->rdfd, StatusOutput, 50);

	return(S_OK);
}

static int CYC_run_command(struct pluginDevice *sd, char *cmd)
{
	char	SshCommand[MAX_OUTLETS*4];

	snprintf(SshCommand, sizeof(SshCommand),
			"exec ssh -q %s@%s /bin/pmCommand %d %s 2>/dev/null", 
			sd->user, sd->device, sd->serial_port, cmd);

	sd->pid = STARTPROC(SshCommand, &sd->rdfd, &sd->wrfd);

	if (sd->pid <= 0) {
		return(S_OOPS);
	}

	return(S_OK);
}

static int 
CYC_robust_cmd(struct pluginDevice *sd, char *cmd)
{
	int rc = S_OOPS;
	int i;

	for (i=0; i < 20 && rc != S_OK; i++) {

		if (sd->pid > 0) {
			Stonithkillcomm(&sd->rdfd, &sd->wrfd, &sd->pid);
		}

		if (CYC_run_command(sd, cmd) != S_OK) {
			Stonithkillcomm(&sd->rdfd, &sd->wrfd, &sd->pid);
			continue;
		} 
		rc = S_OK;
	}

	return rc;
}

#define MAXSAVE 512
static int CYCNametoOutlet(struct pluginDevice *sd, const char *host, int *outlets, int maxoutlet)
{
	char *cmd = status_all;
	char    savebuf[MAXSAVE];
	int err;
	int outlet, numoutlet = 0;
	char name[17], locked[11], on[4];

	if (CYC_robust_cmd(sd, cmd) != S_OK) {
		LOG(PIL_CRIT, "can't run status all command");
		return 0;
	}

	ZEROEXPECT(sd->rdfd, StatusOutput, 50);

	ZEROEXPECT(sd->rdfd, CRNL, 50);

	do {

		memset(savebuf, 0, sizeof(savebuf));
		memset(name, 0, sizeof(name));
		memset(locked, 0, sizeof(locked));
		memset(on, 0, sizeof(on));

		err = CYCScanLine(sd, 2, savebuf, sizeof(savebuf));

		if ((err == S_OK) &&
		    (sscanf(savebuf,"%3d %16s %10s %3s", &outlet, 
			name, locked, on) > 0)) {
			if (!strncasecmp(name, host, strlen(host))) {
				if (numoutlet >= maxoutlet) {
					LOG(PIL_CRIT, "too many outlets");
					return 0;
				}
				outlets[numoutlet++] = outlet;
			}
		}

	} while (err == S_OK);

	return (numoutlet);
}


/*
 *	Return the list of hosts configured for this Cyclades device
 */

static char **
cyclades_hostlist(StonithPlugin  *s)
{
	struct pluginDevice*	sd;
	char *cmd = status_all;
	char    savebuf[MAXSAVE];
	int err, i;
	int outlet;
	int numnames = 0;
	char name[17], locked[11], on[4];
	char *NameList[MAX_OUTLETS];
	char **ret = NULL;

	ERRIFNOTCONFIGED(s,NULL);

	sd = (struct pluginDevice*) s;

	if (CYC_robust_cmd(sd, cmd) != S_OK) {
		LOG(PIL_CRIT, "can't run status all command");
		return (NULL);
	}

	memset(savebuf, 0, sizeof(savebuf));

	NULLEXPECT(sd->rdfd, StatusOutput, 50);

	NULLEXPECT(sd->rdfd, CRNL, 50);

	do {
		char *nm;

		memset(savebuf, 0, sizeof(savebuf));
		memset(name, 0, sizeof(name));
		memset(locked, 0, sizeof(locked));
		memset(on, 0, sizeof(on));

		err = CYCScanLine(sd, 2, savebuf, sizeof(savebuf));

		if ((err == S_OK) &&
		    (sscanf(savebuf,"%3d %16s %10s %3s", &outlet, 
			name, locked, on) > 0)) {
			nm = (char *) STRDUP (name);
			if (!nm) {
				goto out_of_memory;
			}
			strdown(nm);
			NameList[numnames] = nm;
			numnames++;
			NameList[numnames] = NULL;
		}

	} while (err == S_OK);

	if (numnames) {

		ret = (char **)MALLOC((numnames+1)*sizeof(char*));
		if (ret == NULL) {
			goto out_of_memory;
		} else {
			memcpy(ret, NameList, (numnames+1)*sizeof(char*));
		}
		return (ret);
	}
	return(ret);

out_of_memory:
	LOG(PIL_CRIT, "out of memory");
	for (i=0; i<numnames; i++) {
		FREE(NameList[i]);
	}

	return (NULL);
}


static char *cyclades_outletstr(int *outlet, int numoutlet)
{
        int i, len;
        char *ret;

        /* maximum length per outlet is currently four (outlet is one to
         * three digits, followed by either a comma or null), so add one
	 * for good measure */
        len = numoutlet * 5 * sizeof(char);
        if ((ret = MALLOC(len)) != NULL) {
                snprintf(ret, len, "%d", outlet[0]);
                for (i = 1; i < numoutlet; i++) {
                        char buf[5];
                        snprintf(buf, sizeof(buf), ",%d", outlet[i]);
                        strcat(ret, buf);
                }
        }
        return(ret);
}


static int cyclades_onoff(struct pluginDevice *sd, int *outlet, int numoutlet, 
		const char *unitid, int req)
{
	const char * onoff;
	char cmd[MAX_OUTLETS*4], expstring[64];
	struct Etoken exp[] = {{NULL, 0, 0}, {NULL, 0, 0}};
	char *outletstr;
	int i;
	
	onoff = (req == ST_POWERON ? "on" : "off");

	memset(cmd, 0, sizeof(cmd));

	outletstr = cyclades_outletstr(outlet, numoutlet);
	if (outletstr == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return (S_OOPS);
	}
	snprintf(cmd, sizeof(cmd), "%s %s", onoff, outletstr);

	if (CYC_robust_cmd(sd, cmd) != S_OK) {
		LOG(PIL_CRIT, "can't run %s command", onoff);
		FREE(outletstr);
		return(S_OOPS);
	}

	for (i = 0; i < numoutlet; i++) {
		memset(expstring, 0, sizeof(expstring));
		snprintf(expstring, sizeof(expstring), "%d: Outlet turned %s."
		,	outlet[i], onoff);

		exp[0].string = expstring;
	
		/* FIXME: should handle "already powered on/off" case and inform 
		   to log */

		EXPECT(sd->rdfd, exp, 50); 
	}
	
	LOG(PIL_DEBUG, "Power to host %s turned %s", unitid, onoff);

	FREE(outletstr);
	return (S_OK);
}

static int cyclades_reset(struct pluginDevice *sd, int *outlet, int numoutlet,
		const char *unitid)
{
	char cmd[MAX_OUTLETS*4], expstring[64];
	struct Etoken exp[] = {{NULL, 0, 0}, {NULL, 0, 0}};
	char *outletstr;
	int i;

	memset(cmd, 0, sizeof(cmd));

	outletstr = cyclades_outletstr(outlet, numoutlet);
	if (outletstr == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return (S_OOPS);
	}
	snprintf(cmd, sizeof(cmd), "%s %s", cycle, outletstr);

	LOG(PIL_INFO, "Host %s being rebooted.", unitid);

	if (CYC_robust_cmd(sd, cmd) != S_OK) {
		LOG(PIL_CRIT, "can't run cycle command");
		FREE(outletstr);
		return(S_OOPS);
	}

	for (i = 0; i < numoutlet; i++) {
		memset(expstring, 0, sizeof(expstring));
		snprintf(expstring, sizeof(expstring)
		,	"%d: Outlet turned off.", outlet[i]);

		exp[0].string = expstring;
		RESETEXPECT(sd->rdfd, exp, 50); 
	}

	for (i = 0; i < numoutlet; i++) {
		memset(expstring, 0, sizeof(expstring));
		snprintf(expstring, sizeof(expstring)
		,	"%d: Outlet turned on.", outlet[i]);

		exp[0].string = expstring;
		RESETEXPECT(sd->rdfd, exp, 50); 
	}

	FREE(outletstr);
	return (S_OK);
}

/*
 *	Reset the given host on this Stonith device.
 */
static int
cyclades_reset_req(StonithPlugin * s, int request, const char * host)
{
	struct pluginDevice *sd;
	int rc = 0;
	int numoutlet, outlets[MAX_OUTLETS];

	ERRIFNOTCONFIGED(s,S_OOPS);

	sd = (struct pluginDevice*) s;

	numoutlet = CYCNametoOutlet(sd, host, outlets, MAX_OUTLETS);

	if (!numoutlet) {
		LOG(PIL_CRIT, "Unknown host %s to Cyclades PM", host);
		return (S_OOPS);
	}

		
	switch (request) {
	case ST_POWERON:
	case ST_POWEROFF:
		rc = cyclades_onoff(sd, outlets, numoutlet, host, request);
		break;

	case ST_GENERIC_RESET:
		rc = cyclades_reset(sd, outlets, numoutlet, host);
		break;
	default:
		rc = S_INVAL;
		break;
	}

	return rc;
}

static const char * const *
cyclades_get_confignames(StonithPlugin * s)
{
	static const char * ret[] = {ST_IPADDR, ST_LOGIN, ST_SERIALPORT, NULL};
	return ret;
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
cyclades_set_config(StonithPlugin* s, StonithNVpair* list)
{
	struct pluginDevice* sd = (struct pluginDevice *)s;
	int		rc;
	StonithNamesToGet	namestocopy[] =
	{	{ST_IPADDR,	NULL}
	,	{ST_LOGIN,	NULL}
	,	{ST_SERIALPORT, NULL}
	,	{NULL,		NULL}
	};

	ERRIFWRONGDEV(s, S_OOPS);
	if (sd->sp.isconfigured) {
		return S_OOPS;
	}

	if ((rc = OurImports->CopyAllValues(namestocopy, list)) != S_OK) {
		return rc;
	}
	sd->device = namestocopy[0].s_value;
	sd->user = namestocopy[1].s_value;
	sd->serial_port	= atoi(namestocopy[2].s_value);
	FREE(namestocopy[2].s_value);

	return(S_OK);
}

static const char *
cyclades_get_info(StonithPlugin * s, int reqtype)
{
	struct pluginDevice * sd;
	const char * ret;

	ERRIFWRONGDEV(s, NULL);

	sd = (struct pluginDevice*) s;

	switch (reqtype) {
		case ST_DEVICEID:		/* What type of device? */
			/* FIXME: could inform the exact PM model */
			ret = sd->idinfo;
			break;

		case ST_DEVICENAME:		/* What particular device? */
			ret = sd->device;
			break;

		case ST_DEVICEDESCR:		/* Description of dev type */
			ret = "Cyclades AlterPath PM "
				"series power switches (via TS/ACS/KVM).";
			break;

		case ST_DEVICEURL:		/* Manufacturer's web site */
			ret = "http://www.cyclades.com/";
			break;

		case ST_CONF_XML:		/* XML metadata */
			ret = cycladesXML;
			break;

		default:
			ret = NULL;
			break;
	}
	return ret;
}

/*
 *	Cyclades Stonith destructor...
 */
static void
cyclades_destroy(StonithPlugin *s)
{
	struct pluginDevice* sd;

	VOIDERRIFWRONGDEV(s);

	sd = (struct pluginDevice*) s;

	sd->pluginid = NOTpluginID;
	Stonithkillcomm(&sd->rdfd, &sd->wrfd, &sd->pid);
	if (sd->device != NULL) {
		FREE(sd->device);
		sd->device = NULL;
	}
	if (sd->user != NULL) {
		FREE(sd->user);
		sd->user = NULL;
	}

	FREE(sd);
}

/* Create a new cyclades Stonith device */
static StonithPlugin *
cyclades_new(const char *plugin)
{
	struct pluginDevice*	sd = ST_MALLOCT(struct pluginDevice);

	if (sd == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}

	memset(sd, 0, sizeof(*sd));
	sd->pluginid = pluginid;
	sd->pid = -1;
	sd->rdfd = -1;
	sd->wrfd = -1;
	sd->idinfo = DEVICE;
	sd->sp.s_ops = &cycladesOps;

	return &(sd->sp);	/* same as sd */
}
