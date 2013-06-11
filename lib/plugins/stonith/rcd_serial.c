/*
 * Stonith module for RCD_SERIAL Stonith device
 *
 * Original code from null.c by
 * Copyright (c) 2000 Alan Robertson <alanr@unix.sh>
 *
 * Copious borrowings from nw_rpc100s.c by
 * Copyright (c) 2000 Computer Generation Incorporated
 *          Eric Z. Ayers <eric.ayers@compgen.com>
 *
 *                and from apcsmart.c by
 * Copyright (c) 2000 Andreas Piesk <a.piesk@gmx.net>
 *
 * Modifications for RC Delayed Serial Ciruit by 
 * Copyright (c) 2002 John Sutton <john@scl.co.uk>
 *
 * Mangled by Zhaokai <zhaokai@cn.ibm.com>, IBM, 2005
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

#define	DEVICE	"RC Delayed Serial"
#include "stonith_plugin_common.h"
#include "stonith_signal.h"

#define PIL_PLUGIN              rcd_serial
#define PIL_PLUGIN_S            "rcd_serial"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL

#define	ST_DTRRTS		"dtr_rts"
#define	ST_MSDURATION		"msduration"
#define MAX_RCD_SERIALLINE	512

#include <pils/plugin.h>
#include <sys/ioctl.h>
#include <sys/time.h>

static StonithPlugin*	rcd_serial_new(const char *);
static void		rcd_serial_destroy(StonithPlugin *);
static int		rcd_serial_set_config(StonithPlugin *, StonithNVpair *);
static const char * const *	rcd_serial_get_confignames(StonithPlugin *);
static const char *	rcd_serial_getinfo(StonithPlugin * s, int InfoType);
static int		rcd_serial_status(StonithPlugin * );
static int		rcd_serial_reset_req(StonithPlugin * s, int request, const char * host);
static char **		rcd_serial_hostlist(StonithPlugin  *);

static struct stonith_ops rcd_serialOps ={
	rcd_serial_new,		/* Create new STONITH object		*/
	rcd_serial_destroy,	/* Destroy STONITH object		*/
	rcd_serial_getinfo,	/* Return STONITH info string		*/
	rcd_serial_get_confignames,/* Return STONITH info string	*/
	rcd_serial_set_config,	/* Get configuration from NVpairs	*/
	rcd_serial_status,	/* Return STONITH device status		*/
	rcd_serial_reset_req,	/* Request a reset 			*/
	rcd_serial_hostlist,	/* Return list of supported hosts 	*/
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug)
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
	,	&rcd_serialOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/* ------------------- RCD specific stuff -------------- */

/*
  A diagram of a circuit suitable for use with this plugin is in
  README.rcd_serial which should be somewhere in the distribution (if Alan
  includes it ;-) and/or at http://www.scl.co.uk/rcd_serial/ (if I remember
  to put it there ;-).

  Once you've got this built, you can test things using the stonith command
  as follows:

	stonith -L
		will show a list of plugin types, including rcd_serial

	stonith -t rcd_serial testhost
		will show required parameters

  In these 3 you can either pass the params after the -p option or you can
  put them in a config file and use -F configname instead of -p "param ...".

	stonith -t rcd_serial -p "testhost /dev/ttyS0 rts 1500" -S
		will show the status of the device

	stonith -t rcd_serial -p "testhost /dev/ttyS0 rts 1500" -l
		will list the single host testhost

	stonith -t rcd_serial -p "testhost /dev/ttyS0 rts 1500" testhost
		will reset testhost (provided testhost has its reset pins
		suitably wired to the RTS signal coming out of port /dev/ttyS0
		and that 1.5s is enough time to cause a reset ;-)
*/

/*
  Define RCD_NOPAUSE if you are using the serial port for some purpose
  _in_addition_ to using it as a stonith device.  For example, I use one
  of the input pins on the same serial port for monitoring the state of a
  power supply.  Periodically, a cron job has to open the port to read the
  state of this input and thus has to clear down the output pins DTR and RTS
  in order to avoid causing a spurious stonith reset.  Now, if it should
  happen that just at the same time as we are _really_ trying to do a stonith
  reset, this cron job starts up, then the stonith reset won't occur ;-(.
  To avoid this (albeit unlikely) outcome, you should #define RCD_NOPAUSE.
  The effect of this is that instead of setting the line high just once and
  then falling into a pause until an alarm goes off, rather, the program falls
  into a loop which is continuously setting the line high.  That costs us a bit
  of CPU as compared with sitting in a pause, but hey, how often is this code
  going to get exercised!  Never, we hope...
*/
#undef RCD_NOPAUSE

#ifdef RCD_NOPAUSE
static int RCD_alarmcaught;
#endif

/*
 * own prototypes
 */

static void RCD_alarm_handler(int sig);
static int RCD_open_serial_port(char *device);
static int RCD_close_serial_port(char *device, int fd);

static void
RCD_alarm_handler(int sig) {
#if !defined(HAVE_POSIX_SIGNALS)
        if (sig) {
		signal(sig, SIG_DFL);
	}else{
		signal(sig, RCD_alarm_handler);
	}
#else
	struct sigaction sa;
	sigset_t sigmask;

	/* Maybe a bit naughty but it works and it saves duplicating all */
	/* this setup code - if handler called with 0 for sig, we install */
	/* ourself as handler. */
	if (sig) { 
		 sa.sa_handler = (void (*)(int))SIG_DFL;
	}else{
		sa.sa_handler = RCD_alarm_handler;
	}

	sigemptyset(&sigmask);
	sa.sa_mask = sigmask;
	sa.sa_flags = 0;
	sigaction(SIGALRM, &sa, NULL);
#endif

#ifdef RCD_NOPAUSE
	RCD_alarmcaught = 1;
#endif
	return;
}

static int
RCD_open_serial_port(char *device) {
	int fd;
	int status;
	int bothbits;

	if (OurImports->TtyLock(device) < 0) {
		if (Debug) {
			LOG(PIL_DEBUG, "%s: ttylock failed.", __FUNCTION__);
		}
		return -1;
	}

	bothbits = TIOCM_RTS | TIOCM_DTR;

	if ((fd = open(device, O_RDONLY | O_NDELAY)) != -1) {
		/*
			Opening the device always sets DTR & CTS high.
			Clear them down immediately.
		*/
		status = ioctl(fd, TIOCMBIC, &bothbits);
		/* If there was an error clearing bits, set the fd to -1 
		 * ( indicates error ) */
		if (status != 0 ) { 
			fd = -1;
		}
	}

	return fd;
}

static int
RCD_close_serial_port(char *device, int fd) {
        int rc = close(fd);
	if (device != NULL) {
		OurImports->TtyUnlock(device);
	}
	return rc;
}

/*
 *	RCD_Serial STONITH device.
 */
struct pluginDevice {
	StonithPlugin	sp;
	const char *	pluginid;
	const char *	idinfo;
	char **		hostlist;	/* name of single host we can reset */
	int		hostcount;	/* i.e. 1 after initialisation */
	char *		device;		/* serial device name */
	char *		signal;		/* either rts or dtr */
	long		msduration;	/* how long (ms) to assert the signal */
};

static const char * pluginid = "RCD_SerialDevice-Stonith";
static const char * NOTrcd_serialID = "RCD_Serial device has been destroyed";

#include "stonith_config_xml.h"

#define XML_DTRRTS_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	ST_DTRRTS \
	XML_PARM_SHORTDESC_END

#define XML_DTRRTS_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The hardware handshaking technique to use with " ST_TTYDEV "(\"dtr\" or \"rts\")" \
	XML_PARM_LONGDESC_END

#define XML_DTRRTS_PARM \
	XML_PARAMETER_BEGIN(ST_DTRRTS, "string", "1", "0") \
	  XML_DTRRTS_SHORTDESC \
	  XML_DTRRTS_LONGDESC \
	XML_PARAMETER_END

#define XML_MSDURATION_SHORTDESC \
	XML_PARM_SHORTDESC_BEGIN("en") \
	ST_MSDURATION \
	XML_PARM_SHORTDESC_END

#define XML_MSDURATION_LONGDESC \
	XML_PARM_LONGDESC_BEGIN("en") \
	"The delay duration (in milliseconds) between the assertion of the control signal on " ST_TTYDEV " and the closing of the reset switch" \
	XML_PARM_LONGDESC_END

#define XML_MSDURATION_PARM \
	XML_PARAMETER_BEGIN(ST_MSDURATION, "string", "1", "0") \
	  XML_MSDURATION_SHORTDESC \
	  XML_MSDURATION_LONGDESC \
	XML_PARAMETER_END

static const char *rcd_serialXML = 
  XML_PARAMETERS_BEGIN
    XML_HOSTLIST_PARM
    XML_TTYDEV_PARM
    XML_DTRRTS_PARM
    XML_MSDURATION_PARM
  XML_PARAMETERS_END;

static int
rcd_serial_status(StonithPlugin  *s)
{
	struct pluginDevice*	rcd;
	int fd;
	const char * err;

	ERRIFWRONGDEV(s,S_OOPS);

	rcd = (struct pluginDevice*) s;

	/*
	All we can do is make sure the serial device exists and
	can be opened and closed without error.
	*/

	if ((fd = RCD_open_serial_port(rcd->device)) == -1) {
                err = strerror(errno);
		LOG(PIL_CRIT, "%s: open of %s failed - %s",
			__FUNCTION__, rcd->device, err);
		return(S_OOPS);
	}

	if (RCD_close_serial_port(rcd->device, fd) != 0) {
                err = strerror(errno);
		LOG(PIL_CRIT, "%s: close of %s failed - %s",
			__FUNCTION__, rcd->device, err);
		return(S_OOPS);
	}

	return S_OK;
}


/*
 *	Return the list of hosts configured for this RCD_SERIAL device
 */
static char **
rcd_serial_hostlist(StonithPlugin  *s)
{
	struct pluginDevice*	rcd;

	ERRIFWRONGDEV(s,NULL);
	rcd = (struct pluginDevice*) s;
	if (rcd->hostcount < 0) {
		LOG(PIL_CRIT
		,	"unconfigured stonith object in RCD_SERIAL_list_hosts");
		return(NULL);
	}

	return OurImports->CopyHostList((const char * const *)rcd->hostlist);
}

/*
 *	At last, we really do it! I don't know what the request argument
 *	is so am just ignoring it...
 */
static int
rcd_serial_reset_req(StonithPlugin * s, int request, const char * host)
{
	struct pluginDevice*	rcd;
	int fd;
	int sigbit;
	struct itimerval timer;
	const char * err;
	
	ERRIFWRONGDEV(s,S_OOPS);

	rcd = (struct pluginDevice *) s;

	/* check that host matches */
	if (strcasecmp(host, rcd->hostlist[0])) {
		LOG(PIL_CRIT, "%s: host '%s' not in hostlist.",
			__FUNCTION__, host);
		return(S_BADHOST);
	}

	/* Set the appropriate bit for the signal */
	sigbit = *(rcd->signal)=='r' ? TIOCM_RTS : TIOCM_DTR;

	/* Set up the timer */
	timer.it_interval.tv_sec  = 0;
	timer.it_interval.tv_usec = 0;
	timer.it_value.tv_sec  =  rcd->msduration / 1000;
	timer.it_value.tv_usec = (rcd->msduration % 1000) * 1000;

	/* Open the device */
	if ((fd = RCD_open_serial_port(rcd->device)) == -1) {
#ifdef HAVE_STRERROR
                err = strerror(errno);
#else
		err = sys_errlist[errno];
#endif
		LOG(PIL_CRIT, "%s: open of %s failed - %s",
			__FUNCTION__, rcd->device, err);
		return(S_OOPS);
	}

	/* Start the timer */
	RCD_alarm_handler(0);
#ifdef RCD_NOPAUSE
	RCD_alarmcaught = 0;
#endif
	setitimer(ITIMER_REAL, &timer, 0);

        /* Set the line high */
        ioctl(fd, TIOCMBIS, &sigbit);

        /* Wait for the alarm signal */
#ifdef RCD_NOPAUSE
        while(!RCD_alarmcaught) ioctl(fd, TIOCMBIS, &sigbit);
#else
        pause();
#endif

        /* Clear the line low */
        ioctl(fd, TIOCMBIC, &sigbit);

        /* Close the port */
	if (RCD_close_serial_port(rcd->device, fd) != 0) {
                err = strerror(errno);
		LOG(PIL_CRIT, "%s: close of %s failed - %s",
			__FUNCTION__, rcd->device, err);
		return(S_OOPS);
	}

	LOG(PIL_INFO,"Host rcd_serial-reset: %s", host);
	return S_OK;
}

/*
 *	Parse the information in the given string 
 *	and stash it away...
 */
static int
rcd_serial_set_config(StonithPlugin* s, StonithNVpair *list)
{
	struct pluginDevice*	rcd;
	StonithNamesToGet	namestocopy [] =
	{	{ST_HOSTLIST,	NULL}
	,	{ST_TTYDEV,	NULL}
	,	{ST_DTRRTS,	NULL}
	,	{ST_MSDURATION,	NULL}
	,	{NULL,		NULL}
	};
	char *endptr;
	int rc = 0;

	LOG(PIL_DEBUG, "%s:called", __FUNCTION__);
	
	ERRIFWRONGDEV(s,S_OOPS);
	if (s->isconfigured) {
		return S_OOPS;
	}

	rcd = (struct pluginDevice*) s;

	if ((rc = OurImports->CopyAllValues(namestocopy, list)) != S_OK) {
		return rc;
	}

	if ((rcd->hostlist = (char **)MALLOC(2*sizeof(char*))) == NULL) {
		LOG(PIL_CRIT, "%s: out of memory!", __FUNCTION__);
		FREE(namestocopy[0].s_value);
		FREE(namestocopy[1].s_value);
		FREE(namestocopy[2].s_value);
		FREE(namestocopy[3].s_value);
		return S_OOPS;
	}
	rcd->hostlist[0] = namestocopy[0].s_value;
	strdown(rcd->hostlist[0]);
	rcd->hostlist[1] = NULL;
	rcd->hostcount = 1;
	rcd->device = namestocopy[1].s_value;
	rcd->signal = namestocopy[2].s_value;
        if (strcmp(rcd->signal, "rts") && strcmp(rcd->signal, "dtr")) {
		LOG(PIL_CRIT, "%s: Invalid signal name '%s'",
			pluginid, rcd->signal);
		FREE(namestocopy[3].s_value);
		return S_BADCONFIG;
        }

	errno = 0;
	rcd->msduration = strtol(namestocopy[3].s_value, &endptr, 0);
	if (((errno == ERANGE)
	&&   (rcd->msduration == LONG_MIN || rcd->msduration == LONG_MAX))
	|| *endptr != 0 || rcd->msduration < 1) {
		LOG(PIL_CRIT, "%s: Invalid msduration '%s'",
			pluginid, namestocopy[3].s_value);
		FREE(namestocopy[3].s_value);
		return S_BADCONFIG;
	}
	FREE(namestocopy[3].s_value);
	
	return S_OK;
}

/*
 * Return STONITH config vars
 */
static const char * const *
rcd_serial_get_confignames(StonithPlugin* p)
{
	static const char *	RcdParams[] = {ST_HOSTLIST, ST_TTYDEV
				, ST_DTRRTS, ST_MSDURATION,  NULL };
	return RcdParams;
}

/*
 * Return STONITH info string
 */
static const char *
rcd_serial_getinfo(StonithPlugin * s, int reqtype)
{
	struct pluginDevice* rcd;
	const char * ret;

	ERRIFWRONGDEV(s,NULL);
	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	rcd = (struct pluginDevice *)s;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = rcd->idinfo;
			break;
		case ST_DEVICENAME:
			ret = rcd->device;
			break;
		case ST_DEVICEDESCR:
			ret = "RC Delayed Serial STONITH Device\n"
			"This device can be constructed cheaply from"
			" readily available components,\n"
			"with sufficient expertise and testing.\n"
			"See README.rcd_serial for circuit diagram.\n";
			break;
		case ST_DEVICEURL:
			ret = "http://www.scl.co.uk/rcd_serial/";
			break;
		case ST_CONF_XML:		/* XML metadata */
			ret = rcd_serialXML;
			break;
		default:
			ret = NULL;
			break;
	}
	return ret;
}

/*
 *	RCD_SERIAL Stonith destructor...
 */
static void
rcd_serial_destroy(StonithPlugin *s)
{
	struct pluginDevice* rcd;

	VOIDERRIFWRONGDEV(s);

	rcd = (struct pluginDevice *)s;

	rcd->pluginid = NOTrcd_serialID;
	if (rcd->hostlist) {
		stonith_free_hostlist(rcd->hostlist);
		rcd->hostlist = NULL;
	}
	rcd->hostcount = -1;
	if (rcd->device) {
		FREE(rcd->device);
	}
	if (rcd->signal) {
		FREE(rcd->signal);
	}
	FREE(rcd);
}

/*
 * Create a new RCD_Serial Stonith device.
 * Too bad this function can't be static. (Hmm, weird, it _is_ static?)
 */
static StonithPlugin *
rcd_serial_new(const char *subplugin)
{
	struct pluginDevice*	rcd = ST_MALLOCT(struct pluginDevice);

	if (rcd == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(rcd, 0, sizeof(*rcd));

	rcd->pluginid = pluginid;
	rcd->hostlist = NULL;
	rcd->hostcount = -1;
	rcd->device = NULL;
	rcd->signal = NULL;
	rcd->msduration = 0;
	rcd->idinfo = DEVICE;
	rcd->sp.s_ops = &rcd_serialOps;

	return &(rcd->sp);
}
