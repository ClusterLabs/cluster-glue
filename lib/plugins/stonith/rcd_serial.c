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

#include <portability.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <libintl.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/time.h>
#ifdef HAVE_TERMIO_H
#	include <termio.h>
#endif
#include <sys/termios.h>

#include <stonith/stonith.h>
#include "stonith_signal.h"

#define PIL_PLUGINTYPE          STONITH_TYPE
#define PIL_PLUGINTYPE_S        STONITH_TYPE_S
#define PIL_PLUGIN              rcd_serial
#define PIL_PLUGIN_S            "rcd_serial"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

/*
 * rcd_serialclose is called as part of unloading the rcd_serial STONITH plugin.
 * If there was any global data allocated, or file descriptors opened, etc.
 * which is associated with the plugin, and not a single interface
 * in particular, here's our chance to clean it up.
 */

static void
rcd_serialclosepi(PILPlugin*pi)
{
}


/*
 * rcd_serialcloseintf called as part of shutting down the rcd_serial STONITH
 * interface.  If there was any global data allocated, or file descriptors
 * opened, etc.  which is associated with the rcd_serial implementation,
 * here's our chance to clean it up.
 */
static PIL_rc
rcd_serialcloseintf(PILInterface* pi, void* pd)
{
	return PIL_OK;
}

static void *		rcd_serial_new(void);
static void		rcd_serial_destroy(Stonith *);
static int		rcd_serial_set_config_file(Stonith *,
						const char * cfgname);
static int		rcd_serial_set_config_info(Stonith *,
						const char * info);
static const char *	rcd_serial_getinfo(Stonith * s, int InfoType);
static int		rcd_serial_status(Stonith * );
static int		rcd_serial_reset_req(Stonith * s,
						int request, const char * host);
static char **		rcd_serial_hostlist(Stonith  *);
static void		rcd_serial_free_hostlist(char **);

static struct stonith_ops rcd_serialOps ={
	rcd_serial_new,			/* Create new STONITH object	*/
	rcd_serial_destroy,		/* Destroy STONITH object	*/
	rcd_serial_set_config_file,	/* set configuration from file	*/
	rcd_serial_set_config_info,	/* Get configuration from file	*/
	rcd_serial_getinfo,		/* Return STONITH info string	*/
	rcd_serial_status,		/* Return STONITH device status	*/
	rcd_serial_reset_req,		/* Request a reset */
	rcd_serial_hostlist,		/* Return list of supported hosts */
	rcd_serial_free_hostlist	/* free above list */
};

PIL_PLUGIN_BOILERPLATE("1.0", Debug, rcd_serialclosepi);
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
	,	&rcd_serialOps
	,	rcd_serialcloseintf		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

#define	DEVICE	"RCD_SERIAL STONITH device"
#define WHITESPACE	" \t\n\r\f"

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
static int RCD_close_serial_port(int fd);

static void
RCD_alarm_handler(int sig) {
#if !defined(HAVE_POSIX_SIGNALS)
        if (sig)
		signal(sig, SIG_DFL);
	else    signal(sig, RCD_alarm_handler);
#else
	struct sigaction sa;
	sigset_t sigmask;

	// Maybe a bit naughty but it works and it saves duplicating all
	// this setup code - if handler called with 0 for sig, we install
	// ourself as handler.
	if (sig) sa.sa_handler = (void (*)(int))SIG_DFL;
	else     sa.sa_handler = RCD_alarm_handler;

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
	int bothbits = TIOCM_RTS | TIOCM_DTR;

	if ((fd = open(device, O_RDONLY | O_NDELAY)) != -1) {
		// Opening the device always sets DTR & CTS high.
		// Clear them down immediately.
		ioctl(fd, TIOCMBIC, &bothbits);
	}

	return fd;
}

static int
RCD_close_serial_port(int fd) {
        return close(fd);
}

/*
 *	RCD_Serial STONITH device.
 */
struct RCD_SerialDevice {
	const char *	RCD_SERIALid;
	char **		hostlist;	/* name of single host we can reset */
	int		hostcount;	/* i.e. 1 after initialisation */
	char *		device;		/* serial device name */
	char *		signal;		/* either rts or dtr */
	int		msduration;	/* how long (ms) to assert the signal */
};

static const char * RCD_SERIALid = "RCD_SerialDevice-Stonith";
static const char * NOTrcd_serialID = "Hey, dummy this has been destroyed (RCD_SerialDev)";

#define	ISRCD_SERIALDEV(i)	(((i)!= NULL && (i)->pinfo != NULL)	\
	&& ((struct RCD_SerialDevice *)(i->pinfo))->RCD_SERIALid == RCD_SERIALid)


#ifndef MALLOC
#	define	MALLOC	malloc
#endif
#ifndef FREE
#	define	FREE	free
#endif
#ifndef MALLOCT
#	define     MALLOCT(t)      ((t *)(MALLOC(sizeof(t)))) 
#endif

#define N_(text)	(text)
#define _(text)		dgettext(ST_TEXTDOMAIN, text)


static int
rcd_serial_status(Stonith  *s)
{
	struct RCD_SerialDevice*	rcd;
	int fd;
	const char * err;

	if (!ISRCD_SERIALDEV(s)) {
		syslog(LOG_ERR, "invalid argument to RCD_SERIAL_status");
		return(S_OOPS);
	}

	rcd = (struct RCD_SerialDevice*) s->pinfo;

	/*
	All we can do is make sure the serial device exists and
	can be opened and closed without error.
	*/

	if ((fd = RCD_open_serial_port(rcd->device)) == -1) {
                err = strerror(errno);
		syslog(LOG_ERR, "%s: open of %s failed - %s",
			__FUNCTION__, rcd->device, err);
		return(S_OOPS);
	}

	if (RCD_close_serial_port(fd) != 0) {
                err = strerror(errno);
		syslog(LOG_ERR, "%s: close of %s failed - %s",
			__FUNCTION__, rcd->device, err);
		return(S_OOPS);
	}

	return S_OK;
}


/*
 *	Return the list of hosts configured for this RCD_SERIAL device
 */
static char **
rcd_serial_hostlist(Stonith  *s)
{
	char **		ret = NULL;
	struct RCD_SerialDevice*	rcd;
	int		j;

	if (!ISRCD_SERIALDEV(s)) {
		syslog(LOG_ERR, "invalid argument to RCD_SERIAL_list_hosts");
		return(NULL);
	}
	rcd = (struct RCD_SerialDevice*) s->pinfo;
	if (rcd->hostcount < 0) {
		syslog(LOG_ERR
		,	"unconfigured stonith object in RCD_SERIAL_list_hosts");
		return(NULL);
	}

	ret = (char **)MALLOC((rcd->hostcount+1)*sizeof(char*));
	if (ret == NULL) {
		syslog(LOG_ERR, "out of memory");
		return ret;
	}

	memset(ret, 0, (rcd->hostcount+1)*sizeof(char*));

	for (j=0; j < rcd->hostcount; ++j) {
		ret[j] = MALLOC(strlen(rcd->hostlist[j])+1);
		if (ret[j] == NULL) {
			rcd_serial_free_hostlist(ret);
			ret = NULL;
			return ret;
		}
		strcpy(ret[j], rcd->hostlist[j]);
	}
	return(ret);
}

static void
rcd_serial_free_hostlist (char ** hlist)
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
	hlist = NULL;
}

/*
 *	Parse the config information, and stash it away...
 */
static int
RCD_SERIAL_parse_config_info(struct RCD_SerialDevice* rcd, const char * info)
{
	char *copy;
	char *token;
	char *endptr;
	int ret;

	if (rcd->hostcount >= 0) {
		return(S_OOPS);
	}

	/* strtok() is nice to use to parse a string with
	   (other than it isn't threadsafe), but it is destructive, so
	   we're going to alloc our own private little copy for the
	   duration of this function.
	*/

	copy = strdup(info);
	if (!copy) {
		syslog(LOG_ERR, "%s: out of memory!", __FUNCTION__);
		return S_OOPS;
	}

	/* Grab the hostname */
	token = strtok (copy, WHITESPACE);
	if (!token) {
		syslog(LOG_ERR, "%s: Can't find hostname on config line '%s'",
			RCD_SERIALid, info);
		ret = S_BADCONFIG;
		goto token_error;
	}

	if ((rcd->hostlist = (char **)MALLOC(2*sizeof(char*))) == NULL) {
		syslog(LOG_ERR, "%s: out of memory!", __FUNCTION__);
		ret = S_OOPS;
		goto token_error;
	}
	memset(rcd->hostlist, 0, 2*sizeof(char*));
	rcd->hostcount = 0;

	rcd->hostlist[0] = strdup(token);
	if (!rcd->hostlist[0]) {
		syslog(LOG_ERR, "%s: out of memory!", __FUNCTION__);
		ret = S_OOPS;
		goto token_error;
	}
	rcd->hostcount = 1;

	/* Grab the device name */
	token = strtok (NULL, WHITESPACE);
	if (!token) {
		syslog(LOG_ERR, "%s: Can't find device on config line '%s'",
			RCD_SERIALid, info);
		ret = S_BADCONFIG;
		goto token_error;
	}

	rcd->device = strdup(token);
	if (!rcd->device) {
		syslog(LOG_ERR, "%s: out of memory!", __FUNCTION__);
		ret = S_OOPS;
		goto token_error;
	}

	/* Grab the signal name */
	token = strtok (NULL, WHITESPACE);
	if (!token) {
		syslog(LOG_ERR, "%s: Can't find signal on config line '%s'",
			RCD_SERIALid, info);
		ret = S_BADCONFIG;
		goto token_error;
	}

	rcd->signal = strdup(token);
	if (!rcd->signal) {
		syslog(LOG_ERR, "%s: out of memory!", __FUNCTION__);
		ret = S_OOPS;
		goto token_error;
	}

        if (strcmp(rcd->signal, "rts") && strcmp(rcd->signal, "dtr")) {
		syslog(LOG_ERR, "%s: Invalid signal name on config line '%s'",
			RCD_SERIALid, info);
		ret = S_BADCONFIG;
		goto token_error;
        }

	/* Grab the duration in millisecs */
	token = strtok (NULL, WHITESPACE);
	if (!token) {
		syslog(LOG_ERR, "%s: Can't find msduration on config line '%s'",
			RCD_SERIALid, info);
		ret = S_BADCONFIG;
		goto token_error;
	}

	rcd->msduration = strtol(token, &endptr, 0);
	if (*token == 0 || *endptr != 0 || rcd->msduration < 1) {
		syslog(LOG_ERR, "%s: Invalid msduration on config line '%s'",
			RCD_SERIALid, info);
		ret = S_BADCONFIG;
		goto token_error;
	}

	/* Make sure nothing extra provided */
	token = strtok (NULL, WHITESPACE);
	if (token) {
		syslog(LOG_ERR, "%s: Too many params on config line '%s'",
			RCD_SERIALid, info);
		ret = S_BADCONFIG;
		goto token_error;
	}

        /* free our private copy of the string we've been destructively
           parsing with strtok()
        */
        free(copy);
        return S_OK;

token_error:
        free(copy);
        return(ret);
}

/*
 *	At last, we really do it! I don't know what the request argument
 *	is so am just ignoring it...
 */
static int
rcd_serial_reset_req(Stonith * s, int request, const char * host)
{
	struct RCD_SerialDevice*	rcd;
	int fd;
	int sigbit;
	struct itimerval timer;
	const char * err;

	if (!ISRCD_SERIALDEV(s)) {
		syslog(LOG_ERR, "invalid argument to %s", __FUNCTION__);
		return(S_OOPS);
	}

	rcd = (struct RCD_SerialDevice *) s->pinfo;

	/* check that host matches */
	if (strcmp(host, rcd->hostlist[0])) {
		syslog(LOG_ERR, "%s: host '%s' not in hostlist.",
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
		syslog(LOG_ERR, "%s: open of %s failed - %s",
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
	if (RCD_close_serial_port(fd) != 0) {
                err = strerror(errno);
		syslog(LOG_ERR, "%s: close of %s failed - %s",
			__FUNCTION__, rcd->device, err);
		return(S_OOPS);
	}

	syslog(LOG_INFO, _("Host %s rcd_serial-reset."), host);
	return S_OK;
}

/*
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */
static int
rcd_serial_set_config_file(Stonith* s, const char * configname)
{
	FILE *	cfgfile;

	char	RCD_SERIALline[256];

	struct RCD_SerialDevice*	rcd;

	if (!ISRCD_SERIALDEV(s)) {
		syslog(LOG_ERR,"invalid argument to RCD_SERIAL_set_configfile");
		return(S_OOPS);
	}
	rcd = (struct RCD_SerialDevice*) s->pinfo;

	if ((cfgfile = fopen(configname, "r")) == NULL)  {
		syslog(LOG_ERR, "Cannot open %s", configname);
		return(S_BADCONFIG);
	}
	while (fgets(RCD_SERIALline, sizeof(RCD_SERIALline), cfgfile) != NULL){
		if (	*RCD_SERIALline == '#'  || \
			*RCD_SERIALline == '\n' || \
			*RCD_SERIALline == EOS)
		{
			continue;
		}
		return(RCD_SERIAL_parse_config_info(rcd, RCD_SERIALline));
	}
	return(S_BADCONFIG);
}

/*
 *	Parse the config information in the given string, and stash it away...
 */
static int
rcd_serial_set_config_info(Stonith* s, const char * info)
{
	struct RCD_SerialDevice* rcd;

	if (!ISRCD_SERIALDEV(s)) {
		syslog(LOG_ERR, "%s: invalid argument", __FUNCTION__);
		return(S_OOPS);
	}
	rcd = (struct RCD_SerialDevice *)s->pinfo;

	return(RCD_SERIAL_parse_config_info(rcd, info));
}

static const char *
rcd_serial_getinfo(Stonith * s, int reqtype)
{
	struct RCD_SerialDevice* rcd;
	char *		ret;

	if (!ISRCD_SERIALDEV(s)) {
		syslog(LOG_ERR, "RCD_SERIAL_idinfo: invalid argument");
		return NULL;
	}
	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	rcd = (struct RCD_SerialDevice *)s->pinfo;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = _(DEVICE);
			break;

		case ST_CONF_INFO_SYNTAX:
			ret = _("<hostname> <serial_device> <dtr|rts> "
			"<msduration>\n"
			"All tokens are white-space delimited.\n");
			break;

		case ST_CONF_FILE_SYNTAX:
			ret = _("<hostname> <serial_device> <dtr|rts> "
			"<msduration>\n"
			"All tokens are white-space delimited.\n"
			"Blank lines and lines beginning with # are ignored");
			break;

		case ST_DEVICEDESCR:
			ret = _("RC Delayed Serial STONITH Device\n"
			"This device can be constructed cheaply from"
			" readily available components,\n"
			"with sufficient expertise and testing.\n"
			"See README.rcd_serial for circuit diagram.\n");
			break;

		case ST_DEVICEURL:
			ret = _("http://www.scl.co.uk/rcd_serial/");
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
rcd_serial_destroy(Stonith *s)
{
	struct RCD_SerialDevice* rcd;

	if (!ISRCD_SERIALDEV(s)) {
		syslog(LOG_ERR, "%s: invalid argument", __FUNCTION__);
		return;
	}
	rcd = (struct RCD_SerialDevice *)s->pinfo;

	rcd->RCD_SERIALid = NOTrcd_serialID;
	if (rcd->hostlist) {
		rcd_serial_free_hostlist(rcd->hostlist);
		rcd->hostlist = NULL;
	}
	rcd->hostcount = -1;
	if (rcd->device) FREE(rcd->device);
	if (rcd->signal) FREE(rcd->signal);
	FREE(rcd);
}

/*
 * Create a new RCD_Serial Stonith device.
 * Too bad this function can't be static. (Hmm, weird, it _is_ static?)
 */
static void *
rcd_serial_new(void)
{
	struct RCD_SerialDevice*	rcd = MALLOCT(struct RCD_SerialDevice);

	if (rcd == NULL) {
		syslog(LOG_ERR, "out of memory");
		return(NULL);
	}
	memset(rcd, 0, sizeof(*rcd));

	rcd->RCD_SERIALid = RCD_SERIALid;
	rcd->hostlist = NULL;
	rcd->hostcount = -1;
	rcd->device = NULL;
	rcd->signal = NULL;
	rcd->msduration = 0;

	return((void *)rcd);
}
