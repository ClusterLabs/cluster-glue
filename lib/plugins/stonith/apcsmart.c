/* $Id: apcsmart.c,v 1.24 2005/04/06 18:58:42 blaschke Exp $ */
/*
 * Stonith module for APCSmart Stonith device
 * Copyright (c) 2000 Andreas Piesk <a.piesk@gmx.net>
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
 * Original version of this UPS code was taken from:
 *   'Network UPS Tools' by Russell Kroll <rkroll@exploits.org>
 *   homepage: http://www.networkupstools.org/
 *
 *  Significantly mangled by Alan Robertson <alanr@unix.sh>
 */

#define	DEVICE	                "APCSmart-Stonith"

#include "stonith_plugin_common.h"

/*
 * APCSmart (tested with 2 old 900XLI, and an APC SmartUPS 700)
 *
 * the reset is a combined reset (cmd: S@000).
 * that means if the ups is online, a scheduled reset (20s delay)
 * will be triggered. after the reset the ups will immediately
 * return  online. if the ups is on-battery, the reset will also be
 * a scheduled reset but the ups will remain offline until the power
 * is back. 
 */

#define CFG_FILE		"/etc/ha.d/apcsmart.cfg"

#define MAX_DEVICES		1

#define SERIAL_TIMEOUT		3	/* timeout in sec */
#define SEND_DELAY		50000	/* in microseconds */
#define ENDCHAR			10	/* use LF */
#define MAX_STRING              512
#define SHUTDOWN_DELAY		"020"
#define WAKEUP_DELAY		"000"
#define SWITCH_TO_NEXT_VAL	"-"	/* APC cmd for cycling through
					 * the values
					 */

#define CMD_SMART_MODE          "Y"
#define RSP_SMART_MODE		"SM"
#define CMD_GET_STATUS		"Q"
#define RSP_GET_STATUS		NULL
#define CMD_RESET               "@000"
#define RSP_RESET		"*"
#define RSP_RESET2		"OK"
#define	RSP_NA			"NA"
#define	CMD_READREG1		"~"
#define CMD_OFF			"Z"
#define CMD_ON			"\016" /* (control-n) */
#define CMD_SHUTDOWN_DELAY	"p"
#define CMD_WAKEUP_DELAY	"r"

#define CR			13

struct pluginDevice {
	StonithPlugin	sp;
	const char *	pluginid; /* of object				*/
	char **		hostlist; /* served by the device (only 1)	*/
	int		hostcount;/* of hosts (1)			*/
	char *		upsdev;   /*					*/
	int		upsfd;    /* for serial port			*/
	int		retries;
};

/* saving old settings */
/* FIXME!  These should be part of pluginDevice struct above */
static struct termios old_tio;
static char old_shutdown_delay[MAX_STRING];
static char old_wakeup_delay[MAX_STRING];

static int f_serialtimeout;	/* flag for timeout */
static const char *pluginid = DEVICE;
static const char *NOTpluginID = "destroyed (APCSmart)";

/*
 * stonith prototypes 
 */

#define PIL_PLUGIN              apcsmart
#define PIL_PLUGIN_S            "apcsmart"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

#include "stonith_signal.h"

static StonithPlugin *	apcsmart_new(const char *);
static void		apcsmart_destroy(StonithPlugin *);
static const char**	apcsmart_get_confignames(StonithPlugin*);
static int		apcsmart_set_config(StonithPlugin *, StonithNVpair*);
static const char *	apcsmart_get_info(StonithPlugin * s, int InfoType);
static int		apcsmart_status(StonithPlugin * );
static int		apcsmart_req_reset(StonithPlugin * s, int request, const char * host);
static char **		apcsmart_hostlist(StonithPlugin  *);

static struct stonith_ops apcsmartOps ={
	apcsmart_new,		  /* Create new STONITH object		*/
	apcsmart_destroy,	  /* Destroy STONITH object		*/
	apcsmart_get_info,	  /* Return STONITH info string		*/
	apcsmart_get_confignames, /* Return STONITH info string		*/
	apcsmart_set_config,	  /* Get configuration from NVpairs	*/
	apcsmart_status,	  /* Return STONITH device status	*/
	apcsmart_req_reset,	  /* Request a reset 			*/
	apcsmart_hostlist,	  /* Return list of supported hosts	*/
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
	,	&apcsmartOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*
 * own prototypes 
 */

int APC_open_serialport(const char *port, speed_t speed);
void APC_close_serialport(int upsfd);
void APC_sh_serial_timeout(int sig);
int APC_send_cmd(int upsfd, const char *cmd);
int APC_recv_rsp(int upsfd, char *rsp);
int APC_enter_smartmode(int upsfd);
int APC_set_ups_var(int upsfd, const char *cmd, char *newval);
int APC_init( struct pluginDevice *ad );
void APC_deinit( int upsfd );

/*
 *
 * Portable locking (non-blocking)
 *
 * This is a candidate for including in a general portability library.
 */

static int
file_lock(int fd)
{
	int ret;

#ifdef HAVE_FCNTL
	struct flock l;

	l.l_type = F_WRLCK;
	l.l_whence = 0;
	l.l_start = 0;
	l.l_len = 0;

	ret = fcntl(fd, F_SETLK, &l);
	return((ret == -1) ? -1 : 0);
#else
#  ifdef HAVE_FLOCK
	ret = flock(fd, LOCK_EX | LOCK_NB);
	return(ret);

#  else
#    error "No locking method (flock, fcntl) is available"
	return(-1);
#  endif /* HAVE_FLOCK */
#endif /* HAVE_FCNTL */

}

static int
file_unlock(int fd)
{
	int ret;

#ifdef HAVE_FCNTL
	struct flock l;

	l.l_type = F_UNLCK;
	l.l_whence = 0;
	l.l_start = 0;
	l.l_len = 0;

	ret = fcntl(fd, F_SETLK, &l);
	return((ret == -1) ? -1 : 0);
#else
#  ifdef HAVE_FLOCK
	ret = flock(fd, LOCK_UN);
	return(ret);
#  else
#    error "No unlocking method (flock, fcntl) is available"
	return(-1);
#  endif /* HAVE_FLOCK */
#endif /* HAVE_FCNTL */

}

/*
 * Signal handler for serial port timeouts 
 */

void
APC_sh_serial_timeout(int sig)
{
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	STONITH_IGNORE_SIG(SIGALRM);

	if (Debug) {
		LOG(PIL_DEBUG, "%s: serial port timed out.", __FUNCTION__);
	}

	f_serialtimeout = TRUE;

    return;
}

/*
 * Open serial port and set it to b2400 
 */

int
APC_open_serialport(const char *port, speed_t speed)
{
	struct termios tio;
	int fd;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	STONITH_SIGNAL(SIGALRM, APC_sh_serial_timeout);

	alarm(SERIAL_TIMEOUT);

	f_serialtimeout = FALSE;

	fd = open(port, O_RDWR | O_NOCTTY | O_NONBLOCK | O_EXCL);

	alarm(0);
	STONITH_IGNORE_SIG(SIGALRM);

	if (fd < 0) {
		if (Debug) {
			LOG(PIL_DEBUG, "%s: 1st open failed.", __FUNCTION__);
		}
		return (f_serialtimeout ? S_TIMEOUT : S_OOPS);
	}

	if (file_lock(fd) != 0) {
		if (Debug) {
			LOG(PIL_DEBUG, "%s: 1st lock failed.", __FUNCTION__);
		}
		return (S_OOPS);
	}

	tcgetattr(fd, &old_tio);
	memcpy(&tio, &old_tio, sizeof(struct termios));

	tio.c_lflag = 0 | ECHOE | ECHOKE | ECHOCTL | PENDIN;
	tio.c_iflag = 0 | IXANY | IMAXBEL | IXOFF;
	tio.c_oflag = 0 | ONLCR;
	tio.c_cflag = 0 | CREAD | CS8 | HUPCL | CLOCAL;

	cfsetispeed(&tio, speed);
	cfsetospeed(&tio, speed);

	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;

	tcflush(fd, TCIFLUSH);
	tcsetattr(fd, TCSANOW, &tio);
	close(fd);

	STONITH_SIGNAL(SIGALRM, APC_sh_serial_timeout);
	alarm(SERIAL_TIMEOUT);

	fd = open(port, O_RDWR | O_NOCTTY | O_EXCL);

	alarm(0);
	STONITH_IGNORE_SIG(SIGALRM);

	if (fd < 0) {
		if (Debug) {
			LOG(PIL_DEBUG, "%s: 2nd open failed.", __FUNCTION__);
		}
		return (f_serialtimeout ? S_TIMEOUT : S_OOPS);
	}

	if (file_lock(fd) != 0) {
		if (Debug) {
			LOG(PIL_DEBUG, "%s: 2nd lock failed.", __FUNCTION__);
		}

		return (f_serialtimeout ? S_TIMEOUT : S_OOPS);
	}

	tcgetattr(fd, &tio);

	tio.c_cflag = CS8 | CLOCAL | CREAD;
	tio.c_iflag = IGNPAR;
	tio.c_oflag = 0;
	tio.c_lflag = 0;
	tio.c_cc[VMIN] = 1;
	tio.c_cc[VTIME] = 0;

	cfsetispeed(&tio, speed);
	cfsetospeed(&tio, speed);

	tcflush(fd, TCIFLUSH);
	tcsetattr(fd, TCSANOW, &tio);

	return (fd);
}

/*
 * Close serial port and restore old settings 
 */

void
APC_close_serialport(int upsfd)
{

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	file_unlock(upsfd);

	tcflush(upsfd, TCIFLUSH);
	tcsetattr(upsfd, TCSANOW, &old_tio);
	close(upsfd);
}

/*
 * Send a command to the ups 
 */

int
APC_send_cmd(int upsfd, const char *cmd)
{
	int i;

	if (Debug) {
		LOG(PIL_DEBUG, "%s(\"%s\")", __FUNCTION__, cmd);
	}

	tcflush(upsfd, TCIFLUSH);
	for (i = strlen(cmd); i > 0; i--) {
		if (write(upsfd, cmd++, 1) != 1) {
			return (S_ACCESS);
		}

		usleep(SEND_DELAY);
	}
	return (S_OK);
}

/*
 * Get the response from the ups 
 */

int
APC_recv_rsp(int upsfd, char *rsp)
{
	char *p = rsp;
	char inp;
	int num = 0;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	*p = '\0';

	STONITH_SIGNAL(SIGALRM, APC_sh_serial_timeout);

	alarm(SERIAL_TIMEOUT);

	while (num < MAX_STRING) {

		if (read(upsfd, &inp, 1) == 1) {

	    		/* shutdown sends only a '*' without LF  */
			if ((inp == '*') && (num == 0)) {
				*p++ = inp;
				num++;
				inp = ENDCHAR;
			}

			if (inp == ENDCHAR) {
				alarm(0);
				STONITH_IGNORE_SIG(SIGALRM);

				*p = '\0';
				if (Debug) {
					LOG(PIL_DEBUG, "return(\"%s\")/*%s*/;"
					,	rsp, __FUNCTION__);
				}
				return (S_OK);
			}

			if (inp != CR) {
				*p++ = inp;
				num++;
			}
		}else{
	    		alarm(0);
			STONITH_IGNORE_SIG(SIGALRM);
			*p = '\0';
			return (f_serialtimeout ? S_TIMEOUT : S_ACCESS);
		}
	}
	return (S_ACCESS);
}

/*
 *  Enter smart mode
 */

int
APC_enter_smartmode(int upsfd)
{
    int rc;
    char resp[MAX_STRING];

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	strcpy(resp, RSP_SMART_MODE);

	if (((rc = APC_send_cmd(upsfd, CMD_SMART_MODE)) == S_OK)
	&&	((rc = APC_recv_rsp(upsfd, resp)) == S_OK)
	&&	(strcmp(RSP_SMART_MODE, resp) == 0)) {
			return (S_OK);
	}

	return (S_ACCESS);
}

/* 
 * Set a value in the hardware using the <cmdchar> '-' (repeat) approach
 */

int
APC_set_ups_var(int upsfd, const char *cmd, char *newval)
{
	char resp[MAX_STRING];
	char orig[MAX_STRING];
	int rc;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	if (((rc = APC_enter_smartmode(upsfd)) != S_OK)
	||	((rc = APC_send_cmd(upsfd, cmd)) != S_OK)
	||	((rc = APC_recv_rsp(upsfd, orig)) != S_OK)) {
			return (rc);
	}

	if (strcmp(orig, newval) == 0) {
		return (S_OK);		/* already set */
	}

	*resp = '\0';

	while (strcmp(resp, orig) != 0) {
		if (((rc = APC_send_cmd(upsfd, SWITCH_TO_NEXT_VAL)) != S_OK)
		||	((rc = APC_recv_rsp(upsfd, resp)) != S_OK)) {
	    			return (rc);
		}

		if (((rc = APC_enter_smartmode(upsfd)) != S_OK)
		||	((rc = APC_send_cmd(upsfd, cmd)) != S_OK)
		||	((rc = APC_recv_rsp(upsfd, resp)) != S_OK)) {
	    			return (rc);
		}

		if (strcmp(resp, newval) == 0) {
			strcpy(newval, orig);	/* return the old value */
			return (S_OK);		/* got it */
		}
	}

	LOG(PIL_CRIT, "%s(): Could not set variable '%s' to %s!"
	,	__FUNCTION__, cmd, newval);
	LOG(PIL_CRIT, "%s(): This UPS may not support STONITH :-("
	,	 __FUNCTION__);

	return (S_OOPS);
}

/*
 * Initialize the ups
 */

int
APC_init(struct pluginDevice *ad)
{
	int upsfd;
	char value[MAX_STRING];

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	/* if ad->upsfd == -1 -> dev configured! */
	if(ad->upsfd >= 0 ) {
		 return S_OK;
	}

	/* open serial port and store the fd in ad->upsfd */
	if ((upsfd = APC_open_serialport(ad->upsdev, B2400)) == -1) {
		return -1;
	}

	/* switch into smart mode */
	if (APC_enter_smartmode(upsfd) != S_OK) {
		return -1;
	}

	/* get the old settings and store them */
	strcpy(value, SHUTDOWN_DELAY);
	if (APC_set_ups_var(upsfd, CMD_SHUTDOWN_DELAY, value) != S_OK) {
		return -1;
	}
	strcpy(old_shutdown_delay, value);
	strcpy(value, WAKEUP_DELAY);
	if (APC_set_ups_var(upsfd, CMD_WAKEUP_DELAY, value) != S_OK) {
		return (-1);
	}

	strcpy(old_wakeup_delay, value);
	ad->upsfd = upsfd;
	return S_OK;
}

/*
 * Restore original settings and close the port
 */

void
APC_deinit( int upsfd )
{
	APC_enter_smartmode( upsfd );

	APC_set_ups_var(upsfd, CMD_SHUTDOWN_DELAY, old_shutdown_delay);
	APC_set_ups_var(upsfd, CMD_WAKEUP_DELAY, old_wakeup_delay);

	/* close serial port */
	APC_close_serialport(upsfd);
}
static const char**
apcsmart_get_confignames(StonithPlugin* sp)
{
	static const char * names[] =  {ST_TTYDEV, ST_HOSTLIST, NULL};
	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}
	return names;
}

/*
 * Stash away the config info we've been given...
 */

static int
apcsmart_set_config(StonithPlugin * s, StonithNVpair* list)
{
	struct pluginDevice *	ad = (struct pluginDevice*)s;
	StonithNamesToGet	namestoget [] =
	{	{ST_TTYDEV,	NULL}
	,	{ST_HOSTLIST,	NULL}
	,	{NULL,		NULL}
	};
	int			rc;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}
	ERRIFWRONGDEV(s, S_OOPS);

	if ((rc=OurImports->GetAllValues(namestoget, list)) != S_OK) {
		return rc;
	}

	ad->hostlist =	OurImports->StringToHostList(namestoget[1].s_value);
	if (ad->hostlist == NULL) {
		LOG(PIL_CRIT,"StringToHostList() failed");
		return S_OOPS;
	}
	for (ad->hostcount = 0; ad->hostlist[ad->hostcount]
	;	ad->hostcount++) {
		/* Just count */
	}
	if (access(namestoget[0].s_value, R_OK|W_OK|F_OK) < 0) {
		LOG(PIL_CRIT,"Cannot access tty [%s]"
		,	namestoget[0].s_value);
		return S_BADCONFIG;
	}
	ad->upsdev = namestoget[0].s_value;
	return ad->hostcount ? S_OK : S_BADCONFIG;
}

/*
 * return the status for this device 
 */

static int
apcsmart_status(StonithPlugin * s)
{
	struct pluginDevice *ad = (struct pluginDevice *) s;
	char resp[MAX_STRING];
	int rc;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	ERRIFNOTCONFIGED(s,S_OOPS);


	/* get status */
	if (((rc = APC_init( ad ) == S_OK)
	&&	((rc = APC_send_cmd(ad->upsfd, CMD_GET_STATUS)) == S_OK)
	&&	((rc = APC_recv_rsp(ad->upsfd, resp)) == S_OK))) {
		return (S_OK);		/* everything ok. */
	}
	if (Debug) {
		LOG(PIL_DEBUG, "%s: failed.", __FUNCTION__);
	}
	return (rc);
}


/*
 * return the list of hosts configured for this device 
 */

static char **
apcsmart_hostlist(StonithPlugin * s)
{
	struct pluginDevice *ad = (struct pluginDevice *) s;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}
	ERRIFNOTCONFIGED(s,NULL);

	return OurImports->CopyHostList((const char **)ad->hostlist);
}

static gboolean
apcsmart_RegisterBitsSet(struct pluginDevice * ad, int nreg, unsigned bits
,	gboolean* waserr)
{
	const char*	reqregs[4] = {"?", "~", "'", "8"};
	unsigned	regval;
	char		resp[MAX_STRING];

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}


	if (APC_enter_smartmode(ad->upsfd) != S_OK
	||	APC_send_cmd(ad->upsfd, reqregs[nreg]) != S_OK
	||	APC_recv_rsp(ad->upsfd, resp) != S_OK
	||	(sscanf(resp, "%02x", &regval) != 1)) {
		if (waserr){
			*waserr = TRUE;
		}
		return FALSE;
	}
	if (waserr){
		*waserr = FALSE;
	}
	return ((regval & bits) == bits);
}

#define	apcsmart_IsPoweredOff(ad, err) apcsmart_RegisterBitsSet(ad,1,0x40,err)
#define	apcsmart_ResetHappening(ad,err) apcsmart_RegisterBitsSet(ad,3,0x08,err)


static int
apcsmart_ReqOnOff(struct pluginDevice * ad, int request)
{
	const char *	cmdstr;
	int		rc;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}
	cmdstr = (request == ST_POWEROFF ? CMD_OFF : CMD_ON);
	/* enter smartmode, send on/off command */
	if ((rc =APC_enter_smartmode(ad->upsfd)) != S_OK
	||	(rc = APC_send_cmd(ad->upsfd, cmdstr)) != S_OK) {
		return rc;
	}
	sleep(2);
	if ((rc = APC_send_cmd(ad->upsfd, cmdstr)) == S_OK) {
		gboolean ison;
		gboolean waserr;
		sleep(1);
		ison = !apcsmart_IsPoweredOff(ad, &waserr);
		if (waserr) {
			return S_RESETFAIL;
		}
		if (request == ST_POWEROFF) {
			return ison ?  S_RESETFAIL : S_OK;
		}else{
			return ison ?  S_OK : S_RESETFAIL;
		}
	}
	return rc;
}

/*
 * reset the host 
 */

static int
apcsmart_ReqGenericReset(struct pluginDevice *ad)
{
	char		resp[MAX_STRING];
	int		rc = S_RESETFAIL;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}
	/* enter smartmode, send reset command */
	if (((rc = APC_init(ad)) == S_OK)
		&& ((rc = APC_send_cmd(ad->upsfd, CMD_RESET)) == S_OK)
		&& ((rc = APC_recv_rsp(ad->upsfd, resp)) == S_OK)
		&& (	strcmp(resp, RSP_RESET)  == 0
		||	strcmp(resp, RSP_RESET2) == 0)) {
		int	maxdelay = atoi(SHUTDOWN_DELAY)+5;
		int	j;

		for (j=0; j < maxdelay; ++j) {
			gboolean	err;
			if (apcsmart_ResetHappening(ad, &err)) {
				return err ? S_RESETFAIL : S_OK;
			}
			sleep(1);
		}
		return S_RESETFAIL;

	}else{
		LOG(PIL_DEBUG, "APC: rc = %d resp[%s]"
		,	rc, resp);

		if (rc == S_OK && strcmp(resp, RSP_NA) == 0){
			gboolean iserr;
			/* This means it's currently powered off */
			/* or busy on a previous command... */
			if (apcsmart_IsPoweredOff(ad, &iserr)) {
				if (iserr) {
					return S_RESETFAIL;
				}
				return apcsmart_ReqOnOff(ad, ST_POWERON);
			}
		}
	}
	strcpy(resp, "?");

	/* reset failed */

	return S_RESETFAIL;
}

static int
apcsmart_req_reset(StonithPlugin * s, int request, const char *host)
{
	char **			hl;
	int			b_found=FALSE;
	struct pluginDevice *	ad = (struct pluginDevice *) s;
	int			rc;

	ERRIFNOTCONFIGED(s, S_OOPS);

	if (host == NULL) {
		LOG(PIL_CRIT, "%s: invalid hostname argument.", __FUNCTION__);
		return (S_INVAL);
	}
    

	/* look through the hostlist */
	hl = ad->hostlist;

	while (*hl && !b_found ) {
		if( strcmp( *hl, host ) == 0 ) {
			b_found = TRUE;
			break;
		}else{
        		++hl;
		}
	}

    	/* host not found in hostlist */
	if( !b_found ) {
		LOG(PIL_CRIT, "%s: host '%s' not in hostlist."
		,	__FUNCTION__, host);
		return S_BADHOST;
	}
	if ((rc = APC_init(ad)) != S_OK) {
		return rc;
	}

	if (request == ST_POWERON || request == ST_POWEROFF) {
		return apcsmart_ReqOnOff(ad, request);
	}
	return apcsmart_ReqGenericReset(ad);
}


/*
 * get info about the stonith device 
 */

static const char *
apcsmart_get_info(StonithPlugin * s, int reqtype)
{
	struct pluginDevice *ad = (struct pluginDevice *) s;
	const char *ret;

	if (Debug) {
    		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}

	ERRIFWRONGDEV(s,NULL);
   

	switch (reqtype) {
    		case ST_DEVICEID:
		ret = ad->pluginid;
		break;

		case ST_DEVICEDESCR:
		ret = "APC Smart UPS"
			" (via serial port - NOT USB!). "
			" Works with higher-end APC UPSes, like"
			" Back-UPS Pro, Smart-UPS, Matrix-UPS, etc. "
			" (Smart-UPS may have to be >= Smart-UPS 700?)\n"
		" See http://us1.networkupstools.org/protocols/apcsmart.html"
			" for protocol compatibility details.";
			break;

		case ST_DEVICEURL:
			ret = "http://www.apc.com/";
			break;

		default:
			ret = NULL;
			break;
	}
	return (ret);
}

/*
 * APC Stonith destructor... 
 */

static void
apcsmart_destroy(StonithPlugin * s)
{
    struct pluginDevice *ad = (struct pluginDevice *) s;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
    	}
	VOIDERRIFWRONGDEV(s);

	APC_deinit( ad->upsfd );

	ad->pluginid = NOTpluginID;

	if (ad->hostlist) {
		stonith_free_hostlist(ad->hostlist);
		ad->hostlist = NULL;
	}

	ad->hostcount = -1;
	ad->upsfd = -1;

	FREE(ad);

}

/*
 * Create a new APC Stonith device.  Too bad this function can't be
 * static 
 */

static StonithPlugin *
apcsmart_new(const char *subplugin)
{
    struct pluginDevice *ad = MALLOCT(struct pluginDevice);

	if (Debug) {
		LOG(PIL_DEBUG, "%s: called.", __FUNCTION__);
	}
	if (ad == NULL) {
		LOG(PIL_CRIT, "%s: out of memory.", __FUNCTION__);
		return (NULL);
	}

	memset(ad, 0, sizeof(*ad));

	ad->pluginid = pluginid;
	ad->hostlist = NULL;
	ad->hostcount = -1;
	ad->upsfd = -1;
	ad->sp.s_ops = &apcsmartOps;

	if (Debug) {
		LOG(PIL_DEBUG, "%s: returning successfully.", __FUNCTION__);
	}
	return &(ad->sp);
}
