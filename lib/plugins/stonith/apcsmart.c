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
 * UPS code is taken from:
 *   'Network UPS Tools' by Russell Kroll <rkroll@exploits.org>
 *   homepage: http://www.exploits.org/nut/
 */

#include <portability.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <libintl.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>

#include <stonith/stonith.h>

/*
 * APCSmart (tested with 2 old 900XLI)
 *
 * no configfile needed. every host performing resets using
 * this module must be connected to a ups via /dev/ups,
 * /dev/ups is a symlink to the proper tty device.
 *
 * the reset is a combined reset (cmd: S@000).
 * that means if the ups is online, a scheduled reset (20s delay)
 * will be triggered. after the reset the ups will immediately
 * return  online. if the ups is on-battery, the reset will also be
 * a scheduled reset but the ups will remain offline until the power
 * is back. 
 */

#define	DEVICE	                "APCSmart-Stonith"

#define CFG_FILE		"/etc/ha.d/apcsmart.cfg"

#define MAX_DEVICES		1

#define SERIAL_TIMEOUT		3	/* timeout in sec */
#define SEND_DELAY		50000	/* in µs */
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
#define CMD_RESET               "S@000"
#define RSP_RESET		"*"
#define CMD_SHUTDOWN_DELAY	"p"
#define CMD_WAKEUP_DELAY	"r"

#define CR			13

struct APCDevice {
    const char *APCid;		/* of object				*/
    char **hostlist;		/* served by the device (only 1)	*/
    int hostcount;		/* of hosts (1)				*/
    char *upsdev;		/*					*/
    int upsfd;			/* for serial port			*/
};

/* saving old settings */
static struct termios old_tio;
static char old_shutdown_delay[MAX_STRING];
static char old_wakeup_delay[MAX_STRING];

static int f_serialtimeout;	/* flag for timeout */
static const char *APCid = DEVICE;
static const char *NOTapcID = "destroyed (APCSmart)";

#define	ISAPCDEV(i) (((i)!= NULL && (i)->pinfo != NULL)	&& \
                    ((struct APCDevice *)(i->pinfo))->APCid == APCid)

#define ISCONFIGED(i) (((struct APCDevice *)(i->pinfo))->upsdev != NULL)

#define _(text) dgettext(ST_TEXTDOMAIN, text)




/*
 * stonith prototypes 
 */

#define PIL_PLUGINTYPE          STONITH_TYPE
#define PIL_PLUGINTYPE_S        STONITH_TYPE_S
#define PIL_PLUGIN              apcsmart
#define PIL_PLUGIN_S            "apcsmart"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

/*
 * apcsmartclose is called as part of unloading the apcsmart STONITH plugin.
 * If there was any global data allocated, or file descriptors opened, etc.
 * which is associated with the plugin, and not a single interface
 * in particular, here's our chance to clean it up.
 */

static void
apcsmartclosepi(PILPlugin*pi)
{
}


/*
 * apcsmartcloseintf called as part of shutting down the apcsmart STONITH
 * interface.  If there was any global data allocated, or file descriptors
 * opened, etc.  which is associated with the apcsmart implementation,
 * here's our chance to clean it up.
 */
static PIL_rc
apcsmartcloseintf(PILInterface* pi, void* pd)
{
	return PIL_OK;
}

static void *		apcsmart_new(void);
static void		apcsmart_destroy(Stonith *);
static int		apcsmart_set_config_file(Stonith *, const char * cfgname);
static int		apcsmart_set_config_info(Stonith *, const char * info);
static const char *	apcsmart_getinfo(Stonith * s, int InfoType);
static int		apcsmart_status(Stonith * );
static int		apcsmart_reset_req(Stonith * s, int request, const char * host);
static char **		apcsmart_hostlist(Stonith  *);
static void		apcsmart_free_hostlist(char **);

static struct stonith_ops apcsmartOps ={
	apcsmart_new,		/* Create new STONITH object	*/
	apcsmart_destroy,		/* Destroy STONITH object	*/
	apcsmart_set_config_file,	/* set configuration from file	*/
	apcsmart_set_config_info,	/* Get configuration from file	*/
	apcsmart_getinfo,		/* Return STONITH info string	*/
	apcsmart_status,		/* Return STONITH device status	*/
	apcsmart_reset_req,		/* Request a reset */
	apcsmart_hostlist,		/* Return list of supported hosts */
	apcsmart_free_hostlist		/* free above list */
};

PIL_PLUGIN_BOILERPLATE("1.0", Debug, apcsmartclosepi);
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
#undef MALLOCT
#define MALLOCT(t) ((t *)(MALLOC(sizeof(t))))

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
	,	apcsmartcloseintf		/*close */
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
int APC_parse_config_info(struct APCDevice *ad, const char *info );
int APC_init( struct APCDevice *ad );
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
    struct sigaction sa;
    sigset_t sigmask;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    sa.sa_handler = (void (*)(int))SIG_DFL;
    sigemptyset(&sigmask);
    sa.sa_mask = sigmask;
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, NULL);

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: serial port timed out.", __FUNCTION__);
#endif

    f_serialtimeout = TRUE;

    return;
}

/*
 * Open serial port and set it to b2400 
 */

int
APC_open_serialport(const char *port, speed_t speed)
{
    struct sigaction sa;
    sigset_t sigmask;
    struct termios tio;
    int fd;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    sa.sa_handler = APC_sh_serial_timeout;
    sigemptyset(&sigmask);
    sa.sa_mask = sigmask;
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, NULL);

    alarm(SERIAL_TIMEOUT);

    f_serialtimeout = FALSE;

    fd = open(port, O_RDWR | O_NOCTTY | O_NONBLOCK | O_EXCL);

    alarm(0);
    IGNORESIG(SIGALRM);

    if (fd < 0) {

#ifdef APC_DEBUG
	syslog(LOG_DEBUG, "%s: 1st open failed.", __FUNCTION__);
#endif
	return (f_serialtimeout ? S_TIMEOUT : S_OOPS);
    }

    if (file_lock(fd) != 0) {

#ifdef APC_DEBUG
	syslog(LOG_DEBUG, "%s: 1st lock failed.", __FUNCTION__);
#endif
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

    signal(SIGALRM, APC_sh_serial_timeout);
    alarm(SERIAL_TIMEOUT);

    fd = open(port, O_RDWR | O_NOCTTY | O_EXCL);

    alarm(0);
    IGNORESIG(SIGALRM);

    if (fd < 0) {

#ifdef APC_DEBUG
	syslog(LOG_DEBUG, "%s: 2nd open failed.", __FUNCTION__);
#endif
	return (f_serialtimeout ? S_TIMEOUT : S_OOPS);
    }

    if (file_lock(fd) != 0) {

#ifdef APC_DEBUG
	syslog(LOG_DEBUG, "%s: 2nd lock failed.", __FUNCTION__);
#endif

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

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

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

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    for (i = strlen(cmd); i > 0; i--) {
	tcflush(upsfd, TCIFLUSH);

	if (write(upsfd, cmd++, 1) != 1)
	    return (S_ACCESS);

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
    struct sigaction sa;
    sigset_t sigmask;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    *p = '\0';

    sa.sa_handler = APC_sh_serial_timeout;
    sigemptyset(&sigmask);
    sa.sa_mask = sigmask;
    sa.sa_flags = 0;
    sigaction(SIGALRM, &sa, NULL);

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
		IGNORESIG(SIGALRM);

		*p = '\0';
		return (S_OK);
	    }

	    if (inp != CR) {
		*p++ = inp;
		num++;
	    }

	} else {
	    alarm(0);
	    IGNORESIG(SIGALRM);
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

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    strcpy( resp, RSP_SMART_MODE);

    if (((rc = APC_send_cmd(upsfd, CMD_SMART_MODE)) == S_OK) &&
	((rc = APC_recv_rsp(upsfd, resp)) == S_OK) &&
	(strcmp(RSP_SMART_MODE, resp) == 0))
	return (S_OK);

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

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (((rc = APC_enter_smartmode(upsfd)) != S_OK) ||
	((rc = APC_send_cmd(upsfd, cmd)) != S_OK) ||
	((rc = APC_recv_rsp(upsfd, orig)) != S_OK))
	return (rc);

    if (strcmp(orig, newval) == 0)
	return (S_OK);		/* already set */

    *resp = '\0';

    while (strcmp(resp, orig) != 0) {
	if (((rc = APC_send_cmd(upsfd, SWITCH_TO_NEXT_VAL)) != S_OK) ||
	    ((rc = APC_recv_rsp(upsfd, resp)) != S_OK))
	    return (rc);

	if (((rc = APC_enter_smartmode(upsfd)) != S_OK) ||
	    ((rc = APC_send_cmd(upsfd, cmd)) != S_OK) ||
	    ((rc = APC_recv_rsp(upsfd, resp)) != S_OK))
	    return (rc);

	if (strcmp(resp, newval) == 0) {
	    strcpy(newval, orig);	/* return the old value */
	    return (S_OK);		/* got it */
	}
    }

    syslog(LOG_ERR, "%s: variable '%s' wrapped!", __FUNCTION__, cmd);

    return (S_OOPS);
}

/*
 * Initialize the ups
 */

int
APC_init( struct APCDevice *ad )
{
  int upsfd;
  char value[MAX_STRING];

#ifdef APC_DEBUG
  syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

  /* if ad->upsfd == -1 -> dev configured! */
  if(ad->upsfd != -1 ) return( S_OK );

  /* open serial port and store the fd in ad->upsfd */
  if ((upsfd = APC_open_serialport(ad->upsdev, B2400)) == -1)
    return (-1);

  /* switch into smart mode */
  if(APC_enter_smartmode(upsfd) != S_OK)
    return( -1 );

  /* get the old settings and store them */
  strcpy(value, SHUTDOWN_DELAY);
  if (APC_set_ups_var(upsfd, CMD_SHUTDOWN_DELAY, value) != S_OK)
    return (-1);  

  strcpy(old_shutdown_delay, value);

  strcpy(value, WAKEUP_DELAY);
  if (APC_set_ups_var(upsfd, CMD_WAKEUP_DELAY, value) != S_OK)
    return (-1);

  strcpy(old_wakeup_delay, value);

  ad->upsfd = upsfd;

  return( S_OK );
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

/*
 * Parse config
 */

int
APC_parse_config_info(struct APCDevice *ad, const char *info )
{
  char hostname[MAX_STRING];
  static char devicename[MAX_STRING];
  char **hl;

#ifdef APC_DEBUG
  syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

  if (ad->hostcount >= 0) {
    return(S_OOPS);
  }

  if ((hl = (char **)MALLOC((MAX_DEVICES+1)*sizeof(char*))) == NULL) {
    syslog(LOG_ERR, "%s: out of memory!", __FUNCTION__);
    return S_OOPS;
  }

  memset(hl, 0, (MAX_DEVICES+1)*sizeof(char*));

  if (sscanf(info, "%s %s", devicename, hostname) == 2) {

    if(( hl[0] = MALLOC(((strlen(hostname)+1)*sizeof(char)))) == NULL ) {
      apcsmart_free_hostlist(hl);
      hl = NULL;
      return( S_OOPS );
    }
    strcpy( hl[0], hostname );

    ad->hostlist = hl;
    ad->hostcount = MAX_DEVICES+1;

    ad->upsdev = devicename;

    return(S_OK);
  }

  return(S_BADCONFIG);
}                                

/*
 * return the status for this device 
 */

int
apcsmart_status(Stonith * s)
{
    struct APCDevice *ad;
    char resp[MAX_STRING];
    int rc;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (!ISAPCDEV(s)) {
	syslog(LOG_ERR, "%s: invalid argument.", __FUNCTION__);
	return (S_INVAL);
    }

    if( !ISCONFIGED(s)) {
        syslog(LOG_ERR, "%s: device is UNCONFIGURED!", __FUNCTION__ );
        return( S_OOPS );
    }

    ad = (struct APCDevice *) s->pinfo;

    rc = APC_init(ad);

    /* get status */
    if (((rc = APC_init( ad ) == S_OK) &&
	((rc = APC_send_cmd(ad->upsfd, CMD_GET_STATUS)) == S_OK) &&
	((rc = APC_recv_rsp(ad->upsfd, resp)) == S_OK)))
	return (S_OK);		/* everything ok. */

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: failed.", __FUNCTION__);
#endif

    return (rc);
}


/*
 * return the list of hosts configured for this device 
 */

char **
apcsmart_hostlist(Stonith * s)
{
    int numhosts;
    char **hl;
    struct APCDevice *ad;
    int j;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (!ISAPCDEV(s)) {
	syslog(LOG_ERR, "%s: invalid argument.", __FUNCTION__);
	return (NULL);
    }

    if( !ISCONFIGED(s)) {
        syslog(LOG_ERR, "%s: device is UNCONFIGURED!", __FUNCTION__ );
        return( NULL );
    }

    ad = (struct APCDevice *) s->pinfo;

    numhosts = ad->hostcount;

    if (( hl = (char **)MALLOC(numhosts * sizeof(char *))) == NULL) {
	syslog(LOG_ERR, "%s: out of memory.", __FUNCTION__);
	return (hl);
    }

    memset(hl, 0, numhosts * sizeof(char *));

    for (j = 0; j < numhosts -1; ++j) {
    
	if ((hl[j] = MALLOC(strlen(ad->hostlist[j]) + 1)) == NULL) {
	    apcsmart_free_hostlist(hl);
	    hl = NULL;
	    return (hl);
	}

	strcpy(hl[j], ad->hostlist[j]);
    }
    return (hl);
}

/*
 * free the hostlist 
 */

void
apcsmart_free_hostlist(char **hlist)
{
    char **hl = hlist;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (hl == NULL)
	return;

    while (*hl) {
	FREE(*hl);
	*hl = NULL;
	++hl;
    }

    FREE(hlist);
    hlist = NULL;
}

/*
 * reset the host 
 */

int
apcsmart_reset_req(Stonith * s, int request, const char *host)
{
    struct APCDevice *ad;
    char resp[MAX_STRING];
    int rc;
    int i;
    char **hl;
    int b_found=FALSE;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (!ISAPCDEV(s)) {
	syslog(LOG_ERR, "%s: invalid argument.", __FUNCTION__);
	return (S_INVAL);
    }

    if( !ISCONFIGED(s)) {
        syslog(LOG_ERR, "%s: device is UNCONFIGURED!", __FUNCTION__ );
        return( S_OOPS );
    }

    ad = (struct APCDevice *) s->pinfo;

    /* look through the hostlist */
    hl = ad->hostlist;

    while (*hl && !b_found ) {
      if( strcmp( *hl, host ) == 0 ) {
        b_found = TRUE;
        break;
      } else
        ++hl;
    }

    /* host not found in hostlist */
    if( !b_found ) {
      syslog(LOG_ERR, "%s: host '%s' not in hostlist.", __FUNCTION__, host);

      return( S_BADHOST );
    }

    /* enter smartmode and get status */
    if (((rc = APC_init(ad)) == S_OK) &&
	((rc = APC_send_cmd(ad->upsfd, CMD_RESET)) == S_OK) &&
	((rc = APC_recv_rsp(ad->upsfd, resp)) == S_OK) &&
	(strcmp(resp, RSP_RESET) == 0)) {

	/* ok, reset is initiated. ups don't accept any cmds until */
	/* reboot -> reboot complete if status cmd accepted */
	/* we wait max. 30 sec after shutdown */

	sleep(atoi(SHUTDOWN_DELAY));

	/* ups should be dead now -> wait for rebirth */

	for (i = 0; i < 10; i++) {
	    if (((rc = APC_send_cmd(ad->upsfd, CMD_GET_STATUS)) == S_OK) &&
	        ((rc = APC_recv_rsp(ad->upsfd, resp)) == S_OK))
		return (S_OK);
	    sleep(1);
	}
    }

    /* reset failed */
    syslog(LOG_ERR, "%s: resetting host '%s' failed.", __FUNCTION__, host);

    return (S_RESETFAIL);
}

/*
 * parse the information in the given configuration file,
 * and stash it away... 
 */

int
apcsmart_set_config_file(Stonith * s, const char *configname)
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

    if ((cfgfile = fopen(configname, "r")) == NULL)  {
      syslog(LOG_ERR, "Cannot open %s", configname);
      return(S_BADCONFIG);
    }

    while (fgets(confline, sizeof(confline), cfgfile) != NULL) {
      if (*confline == '#' || *confline == '\n' || *confline == EOS)
        continue;
      return(APC_parse_config_info(ad, confline));
    }
    return(S_BADCONFIG);
}

/*
 * Parse the config information in the given string, and stash it away... 
 */

int
apcsmart_set_config_info(Stonith * s, const char *info)
{
    struct APCDevice *ad;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: info: '%s'.", __FUNCTION__, info );
#endif

    if (!ISAPCDEV(s)) {
	syslog(LOG_ERR, "%s: invalid argument.", __FUNCTION__);
	return (S_INVAL);
    }

    ad = (struct APCDevice *) s->pinfo;
        
    return(APC_parse_config_info(ad, info));
}

/*
 * get info about the stonith device 
 */

const char *
apcsmart_getinfo(Stonith * s, int reqtype)
{
    struct APCDevice *ad;
    const char *ret;

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (!ISAPCDEV(s)) {
	syslog(LOG_ERR, "%s: invalid argument.", __FUNCTION__);
	return NULL;
    }
   
    ad = (struct APCDevice *) s->pinfo;

    switch (reqtype) {
    	case ST_DEVICEID:
		ret = ad->APCid;
		break;

    	case ST_CONF_INFO_SYNTAX:
        	ret = _("hostname devicename\n"
                	"The hostname and devicename are white-space delimited.");
        	break;

    	case ST_CONF_FILE_SYNTAX:
        	ret = _("hostname devicename\n"
                	"The hostname and devicename are white-space delimited.\n"
                	"All three items must be on one line.\n"
                	"Blank lines and lines beginning with # are ignored.");
		break;

	case ST_DEVICEDESCR:
		ret = _("APC Smart UPS (via serial port)");
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

void
apcsmart_destroy(Stonith * s)
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

    APC_deinit( ad->upsfd );

    ad->APCid = NOTapcID;

    if (ad->hostlist) {
	apcsmart_free_hostlist(ad->hostlist);
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

void *
apcsmart_new(void)
{
    struct APCDevice *ad = MALLOCT(struct APCDevice);

#ifdef APC_DEBUG
    syslog(LOG_DEBUG, "%s: called.", __FUNCTION__);
#endif

    if (ad == NULL) {
	syslog(LOG_ERR, "%s: out of memory.", __FUNCTION__);
	return (NULL);
    }

    memset(ad, 0, sizeof(*ad));

    ad->APCid = APCid;
    ad->hostlist = NULL;
    ad->hostcount = -1;
    ad->upsfd = -1;

    return ((void *) ad);
}
