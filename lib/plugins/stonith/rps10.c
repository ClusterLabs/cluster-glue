/* $Id: rps10.c,v 1.14 2004/10/05 14:26:17 lars Exp $ */
/*
 *	Stonith module for WTI Remote Power Controllers (RPS-10M device)
 *
 *      Original code from baytech.c by
 *	Copyright (c) 2000 Alan Robertson <alanr@unix.sh>
 *
 *      Modifications for WTI RPS10
 *	Copyright (c) 2000 Computer Generation Incorporated
 *               Eric Z. Ayers <eric.ayers@compgen.com>
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

#define	DEVICE	"WTI RPS10 Power Switch"
#include "stonith_plugin_common.h"

#include <termios.h>
#define PIL_PLUGIN              rps10
#define PIL_PLUGIN_S            "rps10"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#include <pils/plugin.h>

static void *		rps10_new(void);
static void		rps10_destroy(Stonith *);
static int		rps10_set_config_file(Stonith *, const char * cfgname);
static int		rps10_set_config_info(Stonith *, const char * info);
static const char *	rps10_getinfo(Stonith * s, int InfoType);
static int		rps10_status(Stonith * );
static int		rps10_reset_req(Stonith * s, int request, const char * host);
static char **		rps10_hostlist(Stonith  *);

static struct stonith_ops rps10Ops ={
	rps10_new,		/* Create new STONITH object	*/
	rps10_destroy,		/* Destroy STONITH object	*/
	rps10_set_config_file,	/* set configuration from file	*/
	rps10_set_config_info,	/* Get configuration from file	*/
	rps10_getinfo,		/* Return STONITH info string	*/
	rps10_status,		/* Return STONITH device status	*/
	rps10_reset_req,		/* Request a reset */
	rps10_hostlist,		/* Return list of supported hosts */
};

PIL_PLUGIN_BOILERPLATE("1.0", Debug, NULL);
static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static StonithImports*		OurImports;
static void*			interfprivate;

#include "stonith_signal.h"
#define  DOESNT_USE_STONITHKILLCOMM
#define  DOESNT_USE_STONITHSCANLINE
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
	,	&rps10Ops
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*
 *	This was written for a Western Telematic Inc. (WTI) 
 *      Remote Power Switch - RPS-10M. 
 *
 *      It has a DB9 serial port, a Rotary Address Switch,
 *      and a pair of RJ-11 jacks for linking multiple switches 
 *      together.  The 'M' unit is a master unit which can control 
 *      up to 9 additional slave units. (the master unit also has an
 *      A/C outlet, so you can control up to 10 devices)
 *
 *      There are a set of dip switches. The default shipping configuration
 *      is with all dip switches down. I highly recommend that you flip
 *      switch #3 up, so that when the device is plugged in, the power 
 *      to the unit comes on.
 *
 *      The serial interface is fixed at 9600 BPS (well, you *CAN* 
 *        select 2400 BPS with a dip switch, but why?) 8-N-1
 *
 *      The ASCII command string is:
 *
 *      ^B^X^X^B^X^Xac^M
 *      
 *      ^B^X^X^B^X^X  "fixed password" prefix (CTRL-B CTRL-X ... )
 *      ^M            the carriage return character
 *     
 *      a = 0-9  Indicates the address of the module to receive the command
 *      a = *    Sends the command to all modules
 *
 *      c = 0    Switch the AC outlet OFF
 *               Returns:
 *                         Plug 0 Off
 *                         Complete
 *
 *      c = 1    Switch the AC outlet ON
 *               Returns:
 *                        Plug 0 On
 *                        Complete
 *
 *      c = T    Toggle AC OFF (delay) then back ON
 *               Returns:
 *                         Plug 0 Off
 *                         Plug 0 On
 *                         Complete
 *
 *      c = ?    Read and display status of the selected module
 *               Returns:
 *                        Plug 0 On   # or Plug 0 Off
 *                        Complete
 *
 *   e.g. ^B^X^X^B^X^X0T^M toggles the power on plug 0 OFF and then ON
 * 
 *   21 September 2000
 *   Eric Z. Ayers
 *   Computer Generation, Inc.
 */

struct cntrlr_str {
  char outlet_id;		/* value 0-9, '*' */
  char * node;          /* name of the node attached to this outlet */
};

struct pluginDevice {
  const char *	pluginid;

  char *	idinfo;  /* ??? What's this for Alan ??? */
  char *	unitid;  /* ??? What's this for Alan ??? */

  int		fd;      /* FD open to the serial port */

  int		config;  /* 0 if not configured, 
                            1 if configured with rps10_set_config_info() 
                                   or rps10_set_config_file()
                          */
  char *	device;  /* Serial device name to use to communicate 
                            to this RPS10
			  */

#define WTI_NUM_CONTROLLERS	10
  struct cntrlr_str 
                controllers[WTI_NUM_CONTROLLERS];
  		/* one master switch can address 10 controllers */

  /* Number of actually configured units */
  int	unit_count;

};

/* This string is used to identify this type of object in the config file */
static const char * pluginid = "WTI_RPS10";
static const char * NOTwtiid = "OBJECT DESTROYED: (WTI RPS-10)";

/* WTIpassword - The fixed string ^B^X^X^B^X^X */
static const char WTIpassword[7] = {2,24,24,2,24,24,0}; 

#ifndef DEBUG
#define DEBUG 0
#endif
static int gbl_debug = DEBUG;

/*
 *	Different expect strings that we get from the WTI_RPS10
 *	Remote Power Controllers...
 */

static struct Etoken WTItokReady[] =	{ {"RPS-10 Ready", 0, 0}, {NULL,0,0}};
static struct Etoken WTItokComplete[] =	{ {"Complete", 0, 0} ,{NULL,0,0}};
static struct Etoken WTItokPlug[] =	{ {"Plug", 0, 0}, {NULL,0,0}};
static struct Etoken WTItokOutlet[] =	{ {"0", 0, 0}, 
					  {"1", 0, 0}, 
					  {"2", 0, 0}, 
					  {"3", 0, 0}, 
					  {"4", 0, 0}, 
					  {"5", 0, 0}, 
					  {"6", 0, 0}, 
					  {"7", 0, 0}, 
					  {"8", 0, 0}, 
					  {"9", 0, 0}, 
					  {NULL,0,0}};

static struct Etoken WTItokOff[] =	{ {"Off", 0, 0}, {NULL,0,0}};

/* 
 * Tokens currently not used because they don't show up on all RPS10 units:
 *
 */
static struct Etoken WTItokOn[] =	{ {"On", 0, 0}, {NULL,0,0}};

/* Accept either a CR/NL or an NL/CR */
static struct Etoken WTItokCRNL[] =	{ {"\n\r",0,0},{"\r\n",0,0},{NULL,0,0}};

static int	RPSConnect(struct pluginDevice * ctx);
static int	RPSDisconnect(struct pluginDevice * ctx);

static int	RPSReset(struct pluginDevice*, char unit_id, const char * rebootid);
#if defined(ST_POWERON) 
static int	RPSOn(struct pluginDevice*, char unit_id, const char * rebootid);
#endif
#if defined(ST_POWEROFF) 
static int	RPSOff(struct pluginDevice*, char unit_id, const char * rebootid);
#endif
static signed char RPSNametoOutlet ( struct pluginDevice * ctx, const char * host );

static int RPS_parse_config_info(struct pluginDevice* ctx, const char * info);

#define        SENDCMD(outlet, cmd, timeout)              { 			\
		int return_val = RPSSendCommand(ctx, outlet, cmd, timeout);	\
		if (return_val != S_OK)  return return_val;			\
		}

/*
 * RPSSendCommand - send a command to the specified outlet
 */
static int
RPSSendCommand (struct pluginDevice *ctx, char outlet, char command, int timeout)
{
	char            writebuf[10]; /* all commands are 9 chars long! */
	int		return_val;  /* system call result */
	fd_set          rfds, wfds, xfds;
				     /*  list of FDs for select() */
	struct timeval 	tv;	     /*  */

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&xfds);

	snprintf (writebuf, sizeof(writebuf), "%s%c%c\r",
		  WTIpassword, outlet, command);

	if (gbl_debug) printf ("Sending %s\n", writebuf);

	/* Make sure the serial port won't block on us. use select()  */
	FD_SET(ctx->fd, &wfds);
	FD_SET(ctx->fd, &xfds);
	
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	
	return_val = select(ctx->fd+1, NULL, &wfds,&xfds, &tv);
	if (return_val == 0) {
		/* timeout waiting on serial port */
		LOG(PIL_CRIT, "%s: Timeout writing to %s",
			pluginid, ctx->device);
		return S_TIMEOUT;
	} else if ((return_val == -1) || FD_ISSET(ctx->fd, &xfds)) {
		/* an error occured */
		LOG(PIL_CRIT, "%s: Error before writing to %s: %s",
			pluginid, ctx->device, strerror(errno));		
		return S_OOPS;
	}

	/* send the command */
	if (write(ctx->fd, writebuf, strlen(writebuf)) != 
			(int)strlen(writebuf)) {
		LOG(PIL_CRIT, "%s: Error writing to  %s : %s",
			pluginid, ctx->device, strerror(errno));
		return S_OOPS;
	}

	/* suceeded! */
	return S_OK;

}  /* end RPSSendCommand() */

/* 
 * RPSReset - Reset (power-cycle) the given outlet id 
 */
static int
RPSReset(struct pluginDevice* ctx, char unit_id, const char * rebootid)
{

	if (gbl_debug) printf ("Calling RPSReset (%s)\n", pluginid);
	
	if (ctx->fd < 0) {
		LOG(PIL_CRIT, "%s: device %s is not open!", pluginid, 
		       ctx->device);
		return S_OOPS;
	}

	/* send the "toggle power" command */
	SENDCMD(unit_id, 'T', 10);

	/* Expect "Plug 0 Off" */
	/* Note: If asked to control "*", the RPS10 will report all units it
	 * separately; however, we don't know how many, so we can only wait
	 * for the first unit to report something and then wait until the
	 * "Complete" */
	EXPECT(ctx->fd, WTItokPlug, 5);
	if (gbl_debug)	printf ("Got Plug\n");
	EXPECT(ctx->fd, WTItokOutlet, 2);
	if (gbl_debug) printf ("Got Outlet #\n");
	EXPECT(ctx->fd, WTItokOff, 2);
	if (gbl_debug) printf ("Got Off\n");	
	EXPECT(ctx->fd, WTItokCRNL, 2);
	LOG(PIL_INFO, "%s: %s",_("Host is being rebooted"), rebootid);
	
	/* Expect "Complete" */
	EXPECT(ctx->fd, WTItokComplete, 14);
	if (gbl_debug) printf ("Got Complete\n");
	EXPECT(ctx->fd, WTItokCRNL, 2);
	if (gbl_debug) printf ("Got NL\n");
	
	return(S_OK);

} /* end RPSReset() */


#if defined(ST_POWERON) 
/* 
 * RPSOn - Turn OFF the given outlet id 
 */
static int
RPSOn(struct pluginDevice* ctx, char unit_id, const char * host)
{

	if (ctx->fd < 0) {
		LOG(PIL_CRIT, "%s: device %s is not open!", pluginid, 
		       ctx->device);
		return S_OOPS;
	}

	/* send the "On" command */
	SENDCMD(unit_id, '1', 10);

	/* Expect "Plug 0 On" */
	EXPECT(ctx->fd, WTItokPlug, 5);
	EXPECT(ctx->fd, WTItokOutlet, 2);
	EXPECT(ctx->fd, WTItokOn, 2);
	EXPECT(ctx->fd, WTItokCRNL, 2);
	LOG(PIL_INFO, "%s: %s", _("Host is being turned on"), host);
	
	/* Expect "Complete" */
	EXPECT(ctx->fd, WTItokComplete, 5);
	EXPECT(ctx->fd, WTItokCRNL, 2);

	return(S_OK);

} /* end RPSOn() */
#endif


#if defined(ST_POWEROFF) 
/* 
 * RPSOff - Turn Off the given outlet id 
 */
static int
RPSOff(struct pluginDevice* ctx, char unit_id, const char * host)
{

	if (ctx->fd < 0) {
		LOG(PIL_CRIT, "%s: device %s is not open!", pluginid, 
		       ctx->device);
		return S_OOPS;
	}

	/* send the "Off" command */
	SENDCMD(unit_id, '0', 10);

	/* Expect "Plug 0 Off" */
	EXPECT(ctx->fd, WTItokPlug, 5);
	EXPECT(ctx->fd, WTItokOutlet, 2);
	EXPECT(ctx->fd, WTItokOff, 2);
	EXPECT(ctx->fd, WTItokCRNL, 2);
	LOG(PIL_INFO, "%s: %s", _("Host is being turned on."), host);
	
	/* Expect "Complete" */
	EXPECT(ctx->fd, WTItokComplete, 5);
	EXPECT(ctx->fd, WTItokCRNL, 2);

	return(S_OK);

} /* end RPSOff() */
#endif


/*
 * rps10_status - API entry point to probe the status of the stonith device 
 *           (basically just "is it reachable and functional?", not the
 *            status of the individual outlets)
 * 
 * Returns:
 *    S_OOPS - some error occured
 *    S_OK   - if the stonith device is reachable and online.
 */
static int
rps10_status(Stonith  *s)
{
	struct pluginDevice*	ctx;
	
	if (gbl_debug) printf ("Calling rps10_status (%s)\n", pluginid);
	
	ERRIFNOTCONFIGED(s,S_OOPS);

	ctx = (struct pluginDevice*) s->pinfo;
	if (RPSConnect(ctx) != S_OK) {
		return(S_OOPS);
	}

	/* The "connect" really does enough work to see if the 
	   controller is alive...  It verifies that it is returning 
	   RPS-10 Ready 
	*/

	return(RPSDisconnect(ctx));
}

/*
 * rps10_hostlist - API entry point to return the list of hosts 
 *                 for the devices on this WTI_RPS10 unit
 * 
 *               This type of device is configured from the config file,
 *                 so we don't actually have to connect to figure this
 *                 out, just peruse the 'ctx' structure.
 * Returns:
 *     NULL on error
 *     a malloced array, terminated with a NULL,
 *         of null-terminated malloc'ed strings.
 */
static char **
rps10_hostlist(Stonith  *s)
{
	char **		ret = NULL;	/* list to return */
	int 		i;
	int 		j;
	struct pluginDevice*	ctx;

	if (gbl_debug) printf ("Calling rps10_hostlist (%s)\n", pluginid);
	
	ERRIFNOTCONFIGED(s,NULL);

	ctx = (struct pluginDevice*) s->pinfo;

	if (ctx->unit_count >= 1) {
		ret = (char **)MALLOC((ctx->unit_count+1)*sizeof(char*));
		if (ret == NULL) {
			LOG(PIL_CRIT, "out of memory");
			return ret;
		}
		ret[ctx->unit_count]=NULL; /* null terminate the array */
		for (i=0; i < ctx->unit_count; i++) {
			ret[i] = STRDUP(ctx->controllers[i].node);
			if (ret[i] == NULL) {
				for(j=0; j<i; j++) {
					FREE(ret[j]);
				}
				FREE(ret); ret = NULL;
				break;
			}
		} /* end for each possible outlet */
	} /* end if any outlets are configured */
	return(ret);
} /* end si_hostlist() */

/*
 *	Parse the given configuration information, and stash
 *      it away...
 *
 *         The format of <info> for this module is:
 *            <serial device> <remotenode> <outlet> [<remotenode> <outlet>] ...
 *
 *      e.g. A machine named 'nodea' can kill a machine named 'nodeb' through
 *           a device attached to serial port /dev/ttyS0.
 *           A machine named 'nodeb' can kill machines 'nodea' and 'nodec'
 *           through a device attached to serial port /dev/ttyS1 (outlets 0 
 *             and 1 respectively)
 *
 *      <assuming this is the heartbeat configuration syntax:>
 * 
 *      stonith nodea rps10 /dev/ttyS0 nodeb 0 
 *      stonith nodeb rps10 /dev/ttyS0 nodea 0 nodec 1
 *
 *      Another possible configuration is for 2 stonith devices
 *         accessible through 2 different serial ports on nodeb:
 *
 *      stonith nodeb rps10 /dev/ttyS0 nodea 0 
 *      stonith nodeb rps10 /dev/ttyS1 nodec 0
 */

/*
 * 	OOPS!
 *
 * 	Most of the large block of comments above is incorrect as far as this
 * 	module is concerned.  It is somewhat applicable to the heartbeat code,
 * 	but not to this Stonith module.
 *
 * 	The format of parameter string for this module is:
 *            <serial device> <remotenode> <outlet> [<remotenode> <outlet>] ...
 */

static int
RPS_parse_config_info(struct pluginDevice* ctx, const char * info)
{
	char *copy;
	char *token;
	char *outlet, *node;


	if (ctx->config) {
		/* The module is already configured. */
		return(S_OOPS);
	}

	/* strtok() is nice to use to parse a string with 
	   (other than it isn't threadsafe), but it is destructive, so
	   we're going to alloc our own private little copy for the
	   duration of this function.
	*/

	copy = STRDUP(info);
	if (!copy) {
		LOG(PIL_CRIT, "out of memory");
		return S_OOPS;
	}

	/* Grab the serial device */
	token = strtok (copy, " \t");

	if (!token) {
		LOG(PIL_CRIT, "%s: Can't find serial device on config line '%s'",
		       pluginid, info);
		goto token_error;		
	}

	ctx->device = STRDUP(token);
	if (!ctx->device) {
		LOG(PIL_CRIT, "out of memory");
		goto token_error;
	}

	/* Loop through the rest of the command line which should consist of */
	/* <nodename> <outlet> pairs */
	while ((node = strtok (NULL, " \t"))
	       && (outlet = strtok (NULL, " \t\n"))) {
		char outlet_id;

		/* validate the outlet token */
		if ((sscanf (outlet, "%c", &outlet_id) != 1)
		    || !( ((outlet_id >= '0') && (outlet_id <= '9'))
			|| (outlet_id == '*') || (outlet_id == 'A') )
		   ) {
			LOG(PIL_CRIT
			, "%s: the outlet_id %s must be between"
			" 0 and 9 or '*' / 'A'",
			       pluginid, outlet);
			goto token_error;
		}
		
		if (outlet_id == 'A') {
			/* Remap 'A' to '*'; in some configurations,
			 * a '*' can't be configured because it breaks
			 * scripts -- lmb */
			outlet_id = '*';
		}
		
		if (ctx->unit_count >= WTI_NUM_CONTROLLERS) {
			LOG(PIL_CRIT, 
				"%s: Tried to configure too many controllers",
				pluginid);
			goto token_error;
		}
		
		ctx->controllers[ctx->unit_count].node = STRDUP(node);
		g_strdown(ctx->controllers[ctx->unit_count].node);
		ctx->controllers[ctx->unit_count].outlet_id = outlet_id;
		ctx->unit_count++;

	} 

	/* free our private copy of the string we've been destructively 
	 * parsing with strtok()
	 */
	FREE(copy);
	ctx->config = 1;
	return ((ctx->unit_count > 0) ? S_OK : S_BADCONFIG);

token_error:
	FREE(copy);
	return(S_BADCONFIG);
}


/* 
 * dtrtoggle - toggle DTR on the serial port
 * 
 * snarfed from minicom, sysdep1.c, a well known POSIX trick.
 *
 */
static void dtrtoggle(int fd) {
    struct termios tty, old;
    int sec = 2;
    
    if (gbl_debug) printf ("Calling dtrtoggle (%s)\n", pluginid);
    
    tcgetattr(fd, &tty);
    tcgetattr(fd, &old);
    cfsetospeed(&tty, B0);
    cfsetispeed(&tty, B0);
    tcsetattr(fd, TCSANOW, &tty);
    if (sec>0) {
      sleep(sec);
      tcsetattr(fd, TCSANOW, &old);
    }
    
    if (gbl_debug) printf ("dtrtoggle Complete (%s)\n", pluginid);
}

/*
 * RPSConnect -
 *
 * Connect to the given WTI_RPS10 device.  
 * Side Effects
 *    DTR on the serial port is toggled
 *    ctx->fd now contains a valid file descriptor to the serial port
 *    ??? LOCK THE SERIAL PORT ???
 *  
 * Returns 
 *    S_OK on success
 *    S_OOPS on error
 *    S_TIMEOUT if the device did not respond
 *
 */
static int
RPSConnect(struct pluginDevice * ctx)
{
  	  
	/* Open the serial port if it isn't already open */
	if (ctx->fd < 0) {
		struct termios tio;

		ctx->fd = open (ctx->device, O_RDWR);
		if (ctx->fd <0) {
			LOG(PIL_CRIT, "%s: Can't open %s : %s",
				pluginid, ctx->device, strerror(errno));
			return S_OOPS;
		}

		/* set the baudrate to 9600 8 - N - 1 */
		memset (&tio, 0, sizeof(tio));

		/* ??? ALAN - the -tradtitional flag on gcc causes the 
		   CRTSCTS constant to generate a warning, and warnings 
                   are treated as errors, so I can't set this flag! - EZA ???
		   
                   Hmmm. now that I look at the documentation, RTS
		   is just wired high on this device! we don't need it.
		*/
		/* tio.c_cflag = B9600 | CS8 | CLOCAL | CREAD | CRTSCTS ;*/
		tio.c_cflag = B9600 | CS8 | CLOCAL | CREAD ;
		tio.c_lflag = ICANON;

		if (tcsetattr (ctx->fd, TCSANOW, &tio) < 0) {
			LOG(PIL_CRIT, "%s: Can't set attributes %s : %s",
				pluginid, ctx->device, strerror(errno));
			close (ctx->fd);
			ctx->fd=-1;
			return S_OOPS;
		}
		/* flush all data to and fro the serial port before we start */
		if (tcflush (ctx->fd, TCIOFLUSH) < 0) {
			LOG(PIL_CRIT, "%s: Can't flush %s : %s",
				pluginid, ctx->device, strerror(errno));
			close (ctx->fd);
			ctx->fd=-1;
			return S_OOPS;		
		}
		
	}

	/* Toggle DTR - this 'resets' the controller serial port interface 
           In minicom, try CTRL-A H to hangup and you can see this behavior.
         */
	dtrtoggle(ctx->fd);

	/* Wait for the switch to respond with "RPS-10 Ready".  
	   Emperically, this usually takes 5-10 seconds... 
	   ... If this fails, this may be a hint that you got
	   a broken serial cable, which doesn't connect hardware
	   flow control.
	*/
	if (gbl_debug) printf ("Waiting for READY\n");
	EXPECT(ctx->fd, WTItokReady, 12);
	if (gbl_debug) printf ("Got READY\n");
	EXPECT(ctx->fd, WTItokCRNL, 2);
	if (gbl_debug) printf ("Got NL\n");

  return(S_OK);
}

static int
RPSDisconnect(struct pluginDevice * ctx)
{

  if (ctx->fd >= 0) {
    /* Flush the serial port, we don't care what happens to the characters
       and failing to do this can cause close to hang.
    */
    tcflush(ctx->fd, TCIOFLUSH);
    close (ctx->fd);
  }
  ctx->fd = -1;

  return S_OK;
} 

/*
 * RPSNametoOutlet - Map a hostname to an outlet on this stonith device.
 *
 * Returns:
 *     0-9, * on success ( the outlet id on the RPS10 )
 *     -1 on failure (host not found in the config file)
 * 
 */
static signed char
RPSNametoOutlet ( struct pluginDevice * ctx, const char * host )
{
	int i=0;
	char *shost;

	if ( (shost = STRDUP(host)) == NULL) {
		LOG(PIL_CRIT, "strdup failed in RPSNametoOutlet");
		return -1;
	}
	g_strdown(shost);
		
	/* scan the controllers[] array to see if this host is there */
	for (i=0;i<ctx->unit_count;i++) {
		/* return the outlet id */
		if ( ctx->controllers[i].node 
		    && !strcmp(host, ctx->controllers[i].node)) {
			/* found it! */
			break;
		}
	}
	
	free(shost);
	if (i == ctx->unit_count) {
		return -1;
	} else {
		return ctx->controllers[i].outlet_id;
	}
}


/*
 *	rps10_reset - API call to Reset (reboot) the given host on 
 *          this Stonith device.  This involves toggling the power off 
 *          and then on again, OR just calling the builtin reset command
 *          on the stonith device.
 */
static int
rps10_reset_req(Stonith * s, int request, const char * host)
{
	int	rc = S_OK;
	int	lorc = S_OK;
	signed char outlet_id = -1;
	struct pluginDevice*	ctx;
	
	if (gbl_debug) printf ("Calling rps10_reset (%s)\n", pluginid);
	
	ERRIFNOTCONFIGED(s,S_OOPS);

	ctx = (struct pluginDevice*) s->pinfo;

	if ((rc = RPSConnect(ctx)) != S_OK) {
		return(rc);
	}

	outlet_id = RPSNametoOutlet(ctx, host);

	if (outlet_id < 0) {
		LOG(PIL_WARN, "%s %s %s[%s]"
		,	ctx->idinfo, ctx->unitid
		,	_("doesn't control host"), host );
		RPSDisconnect(ctx);
		return(S_BADHOST);
	}

	switch(request) {

#if defined(ST_POWERON) 
		case ST_POWERON:
			rc = RPSOn(ctx, outlet_id, host);
			break;
#endif
#if defined(ST_POWEROFF)
		case ST_POWEROFF:
			rc = RPSOff(ctx, outlet_id, host);
			break;
#endif
	case ST_GENERIC_RESET:
		rc = RPSReset(ctx, outlet_id, host);
		break;
	default:
		rc = S_INVAL;
		break;
	}

	lorc = RPSDisconnect(ctx);

	return(rc != S_OK ? rc : lorc);
}

/*
 *	Parse the information in the given configuration file,
 *	and stash it away...
 */
static int
rps10_set_config_file(Stonith* s, const char * configname)
{
	FILE *	cfgfile;

	char	RPSid[256];

	struct pluginDevice*	ctx;

	ERRIFWRONGDEV(s,S_OOPS);

	ctx = (struct pluginDevice*) s->pinfo;

	if ((cfgfile = fopen(configname, "r")) == NULL)  {
		LOG(PIL_CRIT, "%s %s", _("Cannot open"), configname);
		return(S_BADCONFIG);
	}

	while (fgets(RPSid, sizeof(RPSid), cfgfile) != NULL){

		switch (RPSid[0]){
			case '\0': case '\n': case '\r': case '#':
			continue;
		}

		/* We can really only handle one line. Wimpy. */
		return RPS_parse_config_info(ctx, RPSid);
	}
	return(S_BADCONFIG);
}

/*
 *	rps10_set_config_info - API entry point to process one line of config info 
 *       for this particular device.
 *
 *      Parse the config information in the given string, and stash it away...
 *
 */
static int
rps10_set_config_info(Stonith* s, const char * info)
{
	struct pluginDevice* ctx;

	ERRIFWRONGDEV(s,S_OOPS);

	ctx = (struct pluginDevice *)s->pinfo;

	return(RPS_parse_config_info(ctx, info));
}

/*
 * rps10_getinfo - API entry point to retrieve something from the handle
 */
static const char *
rps10_getinfo(Stonith * s, int reqtype)
{
	struct pluginDevice* ctx;
	const char *	ret;

	ERRIFWRONGDEV(s,NULL);

	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	ctx = (struct pluginDevice *)s->pinfo;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = ctx->idinfo;
			break;

		case ST_CONF_INFO_SYNTAX:
			ret = _("<serial_device> <node> <outlet> "
			"[ <node> <outlet> [...] ]\n"
			"All tokens are white-space delimited.\n");
			break;

		case ST_CONF_FILE_SYNTAX:
			ret = _("<serial_device> <node> <outlet> "
			"[ <node> <outlet> [...] ]\n"
			"All tokens are white-space delimited.\n"
			"Blank lines and lines beginning with # are ignored");
			break;

		case ST_DEVICEDESCR:
			ret = _("Western Telematic Inc. (WTI) "
			"Remote Power Switch - RPS-10M.\n");
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
 * rps10_destroy - API entry point to destroy a WTI_RPS10 Stonith object.
 */
static void
rps10_destroy(Stonith *s)
{
	struct pluginDevice* ctx;

	VOIDERRIFWRONGDEV(s);

	ctx = (struct pluginDevice *)s->pinfo;

	ctx->pluginid = NOTwtiid;

	/*  close the fd if open and set ctx->fd to invalid */
	RPSDisconnect(ctx);
	
	if (ctx->device != NULL) {
		FREE(ctx->device);
		ctx->device = NULL;
	}
	if (ctx->idinfo != NULL) {
		FREE(ctx->idinfo);
		ctx->idinfo = NULL;
	}
	if (ctx->unitid != NULL) {
		FREE(ctx->unitid);
		ctx->unitid = NULL;
	}
}

/* 
 * rps10_new - API entry point called to create a new WTI_RPS10 Stonith device
 *          object. 
 */
static void *
rps10_new(void)
{
	struct pluginDevice*	ctx = MALLOCT(struct pluginDevice);

	if (ctx == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->pluginid = pluginid;
	ctx->fd = -1;
	ctx->config = 0;
	ctx->unit_count = 0;
	ctx->device = NULL;
	ctx->idinfo = NULL;
	ctx->unitid = NULL;
	REPLSTR(ctx->idinfo, DEVICE);
	REPLSTR(ctx->unitid, "unknown");

	return((void *)ctx);
}
