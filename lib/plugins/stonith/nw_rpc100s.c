/*
 *	Stonith module for Night/Ware RPC100S 
 *
 *      Original code from baytech.c by
 *	Copyright (c) 2000 Alan Robertson <alanr@unix.sh>
 *
 *      Modifications for NW RPC100S
 *	Copyright (c) 2000 Computer Generation Incorporated
 *               Eric Z. Ayers <eric.ayers@compgen.com>
 *
 *      Mangled by Zhaokai <zhaokai@cn.ibm.com>, IBM, 2005
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
#define	DEVICE	"NW RPC100S Power Switch"
#include "stonith_plugin_common.h"

#define PIL_PLUGIN              nw_rpc100s
#define PIL_PLUGIN_S            "nw_rpc100s"
#define PIL_PLUGINLICENSE 	LICENSE_LGPL
#define PIL_PLUGINLICENSEURL 	URL_LGPL
#define MAX_CFGLINE		256
#include <pils/plugin.h>

static StonithPlugin *	nw_rpc100s_new(const char *);
static void		nw_rpc100s_destroy(StonithPlugin *);
static int		nw_rpc100s_set_config(StonithPlugin *, StonithNVpair *);
static const char * const *	nw_rpc100s_get_confignames(StonithPlugin *);
static const char *	nw_rpc100s_getinfo(StonithPlugin * s, int InfoType);
static int		nw_rpc100s_status(StonithPlugin * );
static int		nw_rpc100s_reset_req(StonithPlugin * s, int request, const char * host);
static char **		nw_rpc100s_hostlist(StonithPlugin  *);

static struct stonith_ops nw_rpc100sOps ={
	nw_rpc100s_new,		/* Create new STONITH object		*/
	nw_rpc100s_destroy,	/* Destroy STONITH object		*/
	nw_rpc100s_getinfo,	/* Return STONITH info string		*/
	nw_rpc100s_get_confignames,/* Return STONITH info string	*/
	nw_rpc100s_set_config,	/* Get configuration from NVpairs	*/
	nw_rpc100s_status,	/* Return STONITH device status		*/
	nw_rpc100s_reset_req,	/* Request a reset 			*/
	nw_rpc100s_hostlist,	/* Return list of supported hosts	*/
};

PIL_PLUGIN_BOILERPLATE2("1.0", Debug)
static const PILPluginImports*  PluginImports;
static PILPlugin*               OurPlugin;
static PILInterface*		OurInterface;
static StonithImports*		OurImports;
static void*			interfprivate;

#include "stonith_signal.h"

#define DOESNT_USE_STONITHKILLCOMM
#define DOESNT_USE_STONITHSCANLINE
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
	,	&nw_rpc100sOps
	,	NULL		/*close */
	,	&OurInterface
	,	(void*)&OurImports
	,	&interfprivate); 
}

/*
   The Nightware RPS-100S is manufactured by:
   
      Micro Energetics Corp
      +1 703 250-3000
      http://www.nightware.com/

   Thank you to David Hicks of Micro Energetics Corp. for providing
   a demo unit to write this software.
      
   This switch has a very simple protocol, 
   You issue a command and it  gives a response.
   Sample commands are conveniently documented on a sticker on the
      bottom of the device.
      
   The switch accepts a single command of the form

   //0,yyy,zzz[/m][/h]<CR>
   
     Where yyy is the wait time before activiting the relay.
           zzz is the relay time.

     The default is that the relay is in a default state of ON, which
     means that  usually yyy is the number of seconds to wait
     before shutting off the power  and zzz is the number of seconds the
     power remains off.  There is a dip switch to change the default
     state to 'OFF'.  Don't set this switch. It will screw up this code. 

     An asterisk can be used for zzz to specify an infinite switch time.
     The /m /and /h command options will convert the specified wait and
     switch times to either minutewes or hours. 
   
   A response is either
    <cr><lf>OK<cr><lf>
       or
    <cr><lf>Invalid Entry<cr><lf>


   As far as THIS software is concerned, we have to implement 4 commands:

   status     -->    //0,0,BOGUS; # Not a real command, this is just a
                                  #   probe to see if switch is alive
   open(on)   -->    //0,0,0;     # turn power to default state (on)
   close(off) -->    //0,0,*;     # leave power off indefinitely
   reboot     -->    //0,0,10;    # immediately turn power off for 10 seconds.

   and expect the response 'OK' to confirm that the unit is operational.
*/



struct pluginDevice {
	StonithPlugin   sp;
	const char *	pluginid;
	const char *	idinfo;

	int	fd;      /* FD open to the serial port */

	char *	device;  /* Serial device name to use to communicate 
                            to this RPS10
			 */

	char *  node;    /* Name of the node that this is controlling */

};

/* This string is used to identify this type of object in the config file */
static const char * pluginid = "NW_RPC100S";
static const char * NOTrpcid = "NW RPC100S device has been destroyed";

#include "stonith_config_xml.h"

static const char *nw_rpc100sXML = 
  XML_PARAMETERS_BEGIN
    XML_TTYDEV_PARM
    XML_HOSTLIST_PARM
  XML_PARAMETERS_END;

/*
 *	Different expect strings that we get from the NW_RPC100S
 *	Remote Power Controllers...
 */

static struct Etoken NWtokOK[] =	{ {"OK", 0, 0}, {NULL,0,0}};
static struct Etoken NWtokInvalidEntry[] = { {"Invalid Entry", 0, 0}, {NULL,0,0}};
/* Accept either a CR/NL or an NL/CR */
static struct Etoken NWtokCRNL[] =	{ {"\n\r",0,0},{"\r\n",0,0},{NULL,0,0}};

static int	RPCConnect(struct pluginDevice * ctx);
static int	RPCDisconnect(struct pluginDevice * ctx);

static int	RPCReset(struct pluginDevice*, int unitnum, const char * rebootid);
#if defined(ST_POWERON) 
static int	RPCOn(struct pluginDevice*, int unitnum, const char * rebootid);
#endif
#if defined(ST_POWEROFF) 
static int	RPCOff(struct pluginDevice*, int unitnum, const char * rebootid);
#endif
static int	RPCNametoOutlet ( struct pluginDevice * ctx, const char * host );

/*static int RPC_parse_config_info(struct pluginDevice* ctx, const char * info);*/


#define        SENDCMD(cmd, timeout)              {			\
		int return_val = RPCSendCommand(ctx, cmd, timeout);     \
		if (return_val != S_OK) {				\
			return return_val;				\
		}							\
	}

/*
 * RPCSendCommand - send a command to the specified outlet
 */
static int
RPCSendCommand (struct pluginDevice *ctx, const char *command, int timeout)
{
	char            writebuf[64]; /* All commands are short.
					 They should be WAY LESS
					 than 64 chars long!
				      */
	int		return_val;  /* system call result */
	fd_set          rfds, wfds, xfds;
				     /*  list of FDs for select() */
	struct timeval 	tv;	     /*  */

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);
	FD_ZERO(&xfds);

	snprintf (writebuf, sizeof(writebuf), "%s\r", command);

	if (Debug) {
		LOG(PIL_DEBUG, "Sending %s", writebuf);
	}

	/* Make sure the serial port won't block on us. use select()  */
	FD_SET(ctx->fd, &wfds);
	FD_SET(ctx->fd, &xfds);
	
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	
	return_val = select(ctx->fd+1, NULL, &wfds,&xfds, &tv);
	if (return_val == 0) {
		/* timeout waiting on serial port */
		LOG(PIL_CRIT, "%s: Timeout writing to %s"
		,	pluginid, ctx->device);
		return S_TIMEOUT;
	} else if ((return_val == -1) || FD_ISSET(ctx->fd, &xfds)) {
		/* an error occured */
		LOG(PIL_CRIT, "%s: Error before writing to %s: %s"
		,	pluginid, ctx->device, strerror(errno));		
		return S_OOPS;
	}

	/* send the command */
	if (write(ctx->fd, writebuf, strlen(writebuf)) != 
			(int)strlen(writebuf)) {
		LOG(PIL_CRIT, "%s: Error writing to  %s : %s"
		,	pluginid, ctx->device, strerror(errno));
		return S_OOPS;
	}

	/* suceeded! */
	return S_OK;

}  /* end RPCSendCommand() */

/* 
 * RPCReset - Reset (power-cycle) the given outlet number
 *
 * This device can only control one power outlet - unitnum is ignored.
 *
 */
static int
RPCReset(struct pluginDevice* ctx, int unitnum, const char * rebootid)
{

	if (Debug) {
		LOG(PIL_DEBUG, "Calling RPCReset (%s)", pluginid);
	}
	
	if (ctx->fd < 0) {
		LOG(PIL_CRIT, "%s: device %s is not open!", pluginid
		,	ctx->device);
		return S_OOPS;
	}

	/* send the "toggle power" command */
	SENDCMD("//0,0,10;\r\n", 12);

	/* Expect "OK" */
	EXPECT(ctx->fd, NWtokOK, 5);
	if (Debug) {
		LOG(PIL_DEBUG, "Got OK");
	}
	EXPECT(ctx->fd, NWtokCRNL, 2);
	if (Debug) {
		LOG(PIL_DEBUG, "Got NL");
	}
	
	return(S_OK);

} /* end RPCReset() */


#if defined(ST_POWERON) 
/* 
 * RPCOn - Turn OFF the given outlet number 
 */
static int
RPCOn(struct pluginDevice* ctx, int unitnum, const char * host)
{

	if (ctx->fd < 0) {
		LOG(PIL_CRIT, "%s: device %s is not open!", pluginid
		,	ctx->device);
		return S_OOPS;
	}

	/* send the "On" command */
	SENDCMD("//0,0,0;\r\n", 10);

	/* Expect "OK" */
	EXPECT(ctx->fd, NWtokOK, 5);
	EXPECT(ctx->fd, NWtokCRNL, 2);

	return(S_OK);

} /* end RPCOn() */
#endif


#if defined(ST_POWEROFF) 
/* 
 * RPCOff - Turn Off the given outlet number 
 */
static int
RPCOff(struct pluginDevice* ctx, int unitnum, const char * host)
{

	if (ctx->fd < 0) {
		LOG(PIL_CRIT, "%s: device %s is not open!", pluginid
		,	ctx->device);
		return S_OOPS;
	}

	/* send the "Off" command */
	SENDCMD("//0,0,*;\r\n", 10);

	/* Expect "OK" */
	EXPECT(ctx->fd, NWtokOK, 5);
	EXPECT(ctx->fd, NWtokCRNL, 2);

	return(S_OK);

} /* end RPCOff() */
#endif


/*
 * nw_rpc100s_status - API entry point to probe the status of the stonith device 
 *           (basically just "is it reachable and functional?", not the
 *            status of the individual outlets)
 * 
 * Returns:
 *    S_OOPS - some error occured
 *    S_OK   - if the stonith device is reachable and online.
 */
static int
nw_rpc100s_status(StonithPlugin  *s)
{
	struct pluginDevice*	ctx;
	
	if (Debug) {
		LOG(PIL_DEBUG, "Calling nw_rpc100s_status (%s)", pluginid);
	}
	
	ERRIFNOTCONFIGED(s,S_OOPS);

	ctx = (struct pluginDevice*) s;
	if (RPCConnect(ctx) != S_OK) {
		return(S_OOPS);
	}

	/* The "connect" really does enough work to see if the 
	   controller is alive...  It verifies that it is returning 
	   RPS-10 Ready 
	*/

	return(RPCDisconnect(ctx));
}

/*
 * nw_rpc100s_hostlist - API entry point to return the list of hosts 
 *                 for the devices on this NW_RPC100S unit
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
nw_rpc100s_hostlist(StonithPlugin  *s)
{
	char **		ret = NULL;	/* list to return */
	struct pluginDevice*	ctx;

	if (Debug) {
		LOG(PIL_DEBUG, "Calling nw_rpc100s_hostlist (%s)", pluginid);
	}
	
	ERRIFNOTCONFIGED(s,NULL);

	ctx = (struct pluginDevice*) s;

	ret = OurImports->StringToHostList(ctx->node);
	if (ret == NULL) {
		LOG(PIL_CRIT, "%s: out of memory", __FUNCTION__);
	} else {
		strdown(ret[0]);
	}

	return(ret);
} /* end si_hostlist() */

/*
 *	Parse the given configuration information, and stash it away...
 *
 *      <info> contains the parameters specific to this type of object
 *
 *         The format of <parameters> for this module is:
 *            <serial device> <remotenode> <outlet> [<remotenode> <outlet>] ...
 *
 *      e.g. A machine named 'nodea' can kill a machine named 'nodeb' through
 *           a device attached to serial port /dev/ttyS0.
 *           A machine named 'nodeb' can kill machines 'nodea' and 'nodec'
 *           through a device attached to serial port /dev/ttyS1 (outlets 0 
 *             and 1 respectively)
 *
 *      stonith nodea NW_RPC100S /dev/ttyS0 nodeb 0 
 *      stonith nodeb NW_RPC100S /dev/ttyS0 nodea 0 nodec 1
 *
 *      Another possible configuration is for 2 stonith devices accessible
 *         through 2 different serial ports on nodeb:
 *
 *      stonith nodeb NW_RPC100S /dev/ttyS0 nodea 0 
 *      stonith nodeb NW_RPC100S /dev/ttyS1 nodec 0
 */

/*static int
RPC_parse_config_info(struct pluginDevice* ctx, const char * info)
{
}*/


/*
 * RPCConnect -
 *
 * Connect to the given NW_RPC100S device.  
 * Side Effects
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
RPCConnect(struct pluginDevice * ctx)
{
  	  
	/* Open the serial port if it isn't already open */
	if (ctx->fd < 0) {
		struct termios tio;

		if (OurImports->TtyLock(ctx->device) < 0) {
			LOG(PIL_CRIT, "%s: TtyLock failed.", pluginid);
			return S_OOPS;
		}

		ctx->fd = open (ctx->device, O_RDWR);
		if (ctx->fd <0) {
			LOG(PIL_CRIT, "%s: Can't open %s : %s"
			,	pluginid, ctx->device, strerror(errno));
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
			LOG(PIL_CRIT, "%s: Can't set attributes %s : %s"
			,	pluginid, ctx->device, strerror(errno));
			close (ctx->fd);
			OurImports->TtyUnlock(ctx->device);
			ctx->fd=-1;
			return S_OOPS;
		}
		/* flush all data to and fro the serial port before we start */
		if (tcflush (ctx->fd, TCIOFLUSH) < 0) {
			LOG(PIL_CRIT, "%s: Can't flush %s : %s"
			,	pluginid, ctx->device, strerror(errno));
			close (ctx->fd);
			OurImports->TtyUnlock(ctx->device);
			ctx->fd=-1;
			return S_OOPS;		
		}
		
	}


	/* Send a BOGUS string */
	SENDCMD("//0,0,BOGUS;\r\n", 10);
	
	/* Should reply with "Invalid Command" */
	if (Debug) {
		LOG(PIL_DEBUG, "Waiting for \"Invalid Entry\"");
	}
	EXPECT(ctx->fd, NWtokInvalidEntry, 12);
	if (Debug) {
		LOG(PIL_DEBUG, "Got Invalid Entry");
	}
	EXPECT(ctx->fd, NWtokCRNL, 2);
	if (Debug) {
		LOG(PIL_DEBUG, "Got NL");
	}
	   
  return(S_OK);
}

static int
RPCDisconnect(struct pluginDevice * ctx)
{

  if (ctx->fd >= 0) {
    /* Flush the serial port, we don't care what happens to the characters
       and failing to do this can cause close to hang.
    */
    tcflush(ctx->fd, TCIOFLUSH);
    close (ctx->fd);
    if (ctx->device != NULL) {
      OurImports->TtyUnlock(ctx->device);
    }
  }
  ctx->fd = -1;

  return S_OK;
} 

/*
 * RPCNametoOutlet - Map a hostname to an outlet number on this stonith device.
 *
 * Returns:
 *     0 on success ( the outlet number on the RPS10 - there is only one )
 *     -1 on failure (host not found in the config file)
 * 
 */
static int
RPCNametoOutlet ( struct pluginDevice * ctx, const char * host )
{
	int rc = -1;
	
	if (!strcasecmp(ctx->node, host)) {
		rc = 0;
	}

	return rc;
}


/*
 *	nw_rpc100s_reset - API call to Reset (reboot) the given host on 
 *          this Stonith device.  This involves toggling the power off 
 *          and then on again, OR just calling the builtin reset command
 *          on the stonith device.
 */
static int
nw_rpc100s_reset_req(StonithPlugin * s, int request, const char * host)
{
	int	rc = S_OK;
	int	lorc = S_OK;
	int outletnum = -1;
	struct pluginDevice*	ctx;
	
	if (Debug) {
		LOG(PIL_DEBUG, "Calling nw_rpc100s_reset (%s)", pluginid);
	}
	
	ERRIFNOTCONFIGED(s,S_OOPS);

	ctx = (struct pluginDevice*) s;

	if ((rc = RPCConnect(ctx)) != S_OK) {
		return(rc);
	}

	outletnum = RPCNametoOutlet(ctx, host);
	LOG(PIL_DEBUG, "zk:outletname=%d", outletnum);

	if (outletnum < 0) {
		LOG(PIL_WARN, "%s doesn't control host [%s]"
		,	ctx->device, host);
		RPCDisconnect(ctx);
		return(S_BADHOST);
	}

	switch(request) {

#if defined(ST_POWERON) 
		case ST_POWERON:
			rc = RPCOn(ctx, outletnum, host);
			break;
#endif
#if defined(ST_POWEROFF)
		case ST_POWEROFF:
			rc = RPCOff(ctx, outletnum, host);
			break;
#endif
	case ST_GENERIC_RESET:
		rc = RPCReset(ctx, outletnum, host);
		break;
	default:
		rc = S_INVAL;
		break;
	}

	lorc = RPCDisconnect(ctx);

	return(rc != S_OK ? rc : lorc);
}

/*
 *	Parse the information in the given string 
 *	and stash it away...
 */
static int
nw_rpc100s_set_config(StonithPlugin* s, StonithNVpair *list)
{
	struct pluginDevice*	ctx;
	StonithNamesToGet	namestocopy [] =
	{	{ST_TTYDEV,	NULL}
	,	{ST_HOSTLIST,	NULL}
	,	{NULL,		NULL}
	};
	int rc;


	ERRIFWRONGDEV(s,S_OOPS);
	if (s->isconfigured) {
		return S_OOPS;
	}

	ctx = (struct pluginDevice*) s;
	
	if ((rc = OurImports->CopyAllValues(namestocopy, list)) != S_OK) {
		return rc;
	}
	ctx->device = namestocopy[0].s_value;
	ctx->node = namestocopy[1].s_value;

	return S_OK;
}

/*
 * Return STONITH config vars
 */
static const char * const *
nw_rpc100s_get_confignames(StonithPlugin* p)
{
	static const char *	RpcParams[] = {ST_TTYDEV , ST_HOSTLIST, NULL };
	return RpcParams;
}



/*
 * nw_rpc100s_getinfo - API entry point to retrieve something from the handle
 */
static const char *
nw_rpc100s_getinfo(StonithPlugin * s, int reqtype)
{
	struct pluginDevice* ctx;
	const char *		ret;

	ERRIFWRONGDEV(s,NULL);

	/*
	 *	We look in the ST_TEXTDOMAIN catalog for our messages
	 */
	ctx = (struct pluginDevice *)s;

	switch (reqtype) {
		case ST_DEVICEID:
			ret = ctx->idinfo;
			break;
		case ST_DEVICENAME:
			ret = ctx->device;
			break;
		case ST_DEVICEDESCR:
			ret = "Micro Energetics Night/Ware RPC100S";
			break;
		case ST_DEVICEURL:
			ret = "http://www.microenergeticscorp.com/";
			break;
		case ST_CONF_XML:		/* XML metadata */
			ret = nw_rpc100sXML;
			break;
		default:
			ret = NULL;
			break;
	}
	return ret;
}

/*
 * nw_rpc100s_destroy - API entry point to destroy a NW_RPC100S Stonith object.
 */
static void
nw_rpc100s_destroy(StonithPlugin *s)
{
	struct pluginDevice* ctx;

	VOIDERRIFWRONGDEV(s);

	ctx = (struct pluginDevice *)s;

	ctx->pluginid = NOTrpcid;

	/*  close the fd if open and set ctx->fd to invalid */
	RPCDisconnect(ctx);
	
	if (ctx->device != NULL) {
		FREE(ctx->device);
		ctx->device = NULL;
	}
	if (ctx->node != NULL) {
		FREE(ctx->node);
		ctx->node = NULL;
	}
	FREE(ctx);
}

/* 
 * nw_rpc100s_new - API entry point called to create a new NW_RPC100S Stonith
 * device object. 
 */
static StonithPlugin *
nw_rpc100s_new(const char *subplugin)
{
	struct pluginDevice*	ctx = ST_MALLOCT(struct pluginDevice);

	if (ctx == NULL) {
		LOG(PIL_CRIT, "out of memory");
		return(NULL);
	}
	memset(ctx, 0, sizeof(*ctx));
	ctx->pluginid = pluginid;
	ctx->fd = -1;
	ctx->device = NULL;
	ctx->node = NULL;
	ctx->idinfo = DEVICE;
	ctx->sp.s_ops = &nw_rpc100sOps;

	return &(ctx->sp);
}
