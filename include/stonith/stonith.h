/*
 *	S hoot
 *	T he
 *	O ther
 *	N ode
 *	I n
 *	T he
 *	H ead
 *
 *	Cause the other machine to reboot or die - now.
 *
 *	We guarantee that when we report that the machine has been
 *	rebooted, then it has been (barring misconfiguration or hardware errors)
 *
 *	A machine which we have STONITHed won't do anything more to its
 *	peripherials etc. until it goes through the reboot cycle.
 */

/*
 *
 * Copyright (c) 2000 Alan Robertson <alanr@unix.sh>
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

#ifndef __STONITH_H
#	define __STONITH_H

#include "signal.h"
/*
 *	Return codes from "Stonith" member functions.
 */

#define	S_OK		0	/* Machine correctly reset	*/
#define	S_BADCONFIG	1	/* Bad config info given	*/
#define	S_ACCESS	2	/* Can't access STONITH device	*/
				/* (login/passwd problem?)	*/
#define	S_INVAL		3	/* Bad/illegal argument		*/
#define	S_BADHOST	4	/* Bad/illegal host/node name	*/
#define	S_RESETFAIL	5	/* Reset failed			*/
#define	S_TIMEOUT	6	/* Timed out in the dialogues	*/
#define	S_ISOFF		7	/* Can't reboot: Outlet is off	*/
#define	S_OOPS		8	/* Something strange happened	*/

typedef struct stonith {
	struct stonith_ops *	s_ops;
	char *			stype;
	void *			pinfo;
}Stonith;

/*
 *	These functions all use syslog(3) for error messages.
 *	Consequently they assume you've done an openlog() to initialize it
 *	for them.
 */

#define NR_STONITH_FNS 9

struct stonith_ops {
	void * (*new)		(void);
	void (*destroy)		(Stonith*);
	int (*set_config_file)	(Stonith *, const char   * filename); 
	int (*set_config_info)	(Stonith *, const char   * confstring); 
/*
 *	Type of information requested by the getinfo() call
 */
#define	ST_CONF_FILE_SYNTAX	1	/* Config file syntax help */
#define	ST_CONF_INFO_SYNTAX	2	/* Config string (info) syntax help */
#define	ST_DEVICEID		3	/* Device Type Identification */
#define	ST_DEVICENAME		4	/* Unique Device Identification */
#define	ST_DEVICEDESCR		5	/* Device Description text */
#define	ST_DEVICEURL		6	/* Manufacturer/Device URL */

	/* Getinfo() calls return text in the current locale */
	const char* (*getinfo)		(Stonith*, int infotype);

	/*
	 * Must call set_config_info or set_config_file before calling any of
	 * the member functions below...
	 */

	int (*status)			(Stonith *s);
/*
 *	Operation requested by reset_req()
 */
#define	ST_GENERIC_RESET	1	/* Reset the machine any way you can */
#define	ST_POWERON		2	/* Power the node on */
#define	ST_POWEROFF		3	/* Power the node off */

	int (*reset_req)		(Stonith * s, int op, const char* node);


	char** (*hostlist)		(Stonith* s);
					/* Returns list of hosts it supports */
	void (*free_hostlist)		(char** hostlist);
};

extern Stonith *	stonith_new(const char * type);
extern void		stonith_delete(Stonith *);
extern char **		stonith_types(void);	/* NULL-terminated list */
			/* valid until next call of stonith_types() */

/*
 * It is intended that the ST_CONF_FILE_SYNTAX info call return a string
 * describing the syntax of the configuration file that set_config_file() will
 * accept. This string can then be used as short help text in configuration
 * tools, etc.
 *
 * The ST_CONF_INFO_SYNTAX info call serves a similar purpose with respect to
 * the configuration string.
 *
 * The ST_DEVICEID info call is intended to return the type of the Stonith
 * device.  Note that it may return a different result once it has attempted
 * to talk to the device (like after a status() call).
 *
 * The ST_DEVICEDESCR info call is intended to return information identifying
 * the type of STONITH device supported by this STONITH object.  This is so
 * users can tell if they have this kind of device or not.
 *
 * The ST_DEVICEURL info call is intended to return the URL of a web site
 * related to the device in question.  This might be the manufacturer,
 * a pointer to the product line, or the individual product itself.
 *
 * A good way for a GUI to work which configures STONITH devices would be to
 * use the result of the stonith_types() call in a pulldown menu.
 *
 * Once the type is selected, create a Stonith object of the selected type.
 * One can then create a dialog box to create the configuration info for the
 * device using the text from the ST_CONF_INFO_SYNTAX info call to direct the
 * user in what information to supply in the conf_info string.
 *
 * Once the user has completed their selection, it can be tested for syntactic
 * validity with set_config_info().
 *
 * If it passes set_config_info(), it can be further validated using status()
 * which will then actually try and talk to the STONITH device.  If status()
 * returns S_OK, then communication with the device was successfully
 * established.
 *
 * Normally that would mean that logins, passwords, device names, and IP
 * addresses, etc. have been validated as required by the particular device.
 *
 * At this point, you can ask the device which machines it knows how to reset
 * using the hostlist() member function.
 *
 * When implementors of Stonith types put the return values of their
 * getinfo() calls inside the dgettext(ST_TEXTDOMAIN) macro, we should be
 * able to satisfy international customers as well.
 *
 */
#define STONITH_TYPE	stonith
#define STONITH_TYPE_S	"stonith"
typedef struct StonithImports_s StonithImports;

struct Etoken {
	const char *	string;		/* The token to look for */
	int		toktype;	/* The type to return on match */
	int		matchto;	/* Modified during matches */
};
struct StonithImports_s {
	int (*ExpectToken)(int fd, struct Etoken * toklist, int to_secs
	,	char * buf, int maxline);
	int (*StartProcess)(const char * cmd, int * readfd, int * writefd);
};
#endif /*__STONITH_H*/
