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
 *	rebooted, then it has been (barring misconfiguration or hardware
 *	errors)
 *
 *	A machine which we have STONITHed won't do anything more to its
 *	peripherials etc. until it goes through the reboot cycle.
 */

/*
 *
 * Copyright (c) 2000 Alan Robertson <alanr@unix.sh>
 * Copyright (c) 2004 International Business Machines, Inc.
 *
 * Author: Alan Robertson
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
#include <glib.h>
#include <ctype.h>

#include <pils/plugin.h>
#define	STONITH_VERS	2

/*
 *	Return codes from "Stonith" operations
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
	char *	stype;
}Stonith;

/* An array of StonithNVpairs is terminated by a NULL s_name */
typedef struct {
	char *	s_name;
	char *	s_value;
}StonithNVpair;

/*
 *	Operation requested by reset_req()
 */
#define	ST_GENERIC_RESET	1 /* Reset the machine any way you can */
#define	ST_POWERON		2 /* Power the node on */
#define	ST_POWEROFF		3 /* Power the node off */
/*
 *	Type of information requested by the get_info() call
 */
#define ST_CONF_XML	1	/* XML config info */
#define ST_DEVICEID	2	/* Device Type Identification */
#define ST_DEVICENAME	3	/* Unique Individual Device Identification */
				/* (only after stonith_set_config() call) */
#define ST_DEVICEDESCR	4	/* Device Description text */
#define ST_DEVICEURL	5	/* Manufacturer/Device URL */

extern PILPluginUniv *StonithPIsys;

char **	stonith_types(void);	/* NULL-terminated list */
				/* valid until next call of stonith_types() */
Stonith*stonith_new(const char * type);
void	stonith_delete(Stonith *);

const char * const *	stonith_get_confignames	(Stonith* s);
				/* static/global return */
				/* Return number and list of valid s_names */

const char*			/* static/global return - lots of things! */
	stonith_get_info	(Stonith* s, int infotype);

void	stonith_set_debug	(Stonith* s, int debuglevel);
void	stonith_set_log		(Stonith* s
				, PILLogFun);
			
int	stonith_set_config	(Stonith* s, StonithNVpair* list);
int	stonith_set_config_file(Stonith* s, const char * configname);
				/* uses get_confignames to determine which 
				 * names to look for in file configname, which
				 * is passed in by the -F option */
int	stonith_set_config_info(Stonith* s, const char * info);
				/* uses get_confignames to determine which 
				 * names to look for in string info, which
				 * is passed in by the -p option */
	/*
	 * Must call stonith_set_config() before calling functions below...
	 */
char**	stonith_get_hostlist	(Stonith* s);
void	stonith_free_hostlist	(char** hostlist);
int	stonith_get_status	(Stonith* s);
int	stonith_req_reset	(Stonith* s, int operation, const char* node);

StonithNVpair* stonith_env_to_NVpair(Stonith* s);

/* Stonith 1 compatibility:  Convert string to an NVpair set */
StonithNVpair*
	stonith1_compat_string_to_NVpair(Stonith* s, const char * str);
StonithNVpair*
	stonith_ghash_to_NVpair(GHashTable* stringtable);
void	free_NVpair(StonithNVpair*); /* Free result from above 2 functions */
void strdown(char *str); /* simple replacement for g_strdown */

/*
 * The ST_DEVICEID info call is intended to return the type of the Stonith
 * device.  Note that it may return a different result once it has attempted
 * to talk to the device (like after a status() call).  This is because
 * a given STONITH module may be able to talk to more than one kind of
 * model of STONITH device, and can't tell which type is out there
 * to until it talks to it.  For example, Baytech 3, Baytech 5 and
 * Baytech 5a are all supported by one module, and this module actually
 * captures the particular model number after it talks to it.
 *
 * The ST_DEVICEDESCR info call is intended to return information identifying
 * the type of STONITH device supported by this STONITH object.  This is so
 * users can tell if they have this kind of device or not.
 *
 * SHOULD THIS BE IN THE XML SO IT CAN BE SUPPLIED IN SEVERAL LANGUAGES??
 * But, this would mean the STONITH command would have to parse XML.
 * Sigh...  I'd rather not...  Or maybe it can be supplied duplicately
 * in the XML if that is thought to be desirable...
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
 * device using return from the ST_CONF_XML info call to direct the
 * GUI in what information to ask for to fill up the StonithNVpair
 * argument to the stonith_set_config() call.  This information would then
 * be prompted for according to the XML information, and then put into
 * a NULL-terminated array of StonithNVpair objects.
 *
 * Once this has been done, it can be tested for syntactic
 * validity with stonith_set_config().
 *
 * If it passes set_config(), it can be further validated using status()
 * which will then actually try and talk to the STONITH device.  If status()
 * returns S_OK, then communication with the device was successfully
 * established.
 *
 * Normally that would mean that logins, passwords, device names, and IP
 * addresses, etc. have been validated as required by the particular device.
 *
 * At this point, you can ask the device which machines it knows how to reset
 * using the stonith_get_hostlist() function.
 *
 */

#endif /*__STONITH_H*/
