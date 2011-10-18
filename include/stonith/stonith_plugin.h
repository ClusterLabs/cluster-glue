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
 * Copyright (c) 2004 International Business Machines, Inc.
 *
 * Author: Alan Robertson <alanr@unix.sh>
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

#ifndef __STONITH_PLUGIN_H
#	define __STONITH_PLUGIN_H

#include <stonith/stonith.h>
#include <glib.h>

typedef struct stonith_plugin	StonithPlugin;

#define NUM_STONITH_FNS 7

struct stonith_ops {
	StonithPlugin * (*new)	(const char*);		/* mini-Constructor */
	void (*destroy)		(StonithPlugin*);	/*(full) Destructor */

	const char* (*get_info)	(StonithPlugin*, int infotype);
	const char * const * (*get_confignames)	(StonithPlugin*);
	int (*set_config)	(StonithPlugin*, StonithNVpair* list);
					/* Finishes construction */
	/*
	 * Must call set_config before calling any of
	 * the member functions below...
	 */

	int (*get_status)	(StonithPlugin*s);
	int (*req_reset)	(StonithPlugin*, int op, const char* node);


	char** (*get_hostlist)	(StonithPlugin*);
				/* Returns list of hosts it supports */
};

struct stonith_plugin  {
	Stonith			s;
	struct stonith_ops*	s_ops;
	gboolean		isconfigured;
};

#define STONITH_TYPE	stonith2
#define STONITH_TYPE_S	"stonith2"
typedef struct StonithImports_s StonithImports;

struct Etoken {
	const char *	string;		/* The token to look for */
	int		toktype;	/* The type to return on match */
	int		matchto;	/* Modified during matches */
};

/* An array of StonithNamesToGet is terminated by a NULL s_name */
typedef struct {
	const char *	s_name;
	char *		s_value;
}StonithNamesToGet;

#define	TELNET_PORT	23
#define	TELNET_SERVICE	"telnet"

struct StonithImports_s {
	int (*ExpectToken)(int fd, struct Etoken * toklist, int to_secs
	,	char * buf, int maxline, int debug);
	int (*StartProcess)(const char * cmd, int * readfd, int * writefd);
	int (*OpenStreamSocket) (const char * host, int port
	,		const char * service);
		/* Service can be NULL, port can be <= 0, but not both... */
	const char* (*GetValue)(StonithNVpair*, const char * name);
	int	(*CopyAllValues) (StonithNamesToGet* out, StonithNVpair* in);
	char **(*StringToHostList)(const char * hlstring);
	char **(*CopyHostList)(const char * const * hlstring);
	void (*FreeHostList)(char** hostlist);
	int (*TtyLock)(const char* tty);
	int (*TtyUnlock)(const char* tty);
};


/*
 *	A few standardized parameter names
 */

#define	ST_HOSTLIST	"hostlist"
#define	ST_IPADDR	"ipaddr"
#define	ST_LOGIN	"login"
#define	ST_PASSWD	"password"
#define	ST_COMMUNITY	"community"	/* SNMP community */
#define	ST_TTYDEV	"ttydev"	/* TTY device name */

#endif /*__STONITH__PLUGIN_H*/
