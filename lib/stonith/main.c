/* $Id: main.c,v 1.13 2005/01/03 18:12:11 alan Exp $ */
/*
 * Stonith: simple test program for exercising the Stonith API code
 *
 * Copyright (C) 2000 Alan Robertson <alanr@unix.sh>
 *
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
#include <syslog.h>
#include <stonith/stonith.h>
#include <pils/plugin.h>
#include <glib.h>

#define	OPTIONS	"F:p:t:sSlLvhd"
#define	EQUAL	'='

extern char *	optarg;
extern int	optind, opterr, optopt;

static int	debug = 0;

void usage(const char * cmd, int exit_status);
void confhelp(const char * cmd, FILE* stream);

/*
 * Note that we don't use the cl_log logging code because the STONITH
 * command is intended to be shipped without the clplumbing libraries.
 *
 *	:-(
 */

void
usage(const char * cmd, int exit_status)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;

	fprintf(stream, "usage: %s [-sSlLvh] "
	"[-t stonith-device-type] "
	"[-p stonith-device-parameters] "
	"[-F stonith-device-parameters-file] "
	"nodename\n", cmd);

	fprintf(stream, "\t-L\tlist supported stonith device types\n");
	fprintf(stream, "\t-l\tlist hosts controlled by this stonith device\n");
	fprintf(stream, "\t-S\treport stonith device status\n");
	fprintf(stream, "\t-s\tsilent\n");
	fprintf(stream, "\t-v\tverbose\n");
	fprintf(stream, "\t-h\tget this help message\n");

	confhelp(cmd, stream);

	exit(exit_status);
}

/* Thanks to Lorn Kay <lorn_kay@hotmail.com> for the confhelp code */
void
confhelp(const char * cmd, FILE* stream)
{
	char ** typelist;
	char ** this;
	Stonith *       s;

	fprintf(stream
	,	"\nSTONITH -t device types and"
		" associated configuration details:\n");

	typelist = stonith_types();
	
	if (typelist == NULL) {
		fprintf(stderr, 
			"Failed to retrieve list of STONITH modules!\n");
		return;
	}
	for(this=typelist; *this; ++this) {
		const char *    SwitchType = *this;
		const char *	cres;

		if ((s = stonith_new(SwitchType)) == NULL) {
			fprintf(stderr, "Invalid STONITH type %s(!)\n"
			,	SwitchType);
			continue;
		}

		fprintf(stream, "\n\nSTONITH Device: %s - ", SwitchType);

		if ((cres = stonith_get_info(s, ST_DEVICEDESCR)) != NULL){
			fprintf(stream, "%s\n"
			,	cres);
		}

		if ((cres = stonith_get_info(s, ST_DEVICEURL)) != NULL){
			fprintf(stream
			,	"For more information see %s\n"
			,	cres);
		}

#ifdef ST_CONFI_INFO_SYNTAX
		fprintf(stream, "\nConfig info [-p] syntax for %s:\n\t%s\n"
		,    SwitchType, stonith_get_info(s, ST_CONF_INFO_SYNTAX));
#endif
#ifdef ST_CONFI_FILE_SYNTAX
		fprintf(stream, "\nConfig file [-F] syntax for %s:\n\t%s\n"
		,    SwitchType, stonith->get_info(s, ST_CONF_FILE_SYNTAX));
#endif

		stonith_delete(s); s = NULL;
	}
	/* Note that the type list can't/shouldn't be freed */
	
}

#define	MAXNVARG	50

int
main(int argc, char** argv)
{
	char *		cmdname;
	int		rc;
	Stonith *	s;
	const char *	SwitchType = NULL;
	const char *	optfile = NULL;
	const char *	parameters = NULL;
	int		verbose = 0;
	int		status = 0;
	int		silent = 0;
	int		listhosts = 0;
	int		listtypes = 0;

	int		c;
	int		errors = 0;
	int		argcount;
	StonithNVpair	nvargs[MAXNVARG];
	int		nvcount=0;

	if ((cmdname = strrchr(argv[0], '/')) == NULL) {
		cmdname = argv[0];
	}else{
		++cmdname;
	}


	while ((c = getopt(argc, argv, OPTIONS)) != -1) {
		switch(c) {

		case 'd':	debug++;
				break;

		case 'F':	optfile = optarg;
				break;

		case 'h':	usage(cmdname, 0);
				break;

		case 'l':	++listhosts;
				break;

		case 'L':	++listtypes;
				break;

		case 'p':	parameters = optarg;
				break;

		case 's':	++silent;
				break;

		case 'S':	++status;
				break;

		case 't':	SwitchType = optarg;
				break;

		case 'v':	++verbose;
				break;

		default:	++errors;
				break;
		}
	}

	if (debug) {
		PILpisysSetDebugLevel(debug);
	}
	if (optfile && parameters) {
		++errors;
	}

	/*
	 *	Process name=value arguments on command line...
	 */
	for (;optind < argc; ++optind) {
		char *	eqpos;
		if ((eqpos=strchr(argv[optind], EQUAL)) == NULL) {
			break;
		}
		if (parameters)  {
			fprintf(stderr
			,	"Cannot include both -p and name=value "
			" style arguments\n");
			usage(cmdname, 1);
		}
		if (nvcount >= MAXNVARG) {
			fprintf(stderr, "Too many n=v arguments\n");
			exit(1);
		}
		nvargs[nvcount].s_name = argv[optind];
		*eqpos = EOS;
		nvargs[nvcount].s_value = eqpos+1;
	}
	nvargs[nvcount].s_name = NULL;
	nvargs[nvcount].s_value = NULL;

	argcount = argc - optind;

	if (!(argcount == 1 || (argcount < 1
	&&	(status||listhosts||listtypes)))) {
		++errors;
	}

	if (errors) {
		usage(cmdname, 1);
	}

	if (listtypes) {
		char **	typelist;

		typelist = stonith_types();
		if (typelist == NULL) {
			syslog(LOG_ERR, "Could not list Stonith types.");
		}else{
			char **	this;

			for(this=typelist; *this; ++this) {
				printf("%s\n", *this);
			}
		}
		return(0);
	}

	if (optfile == NULL && parameters == NULL) {
		optfile = "/etc/ha.d/rpc.cfg";
	}
	if (SwitchType == NULL) {
		SwitchType = "baytech";
	}
#ifndef LOG_PERROR
#	define LOG_PERROR	0
#endif
	openlog(cmdname, (LOG_CONS|(silent ? 0 : LOG_PERROR)), LOG_USER);
	s = stonith_new(SwitchType);

	if (s == NULL) {
		syslog(LOG_ERR, "Invalid device type: '%s'", SwitchType);
		exit(S_OOPS);
	}
#if 0
	/* Old STONITH version 1 stuff... */
	if (optfile) {
		/* Configure the Stonith object from a file */
		if ((rc=s->s_ops->set_config_file(s, optfile)) != S_OK) {
			syslog(LOG_ERR
			,	"Invalid config file for %s device."
			,	SwitchType);
			syslog(LOG_INFO, "Config file syntax: %s"
			,	s->s_ops->getinfo(s, ST_CONF_FILE_SYNTAX));
			stonith_delete(s); s=NULL;
			exit(rc);
		}
	}else{
#else
	if (parameters) {
		/* Configure Stonith object from the -p argument */
		StonithNVpair *		pairs;
		if ((pairs = stonith1_compat_string_to_NVpair
		(	s, parameters)) == NULL) {
			fprintf(stderr
			,	"Invalid STONITH -p parameter [%s]\n"
			,	parameters);
			exit(1);
		}
		if ((rc = stonith_set_config(s, pairs)) != S_OK) {
			fprintf(stderr
			,	"Invalid config info for %s device"
			,	SwitchType);
		}
	}else{
		/*
		 *	Configure STONITH device using cmdline arguments...
		 */
		if ((rc = stonith_set_config(s, nvargs)) != S_OK) {
			const char**	names;
			int		j;
			fprintf(stderr
			,	"Invalid config info for %s device"
			,	SwitchType);
			fprintf(stderr
			,	"Valid config names are:\n");
			
			names = stonith_get_confignames(s);

			for (j=0; names[j]; ++j) {
				fprintf(stderr
				,	"\t%s\n", names[j]);
			}
			exit(rc);
		}
	}

#endif

	rc = stonith_get_status(s);

	if ((SwitchType = stonith_get_info(s, ST_DEVICEID)) == NULL) {
		SwitchType = "BayTech";
	}

	if (status && !silent) {
		if (rc == S_OK) {
			syslog(LOG_ERR, "%s device OK.", SwitchType);
		}else{
			/* Uh-Oh */
			syslog(LOG_ERR, "%s device not accessible."
			,	SwitchType);
		}
	}

	if (listhosts) {
		char **	hostlist;

		hostlist = stonith_get_hostlist(s);
		if (hostlist == NULL) {
			syslog(LOG_ERR, "Could not list hosts for %s."
			,	SwitchType);
		}else{
			char **	this;

			for(this=hostlist; *this; ++this) {
				printf("%s\n", *this);
			}
			stonith_free_hostlist(hostlist);
		}
	}

	if (optind < argc) {
		char *nodename;
		nodename = strdup(argv[optind]);
		g_strdown(nodename);
		rc = stonith_req_reset(s, ST_GENERIC_RESET, nodename);
		free(nodename);
	}
	stonith_delete(s); s = NULL;
	return(rc);
}
