/* $Id: main.c,v 1.9 2004/02/17 22:12:00 lars Exp $ */
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

#define	OPTIONS	"F:p:t:sSlLvh"

extern char *	optarg;
extern int	optind, opterr, optopt;

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

		if ((cres = s->s_ops->getinfo(s, ST_DEVICEDESCR)) != NULL){
			fprintf(stream, "%s\n"
			,	cres);
		}

		if ((cres = s->s_ops->getinfo(s, ST_DEVICEURL)) != NULL){
			fprintf(stream
			,	"For more information see %s\n"
			,	cres);
		}

		fprintf(stream, "\nConfig info [-p] syntax for %s:\n\t%s\n"
		,    SwitchType, s->s_ops->getinfo(s, ST_CONF_INFO_SYNTAX));
		fprintf(stream, "\nConfig file [-F] syntax for %s:\n\t%s\n"
		,    SwitchType, s->s_ops->getinfo(s, ST_CONF_FILE_SYNTAX));

		stonith_delete(s); s = NULL;
	}
	/* Note that the type list can't/shouldn't be freed */
	
}

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

	if ((cmdname = strrchr(argv[0], '/')) == NULL) {
		cmdname = argv[0];
	}else{
		++cmdname;
	}


	while ((c = getopt(argc, argv, OPTIONS)) != -1) {
		switch(c) {
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
	if (optfile && parameters) {
		++errors;
	}
	argcount = argc - optind;
	if (!(argcount == 1 || (argcount < 1
	&& (status||listhosts||listtypes)))) {
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
		/* Configure the Stonith object from the argument */
		if ((rc=s->s_ops->set_config_info(s, parameters)) != S_OK) {
			syslog(LOG_ERR
			,	"Invalid config info for %s device"
			,	SwitchType);
			syslog(LOG_INFO, "Config info syntax: %s"
			,	s->s_ops->getinfo(s, ST_CONF_INFO_SYNTAX));
			stonith_delete(s); s=NULL;
			exit(rc);
		}
	}

	rc = s->s_ops->status(s);

	if ((SwitchType = s->s_ops->getinfo(s, ST_DEVICEID)) == NULL) {
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

		hostlist = s->s_ops->hostlist(s);
		if (hostlist == NULL) {
			syslog(LOG_ERR, "Could not list hosts for %s."
			,	SwitchType);
		}else{
			char **	this;

			for(this=hostlist; *this; ++this) {
				printf("%s\n", *this);
			}
			s->s_ops->free_hostlist(hostlist);
		}
	}

	if (optind < argc) {
		rc = (s->s_ops->reset_req(s, ST_GENERIC_RESET, argv[optind]));
	}
	stonith_delete(s); s = NULL;
	return(rc);
}
