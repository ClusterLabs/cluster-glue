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

#include <lha_internal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <stonith/stonith.h>
#include <pils/plugin.h>
#include <clplumbing/cl_log.h>
#include <glib.h>
#include <libxml/entities.h>

#define	OPTIONS	"c:F:p:t:T:EsnSlLmvhVd"
#define	EQUAL	'='

extern char *	optarg;
extern int	optind, opterr, optopt;

static int	debug = 0;

#define LOG_TERMINAL 0
#define LOG_CLLOG 1
static int	log_destination = LOG_TERMINAL;

static const char META_TEMPLATE[] =
"<?xml version=\"1.0\"?>\n"
"<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"
"<resource-agent name=\"%s\">\n"
"<version>1.0</version>\n"
"<longdesc lang=\"en\">\n"
"%s\n"
"</longdesc>\n"	
"<shortdesc lang=\"en\">%s</shortdesc>\n"
"%s\n"
"<actions>\n"
"<action name=\"start\"   timeout=\"20\" />\n"
"<action name=\"stop\"    timeout=\"15\" />\n"
"<action name=\"status\"  timeout=\"20\" />\n"
"<action name=\"monitor\" timeout=\"20\" interval=\"3600\" />\n"
"<action name=\"meta-data\"  timeout=\"15\" />\n"
"</actions>\n"
"<special tag=\"heartbeat\">\n"
"<version>2.0</version>\n"
"</special>\n"
"</resource-agent>\n";

void version(void);
void usage(const char * cmd, int exit_status, const char * devtype);
void confhelp(const char * cmd, FILE* stream, const char * devtype);
void print_stonith_meta(Stonith * stonith_obj, const char *rsc_type);
void print_types(void);
void print_confignames(Stonith *s);

void log_buf(int severity, char *buf);
void log_msg(int severity, const char * fmt, ...)G_GNUC_PRINTF(2,3);
void trans_log(int priority, const char * fmt, ...)G_GNUC_PRINTF(2,3);

static int pil_loglevel_to_syslog_severity[] = {
	/* Indices: <none>=0, PIL_FATAL=1, PIL_CRIT=2, PIL_WARN=3,
	   PIL_INFO=4, PIL_DEBUG=5 
	*/
	LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_WARNING, LOG_INFO, LOG_DEBUG
	};

/*
 * Note that we don't use the cl_log logging code because the STONITH
 * command is intended to be shipped without the clplumbing libraries.
 *
 *	:-(
 *
 * The stonith command has so far always been shipped along with
 * the clplumbing library, so we'll use cl_log
 * If that ever changes, we'll use something else
 */

void
version()
{
	printf("stonith: %s (%s)\n", GLUE_VERSION, GLUE_BUILD_VERSION);
	exit(0);
}

void
usage(const char * cmd, int exit_status, const char * devtype)
{
	FILE *stream;

	stream = exit_status ? stderr : stdout;

	/* non-NULL devtype indicates help for specific device, so no usage */
	if (devtype == NULL) {
		fprintf(stream, "usage:\n");
		fprintf(stream, "\t %s [-svh] "
		"-L\n"
		, cmd);

		fprintf(stream, "\t %s [-svh] "
		"-t stonith-device-type "
		"-n\n"
		, cmd);

		fprintf(stream, "\t %s [-svh] "
		"-t stonith-device-type "
		"-m\n"
		, cmd);

		fprintf(stream, "\t %s [-svh] "
		"-t stonith-device-type "
		"{-p stonith-device-parameters | "
		"-F stonith-device-parameters-file | "
		"-E | "
		"name=value...} "
		"[-c count] "
		"-lS\n"
		, cmd);

		fprintf(stream, "\t %s [-svh] "
		"-t stonith-device-type "
		"{-p stonith-device-parameters | "
		"-F stonith-device-parameters-file | "
		"-E | "
		"name=value...} "
		"[-c count] "
		"-T {reset|on|off} nodename\n"
		, cmd);

		fprintf(stream, "\nwhere:\n");
		fprintf(stream, "\t-L\tlist supported stonith device types\n");
		fprintf(stream, "\t-l\tlist hosts controlled by this stonith device\n");
		fprintf(stream, "\t-S\treport stonith device status\n");
		fprintf(stream, "\t-s\tsilent\n");
		fprintf(stream, "\t-v\tverbose\n");
		fprintf(stream, "\t-n\toutput the config names of stonith-device-parameters\n");
		fprintf(stream, "\t-m\tdisplay meta-data of the stonith device type\n");
		fprintf(stream, "\t-h\tdisplay detailed help message with stonith device description(s)\n");
	}

	if (exit_status == 0) {
		confhelp(cmd, stream, devtype);
	}

	exit(exit_status);
}

/* Thanks to Lorn Kay <lorn_kay@hotmail.com> for the confhelp code */
void
confhelp(const char * cmd, FILE* stream, const char * devtype)
{
	char ** typelist;
	char ** this;
	Stonith *       s;
	int	devfound = 0;

	
	/* non-NULL devtype indicates help for specific device, so no header */
	if (devtype == NULL) {
		fprintf(stream
		,	"\nSTONITH -t device types and"
			" associated configuration details:\n");
	}

	typelist = stonith_types();
	
	if (typelist == NULL) {
		fprintf(stderr, 
			"Failed to retrieve list of STONITH modules!\n");
		return;
	}
	for(this=typelist; *this && !devfound; ++this) {
		const char *    SwitchType = *this;
		const char *	cres;
		const char * const *	pnames;


		if ((s = stonith_new(SwitchType)) == NULL) {
			fprintf(stderr, "Invalid STONITH type %s(!)\n"
			,	SwitchType);
			continue;
		}

		if (devtype) {
			if (strcmp(devtype, SwitchType)) {
				continue;
			} else {
				devfound = 1;
			}
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
		if (NULL == (pnames = stonith_get_confignames(s))) {
			continue;
		}
		fprintf(stream
		,	"List of valid parameter names for %s STONITH device:\n"
		,	SwitchType);
		for (;*pnames; ++pnames) {
			fprintf(stream
			,	"\t%s\n", *pnames);
		}

#ifdef ST_CONFI_INFO_SYNTAX
		fprintf(stream, "\nConfig info [-p] syntax for %s:\n\t%s\n"
		,    SwitchType, stonith_get_info(s, ST_CONF_INFO_SYNTAX));
#else
		fprintf(stream, "For Config info [-p] syntax"
		", give each of the above parameters in order as"
		"\nthe -p value.\n"
		"Arguments are separated by white space.");
#endif
#ifdef ST_CONFI_FILE_SYNTAX
		fprintf(stream, "\nConfig file [-F] syntax for %s:\n\t%s\n"
		,    SwitchType, stonith->get_info(s, ST_CONF_FILE_SYNTAX));
#else
		fprintf(stream
		,	"\nConfig file [-F] syntax is the same as -p"
		", except # at the start of a line"
		"\ndenotes a comment\n");
#endif

		stonith_delete(s); s = NULL;
	}
	/* Note that the type list can't/shouldn't be freed */
	if (devtype && !devfound) {
		fprintf(stderr, "Invalid device type: '%s'\n", devtype);
	}
	
}

void
print_stonith_meta(Stonith * stonith_obj, const char *rsc_type)
{
	const char * meta_param = NULL;
	const char * meta_longdesc = NULL;
	const char * meta_shortdesc = NULL;
	char *xml_meta_longdesc = NULL;
	char *xml_meta_shortdesc = NULL;
	static const char * no_parameter_info = "<!-- no value -->";

	meta_longdesc = stonith_get_info(stonith_obj, ST_DEVICEDESCR);
	if (meta_longdesc == NULL) {
	    fprintf(stderr, "stonithRA plugin: no long description");
	    meta_longdesc = no_parameter_info;
	}
	xml_meta_longdesc = (char *)xmlEncodeEntitiesReentrant(NULL, (const unsigned char *)meta_longdesc);

	meta_shortdesc = stonith_get_info(stonith_obj, ST_DEVICEID);
	if (meta_shortdesc == NULL) {
	    fprintf(stderr, "stonithRA plugin: no short description");
	    meta_shortdesc = no_parameter_info;
	}
	xml_meta_shortdesc = (char *)xmlEncodeEntitiesReentrant(NULL, (const unsigned char *)meta_shortdesc);
	
	meta_param = stonith_get_info(stonith_obj, ST_CONF_XML);
	if (meta_param == NULL) {
	    fprintf(stderr, "stonithRA plugin: no list of parameters");
	    meta_param = no_parameter_info;
	}
	
	printf(META_TEMPLATE,
		 rsc_type, xml_meta_longdesc, xml_meta_shortdesc, meta_param);

	xmlFree(xml_meta_longdesc);
	xmlFree(xml_meta_shortdesc);
}

#define	MAXNVARG	50

void
print_types()
{
	char **	typelist;

	typelist = stonith_types();
	if (typelist == NULL) {
		log_msg(LOG_ERR, "Could not list Stonith types.");
	}else{
		char **	this;

		for(this=typelist; *this; ++this) {
			printf("%s\n", *this);
		}
	}
}

void
print_confignames(Stonith *s)
{
	const char * const *	names;
	int		i;

	names = stonith_get_confignames(s);

	if (names != NULL) {
		for (i=0; names[i]; ++i) {
			printf("%s  ", names[i]);
		}
	}
	printf("\n");
}

void
log_buf(int severity, char *buf)
{
	if (severity == LOG_DEBUG && !debug)
		return;
	if (log_destination == LOG_TERMINAL) {
		fprintf(stderr, "%s: %s\n", prio2str(severity),buf);
	} else {
		cl_log(severity, "%s", buf);
	}
}

void
log_msg(int severity, const char * fmt, ...)
{
	va_list         ap;
	char            buf[MAXLINE];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf)-1, fmt, ap);
	va_end(ap);
	log_buf(severity, buf);
}

void
trans_log(int priority, const char * fmt, ...)
{
	int				severity;
	va_list         ap;
	char            buf[MAXLINE];

	severity = pil_loglevel_to_syslog_severity[ priority % sizeof
		(pil_loglevel_to_syslog_severity) ];
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf)-1, fmt, ap);
	va_end(ap);
	log_buf(severity, buf);
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
	int		reset_type = ST_GENERIC_RESET;
	int		verbose = 0;
	int		status = 0;
	int		silent = 0;
	int		listhosts = 0;
	int		listtypes = 0;
	int 		listparanames = 0;
	int 		params_from_env = 0;

	int		c;
	int		errors = 0;
	int		argcount;
	StonithNVpair	nvargs[MAXNVARG];
	int		nvcount=0;
	int		j;
	int		count = 1;
	int		help = 0;
	int		metadata = 0;

	/* The bladehpi stonith plugin makes use of openhpi which is
	 * threaded.  The mix of memory allocation without thread
	 * initialization followed by g_thread_init followed by
	 * deallocating that memory results in segfault.  Hence the
	 * following G_SLICE setting; see
	 * http://library.gnome.org/devel/glib/stable/glib-Memory-Slices.html#g-slice-alloc
	 */

	setenv("G_SLICE", "always-malloc", 1);

	if ((cmdname = strrchr(argv[0], '/')) == NULL) {
		cmdname = argv[0];
	}else{
		++cmdname;
	}


	while ((c = getopt(argc, argv, OPTIONS)) != -1) {
		switch(c) {

		case 'c':	count = atoi(optarg);
				if (count < 1) {
					fprintf(stderr
					,	"bad count [%s]\n"
					,	optarg);
					usage(cmdname, 1, NULL);
				}
				break;

		case 'd':	debug++;
				break;

		case 'F':	optfile = optarg;
				break;

		case 'E':	params_from_env = 1;
				break;

		case 'h':	help++;
				break;

		case 'm':	metadata++;
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

		case 'T':	if (strcmp(optarg, "on")== 0) {
					reset_type = ST_POWERON;
				}else if (strcmp(optarg, "off")== 0) {
					reset_type = ST_POWEROFF;
				}else if (strcmp(optarg, "reset")== 0) {
					reset_type = ST_GENERIC_RESET;
				}else{
					fprintf(stderr
					,	"bad reset type [%s]\n"
					,	optarg);
					usage(cmdname, 1, NULL);
				}
				break;

		case 'n':	++listparanames;
				break;

		case 'v':	++verbose;
				break;

		case 'V':	version();
				break;

		default:	++errors;
				break;
		}
	}

	/* if we're invoked by stonithd, log through cl_log */
	if (!isatty(fileno(stdin))) {
		log_destination = LOG_CLLOG;
		cl_log_set_entity("stonith");
		cl_log_enable_stderr(debug?TRUE:FALSE);
		cl_log_set_facility(HA_LOG_FACILITY);

		/* Use logd if it's enabled by heartbeat */
		cl_inherit_logging_environment(0);
	}

	if (help && !errors) {
		usage(cmdname, 0, SwitchType);
	}
	if (debug) {
		PILpisysSetDebugLevel(debug);
		setenv("HA_debug","2",0);
	}
	if ((optfile && parameters) || (optfile && params_from_env)
			|| (params_from_env && parameters)) {
		fprintf(stderr
		,	"Please use just one of -F, -p, and -E options\n");
		usage(cmdname, 1, NULL);
	}

	/*
	 *	Process name=value arguments on command line...
	 */
	for (;optind < argc; ++optind) {
		char *	eqpos;
		if ((eqpos=strchr(argv[optind], EQUAL)) == NULL) {
			break;
		}
		if (parameters || optfile || params_from_env)  {
			fprintf(stderr
			,	"Cannot mix name=value and -p, -F, or -E "
			"style arguments\n");
			usage(cmdname, 1, NULL);
		}
		if (nvcount >= MAXNVARG) {
			fprintf(stderr
			,	"Too many name=value style arguments\n");
			exit(1);
		}
		nvargs[nvcount].s_name = argv[optind];
		*eqpos = EOS;
		nvargs[nvcount].s_value = eqpos+1;
		nvcount++;
	}
	nvargs[nvcount].s_name = NULL;
	nvargs[nvcount].s_value = NULL;

	argcount = argc - optind;

	if (!(argcount == 1 || (argcount < 1
	&&	(status||listhosts||listtypes||listparanames||metadata)))) {
		++errors;
	}

	if (errors) {
		usage(cmdname, 1, NULL);
	}

	if (listtypes) {
		print_types();
		exit(0);
	}

	if (SwitchType == NULL) {
		log_msg(LOG_ERR,"Must specify device type (-t option)");
		usage(cmdname, 1, NULL);
	}
	s = stonith_new(SwitchType);
	if (s == NULL) {
		log_msg(LOG_ERR,"Invalid device type: '%s'", SwitchType);
		exit(S_OOPS);
	}
	if (debug) {
		stonith_set_debug(s, debug);
	}
	stonith_set_log(s, (PILLogFun)trans_log);

	if (!listparanames && !metadata && optfile == NULL &&
			parameters == NULL && !params_from_env && nvcount == 0) {
		const char * const *	names;
		int		needs_parms = 1;

		if (s != NULL && (names = stonith_get_confignames(s)) != NULL && names[0] == NULL) {
			needs_parms = 0;
		}

		if (needs_parms) {
			fprintf(stderr
			,	"Must specify either -p option, -F option, -E option, or "
			"name=value style arguments\n");
			if (s != NULL) {
				stonith_delete(s); 
			}
			usage(cmdname, 1, NULL);
		}
	}

	if (listparanames) {
		print_confignames(s);
		stonith_delete(s); 
		s=NULL;
		exit(0);
	}

	if (metadata) {
		print_stonith_meta(s,SwitchType);
		stonith_delete(s); 
		s=NULL;
		exit(0);
	}

	/* Old STONITH version 1 stuff... */
	if (optfile) {
		/* Configure the Stonith object from a file */
		if ((rc=stonith_set_config_file(s, optfile)) != S_OK) {
			log_msg(LOG_ERR
			,	"Invalid config file for %s device."
			,	SwitchType);
#if 0
			log_msg(LOG_INFO, "Config file syntax: %s"
			,	s->s_ops->getinfo(s, ST_CONF_FILE_SYNTAX));
#endif
			stonith_delete(s); s=NULL;
			exit(S_BADCONFIG);
		}
	}else if (params_from_env) {
		/* Configure Stonith object from the environment */
		StonithNVpair *		pairs;
		if ((pairs = stonith_env_to_NVpair(s)) == NULL) {
			fprintf(stderr
			,	"Invalid config info for %s device.\n"
			,	SwitchType);
			stonith_delete(s); s=NULL;
			exit(1);
		}
		if ((rc = stonith_set_config(s, pairs)) != S_OK) {
			fprintf(stderr
			,	"Invalid config info for %s device\n"
			,	SwitchType);
		}
	}else if (parameters) {
		/* Configure Stonith object from the -p argument */
		StonithNVpair *		pairs;
		if ((pairs = stonith1_compat_string_to_NVpair
		     (	s, parameters)) == NULL) {
			fprintf(stderr
			,	"Invalid STONITH -p parameter [%s]\n"
			,	parameters);
			stonith_delete(s); s=NULL;
			exit(1);
		}
		if ((rc = stonith_set_config(s, pairs)) != S_OK) {
			fprintf(stderr
			,	"Invalid config info for %s device\n"
			,	SwitchType);
		}
	}else{
		/*
		 *	Configure STONITH device using cmdline arguments...
		 */
		if ((rc = stonith_set_config(s, nvargs)) != S_OK) {
			const char * const *	names;
			int		j;
			fprintf(stderr
			,	"Invalid config info for %s device\n"
			,	SwitchType);

			names = stonith_get_confignames(s);

			if (names != NULL) {
				fprintf(stderr
				,	"Valid config names are:\n");
			
				for (j=0; names[j]; ++j) {
					fprintf(stderr
					,	"\t%s\n", names[j]);
				}
			}
			stonith_delete(s); s=NULL;
			exit(rc);
		}
	}


	for (j=0; j < count; ++j) {
		rc = S_OK;

		if (status) {
			rc = stonith_get_status(s);

			if (!silent) {
				if (rc == S_OK) {
					log_msg((log_destination == LOG_TERMINAL) ?
					LOG_INFO : LOG_DEBUG,
					"%s device OK.", SwitchType);
				}else{
					/* Uh-Oh */
					log_msg(LOG_ERR, "%s device not accessible."
					,	SwitchType);
				}
			}
		}

		if (listhosts) {
			char **	hostlist;

			hostlist = stonith_get_hostlist(s);
			if (hostlist == NULL) {
				log_msg(LOG_ERR, "Could not list hosts for %s."
				,	SwitchType);
				rc = -1;
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
			nodename = g_strdup(argv[optind]);
			strdown(nodename);
			rc = stonith_req_reset(s, reset_type, nodename);
			g_free(nodename);
		}
	}
	stonith_delete(s); s = NULL;
	return(rc);
}
