/* File: lrmadmin.c
 * Description: A adminstration tool for Local Resource Manager
 *
 * Author: Sun Jiang Dong <sunjd@cn.ibm.com>
 * Copyright (c) 2004 International Business Machines
 *
 * Todo: security verification
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <lha_internal.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#ifndef __USE_GNU
#define __USE_GNU
/* For strnlen protype */ 
#include <string.h>
#undef __USE_GNU
#else
#include <string.h>
#endif
#include <errno.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif /* HAVE_GETOPT_H */
#include <clplumbing/cl_log.h>
#include <lrm/lrm_api.h>
#include <lrm/lrm_msg.h>
#include <lrm/raexec.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/GSource.h>
#include <clplumbing/Gmain_timeout.h>

static const char *optstring = "A:D:X:dE:F:dg:p:M:O:P:c:S:LI:CT:n:hv";

#ifdef HAVE_GETOPT_H
static struct option long_options[] = {
	{"daemon",		0, NULL, 'd'},
	{"executera",		1, NULL, 'E'},
	{"flush",		1, NULL, 'F'},
	{"state",		1, NULL, 'S'},
	{"listall",		0, NULL, 'L'},
	{"information",		1, NULL, 'I'},
	{"add",			1, NULL, 'A'},
	{"delete",		1, NULL, 'D'},
	{"fail",		1, NULL, 'X'},
	{"raclass_supported",	1, NULL, 'C'},
	{"ratype_supported",	1, NULL, 'T'},
	{"all_type_metadata",	1, NULL, 'O'},
	{"metadata",		1, NULL, 'M'},
	{"provider",		1, NULL, 'P'},
	{"set_lrmd_param",	1, NULL, 'p'},
	{"get_lrmd_param",	1, NULL, 'g'},
	{"help",		0, NULL, 'h'},
	{"version",		0, NULL, 'v'},
	{NULL,			0, NULL, 0}
};
#endif /* HAVE_GETOPT_H */

static GMainLoop *mainloop;
static const char *lrmadmin_name = "lrmadmin";
static const char *fake_name;
/* 20 is the length limit for a argv[x] */
static const int ARGVI_MAX_LEN = 48;

typedef enum {
	ERROR_OPTION = -1,
	NULL_OP,
 	DAEMON_OP,
	EXECUTE_RA,
	FLUSH,
	RSC_STATE,
	LIST_ALLRSC,
	INF_RSC,
	SET_PARAM,
	GET_PARAM,
	ADD_RSC,
	DEL_RSC,
	FAIL_RSC,
	RACLASS_SUPPORTED,
	RATYPE_SUPPORTED,
	RA_METADATA,
	RA_PROVIDER,
	ALL_RA_METADATA,
	HELP
} lrmadmin_cmd_t;

#define nullcheck(p)       ((p) ? (p) : "<null>")
static const char * status_msg[6] = {
	"pending",		  /* LRM_OP_PENDING	 */
	"succeed", 		  /* LRM_OP_DONE         */
        "cancelled", 		  /* LRM_OP_CANCELLED    */
        "timeout",		  /* LRM_OP_TIMEOUT 	 */
        "not Supported",	  /* LRM_OP_NOTSUPPORTED */
        "failed due to an error"  /* LRM_OP_ERROR	 */
};

static const char * rc_msg[] = {
        "unknown error",
        "no ra",
        "ok",
        "unknown error",
        "invalid parameter",
        "unimplement feature",
        "insufficient priority",
        "not installed",
        "not configured",
        "not running",
        "running master",
        "failed master",
	"invalid rc",
        /* For status command only */
        "daemon dead1",
        "daemon dead2",
        "daemon stopped",
        "status unknow"
};


static gboolean QUIT_GETOPT = FALSE;
static lrmadmin_cmd_t lrmadmin_cmd = NULL_OP;
static gboolean ASYN_OPS = FALSE; 
static int call_id = 0;
static int TIMEOUT = -1; /* the unit is ms */

static const char *simple_help_screen =
"lrmadmin -d,--daemon\n"
"         -A,--add <rscid> <raclass> <ratype> <provider|NULL> [<rsc_params_list>]\n"
"         -D,--delete <rscid>\n"
"         -F,--flush <rscid>\n"
"         -X,--fail <rscid> [<fail_rc> [<fail_reason>]]\n"
"         -E,--execute <rscid> <operator> <timeout> <interval> <target_rc|EVERYTIME|CHANGED> [<operator_parameters_list>]\n"
"         -S,--state <rscid> [-n <fake_name>]\n"
"         -L,--listall\n"
"         -I,--information <rsc_id>\n"
"         -C,--raclass_supported\n"
"         -T,--ratype_supported <raclass>\n"
"         -O,--all metadata of this class <raclass>\n"
"         -M,--metadata <raclass> <ratype> <provider|NULL>\n"
"         -P,--provider <raclass> <ratype>\n"
"         -p,--set_lrmd_param <name> <value>\n"
"         -g,--get_lrmd_param <name>\n"
"         -v,--version\n"
"         -h,--help\n";

#define OPTION_OBSCURE_CHECK \
				if ( lrmadmin_cmd != NULL_OP ) { \
					cl_log(LOG_ERR,"Obscure options."); \
					return -1; \
				}

/* the begin of the internal used function list */
static int resource_operation(ll_lrm_t * lrmd, char *rsc_id,
			      int argc, int optind, char * argv[]);
static int add_resource(ll_lrm_t * lrmd, char *rsc_id,
					int argc, int optind, char * argv[]);
static int fail_resource(ll_lrm_t * lrmd, char *rsc_id, int optc, char *opts[]);
static int get_param(ll_lrm_t * lrmd, int argc, int optind, char * argv[]);
static int set_param(ll_lrm_t * lrmd, int argc, int optind, char * argv[]);
static int transfer_cmd_params(int amount, int start, char * argv[], 
			   const char * class, GHashTable ** params_ht);
static void g_print_stringitem_and_free(gpointer data, gpointer user_data);
static void g_print_rainfo_item_and_free(gpointer data, gpointer user_data);
static void g_print_ops(gpointer data, gpointer user_data);
static void g_get_rsc_description(gpointer data, gpointer user_data);
static void g_print_meta(gpointer key, gpointer value, gpointer user_data);

static void print_rsc_inf(lrm_rsc_t * lrmrsc);
static char * params_hashtable_to_str(const char * class, GHashTable * ht);
static void free_stritem_of_hashtable(gpointer key, gpointer value, 
				      gpointer user_data);
static void ocf_params_hash_to_str(gpointer key, gpointer value, 
				   gpointer user_data);
static void normal_params_hash_to_str(gpointer key, gpointer value, 
				      gpointer user_data);
static lrm_rsc_t * get_lrm_rsc(ll_lrm_t * lrmd, char * rscid);

static int ra_metadata(ll_lrm_t * lrmd, int argc, int optind, char * argv[]);
static int ra_provider(ll_lrm_t * lrmd, int argc, int optind, char * argv[]);
static gboolean lrmd_output_dispatch(IPC_Channel* notused, gpointer user_data);
static gboolean lrm_op_timeout(gpointer data);

/* the end of the internal used function list */

static void lrm_op_done_callback(lrm_op_t* op);

static int ret_value;
int main(int argc, char **argv)
{
	int option_char;
	char rscid_arg_tmp[RID_LEN];
        ll_lrm_t* lrmd;
	lrm_rsc_t * lrm_rsc;
	GList 	*raclass_list = NULL,
		*ratype_list = NULL,
		*rscid_list;
	GHashTable *all_meta = NULL;
	char raclass[20];
	const char * login_name = lrmadmin_name;

	/* Prevent getopt_long to print error message on stderr itself */
	/*opterr = 0; */  
	
	if (argc == 1) {
		printf("%s",simple_help_screen);
		return 0;
	}
	
        cl_log_set_entity(lrmadmin_name);
	cl_log_enable_stderr(TRUE);
	cl_log_set_facility(LOG_USER);

	memset(rscid_arg_tmp, '\0', RID_LEN);
	memset(raclass, '\0', 20);
	do {
#ifdef HAVE_GETOPT_H
		option_char = getopt_long (argc, argv, optstring,
			long_options, NULL);
#else
		option_char = getopt (argc, argv, optstring);
#endif

		if (option_char == -1) {
			break;
		}

		switch (option_char) {
			case 'd':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = DAEMON_OP;
				QUIT_GETOPT = TRUE;
				break;

			case 'A':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = ADD_RSC;
				strncpy(rscid_arg_tmp, optarg, RID_LEN-1);
				break;

			case 'D':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = DEL_RSC;
				strncpy(rscid_arg_tmp, optarg, RID_LEN-1);
				break;

			case 'X':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = FAIL_RSC;
				strncpy(rscid_arg_tmp, optarg, RID_LEN-1);
				break;

			case 'C':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = RACLASS_SUPPORTED;
				break;

			case 'T':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = RATYPE_SUPPORTED;
				if (optarg) {
					strncpy(raclass, optarg, 19);
				}
				break;
			
			case 'O':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = ALL_RA_METADATA;
				if (optarg) {
					strncpy(raclass, optarg, 19);
				}
				break;

			case 'F':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = FLUSH;
				strncpy(rscid_arg_tmp, optarg, RID_LEN-1);
				break;

			case 'E':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = EXECUTE_RA;
				strncpy(rscid_arg_tmp, optarg, RID_LEN-1);
				break;

			case 'M':
				OPTION_OBSCURE_CHECK
				lrmadmin_cmd = RA_METADATA;
				break;
				
			case 'P':
				OPTION_OBSCURE_CHECK
				lrmadmin_cmd = RA_PROVIDER;
				break;

			case 'S':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = RSC_STATE;
				strncpy(rscid_arg_tmp, optarg, RID_LEN-1);
				break;

			case 'L':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = LIST_ALLRSC;
				break;

			case 'I':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = INF_RSC;
				strncpy(rscid_arg_tmp, optarg, RID_LEN-1);
				break;

			case 'p':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = SET_PARAM;
				break;

			case 'g':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = GET_PARAM;
				break;

			case 'n':
				if (optarg) {
					fake_name = optarg;
				}
				break;

			case 'v':
			    printf("%s\n",GLUE_VERSION);
			    return 0;
			case 'h':
				OPTION_OBSCURE_CHECK 
				printf("%s",simple_help_screen);
				return 0;

			case '?':
				/* cl_log(LOG_ERR,"There is a unrecognized 
				   option %s", optarg);
				*/
				printf("%s", simple_help_screen);
				return -1;

			default:
				cl_log(LOG_ERR,"getopt returned character"
					 " code %c.", option_char);
				return -1;
               }
	} while (!QUIT_GETOPT);

        lrmd = ll_lrm_new("lrm");

        if (NULL == lrmd) {
               	cl_log(LOG_ERR,"ll_lrm_new returned NULL.");
               	return -2;
        }

	lrmd->lrm_ops->set_lrm_callback(lrmd, lrm_op_done_callback);

	if (fake_name != NULL) {
		login_name = fake_name;
	}
        if (lrmd->lrm_ops->signon(lrmd, login_name) != 1) { /* != HA_OK */
		printf("lrmd is not running.\n");
		if (lrmadmin_cmd == DAEMON_OP) { 
			return LSB_STATUS_STOPPED;
		} else {
			cl_log(LOG_WARNING,"Can't connect to lrmd!");
			return -2;
		}
	}
	
	if (lrmadmin_cmd == DAEMON_OP) { 
		printf("lrmd is stopped.\n");
		lrmd->lrm_ops->signoff(lrmd);
		return 0;
	}
	
	switch (lrmadmin_cmd) {
		case EXECUTE_RA:
			call_id = resource_operation(lrmd, rscid_arg_tmp, argc, optind, argv);
			if (call_id < 0) {
				if ( call_id == -2 ) {
					cl_log(LOG_ERR, "Failed to operate "
					   "resource %s due to parameter error."
					  , argv[optind]);
					ret_value = -3;
				}
				if ( call_id == -1 ) {
					cl_log(LOG_WARNING, "Failed! No such "
					   "resource %s.", argv[optind]);
					ret_value = -2;
				}
				else {
					cl_log(LOG_ERR, "Failed to operate "
					"resource %s due to unknown error."
					, argv[optind]);
					ret_value = -3;
				}
				ASYN_OPS = FALSE;
			} else { 
				/* Return value: HA_OK = 1 Or  HA_FAIL = 0 */
				if ( call_id == 0 ) {
					cl_log(LOG_ERR, "Resource operation "
					"failed." );
					ret_value = -3;
					ASYN_OPS = FALSE;
				} else { 
					ASYN_OPS = TRUE;
				}
			}
			break;	

		case RA_METADATA:
			ra_metadata(lrmd, argc, optind, argv);
			ASYN_OPS = FALSE;
			break;
		case RA_PROVIDER:
			ra_provider(lrmd, argc, optind, argv);
			ASYN_OPS = FALSE;
			break;

		case SET_PARAM:
			set_param(lrmd, argc, optind, argv);
			ASYN_OPS = FALSE;
			break;

		case GET_PARAM:
			get_param(lrmd, argc, optind, argv);
			ASYN_OPS = FALSE;
			break;

		case ADD_RSC:
			if (add_resource(lrmd, rscid_arg_tmp, argc, optind, argv) == 0) {
				printf("Succeeded in adding this resource.\n");
			} else {
				printf("Failed to add this resource.\n");
				ret_value = -3;
			}
			ASYN_OPS = FALSE;
			break;	

		case DEL_RSC:
			/* Return value: HA_OK = 1 Or  HA_FAIL = 0 */
			if (lrmd->lrm_ops->delete_rsc(lrmd, rscid_arg_tmp)==1) {
				printf("Succeeded in deleting this resource.\n");
			} else {
				printf("Failed to delete this resource.\n");
				ret_value = -3;
			}
			ASYN_OPS = FALSE;
			break;	

		case FAIL_RSC:
			/* Return value: HA_OK = 1 Or  HA_FAIL = 0 */
			if (fail_resource(lrmd, rscid_arg_tmp,
				argc-optind, argv+optind) == 1)
			{
				printf("Succeeded in failing the resource.\n");
			} else {
				printf("Failed to fail the resource.\n");
				ret_value = -3;
			}
			ASYN_OPS = FALSE;
			break;	

		case FLUSH:
			lrm_rsc = get_lrm_rsc(lrmd, rscid_arg_tmp);
			if (!(lrm_rsc)) {
				ret_value = -3;
			} else { 
				/* Return value: HA_OK = 1 Or  HA_FAIL = 0 */
				if (lrm_rsc->ops->flush_ops(lrm_rsc) == 1 ) {
					printf("Succeeded in flushing.\n");
				} else {
					printf("Failed to flush.\n");
					ret_value = -3;
				}
				lrm_free_rsc(lrm_rsc);
			}

			ASYN_OPS = FALSE;
			break;	

		case RACLASS_SUPPORTED:
			raclass_list = lrmd->lrm_ops->
					get_rsc_class_supported(lrmd);
			printf("There are %d RA classes supported:\n", 
					g_list_length(raclass_list));
			if (raclass_list) {
				g_list_foreach(raclass_list, g_print_stringitem_and_free,
						NULL);
				g_list_free(raclass_list);
				ret_value = LSB_EXIT_OK;
			} else {
				printf("No RA classes found!\n");
				ret_value = -3;
			}

			ASYN_OPS = FALSE;
			break;	

		case RATYPE_SUPPORTED:
		     	ratype_list = lrmd->lrm_ops->
				get_rsc_type_supported(lrmd, raclass);
			printf("There are %d RAs:\n", g_list_length(ratype_list));
			if (ratype_list) {
				g_list_foreach(ratype_list, g_print_rainfo_item_and_free,
						NULL);
				g_list_free(ratype_list);
			}

			ASYN_OPS = FALSE;
			break;
		case ALL_RA_METADATA:
			all_meta = lrmd->lrm_ops->get_all_type_metadata(lrmd, raclass);
			if (all_meta) {
				g_hash_table_foreach(all_meta, g_print_meta, NULL);
				g_hash_table_destroy(all_meta);
			}
			ASYN_OPS = FALSE;
			break;
		case LIST_ALLRSC:
			rscid_list = lrmd->lrm_ops->get_all_rscs(lrmd);
			if (rscid_list) {
				g_list_foreach(rscid_list, g_get_rsc_description
						, lrmd);
				g_list_free(rscid_list);
			} else
				printf("Currently no resources are managed by "
					 "LRM.\n");

			ASYN_OPS = FALSE;
			break;	

		case INF_RSC:
			lrm_rsc = get_lrm_rsc(lrmd, rscid_arg_tmp);
			if (!(lrm_rsc)) {
				ret_value = -3;
			} else {
				print_rsc_inf(lrm_rsc);
				lrm_free_rsc(lrm_rsc);
			}

			ASYN_OPS = FALSE;
			break;	

		case RSC_STATE: 
			lrm_rsc = get_lrm_rsc(lrmd, rscid_arg_tmp);
			if (!(lrm_rsc)) {
				ret_value = -3;
			} else { 
				state_flag_t cur_state = LRM_RSC_IDLE;
				GList * ops_queue;
				ops_queue = lrm_rsc->ops->get_cur_state(lrm_rsc, 
								&cur_state);
				printf("resource state:%s\n",
					 cur_state==LRM_RSC_IDLE?
					 "LRM_RSC_IDLE":"LRM_RSC_BUSY");
								
				printf("The resource %d operations' "
					"information:\n"
					, g_list_length(ops_queue));
				if (ops_queue) {
					g_list_foreach(ops_queue,
						       g_print_ops, 
						       NULL);
					lrm_free_op_list(ops_queue);
				}
				lrm_free_rsc(lrm_rsc);
			}

			ASYN_OPS = FALSE;
			break;


		default:
			fprintf(stderr, "Option %c is not supported yet.\n",
				option_char);
			ret_value = -1;
			ASYN_OPS = FALSE;
			break;	
	}

	if (ASYN_OPS) {
        	G_main_add_IPC_Channel(G_PRIORITY_LOW, lrmd->lrm_ops->ipcchan(lrmd),
			FALSE, lrmd_output_dispatch, lrmd, NULL);
		if (TIMEOUT > 0) {
			Gmain_timeout_add(TIMEOUT, lrm_op_timeout, &ret_value);
		}

		mainloop = g_main_new(FALSE);
		printf( "Waiting for lrmd to callback...\n");
        	g_main_run(mainloop);
	}

	lrmd->lrm_ops->signoff(lrmd);
	return ret_value;
}

static gboolean
lrm_op_timeout(gpointer data)
{
	int *	idata = data;

	printf("ERROR: This operation has timed out - no result from lrmd.\n");

	*idata = -5;
	g_main_quit(mainloop);
	return FALSE;
}

static gboolean 
lrmd_output_dispatch(IPC_Channel* notused, gpointer user_data)
{
        ll_lrm_t *lrm = (ll_lrm_t*)user_data;
        lrm->lrm_ops->rcvmsg(lrm, FALSE);

	g_main_quit(mainloop);
        return TRUE;
}

static void
lrm_op_done_callback(lrm_op_t* op)
{
	if (!op) {
		cl_log(LOG_ERR, "In callback function, op is NULL pointer.");
		ret_value = -3;
		return;
	}

	printf("----------------operation--------------\n");
	printf("type:%s\n", op->op_type);
	if ( (0 == STRNCMP_CONST(op->op_type, "status") 
		|| 0 == STRNCMP_CONST(op->op_type, "monitor")) && (op->rc == 7) ) {
		printf("operation status:%s\n", status_msg[LRM_OP_DONE-LRM_OP_PENDING]);
		printf("op_status: %d\n", LRM_OP_DONE);
	} else {
		printf("operation status:%s\n", status_msg[(op->op_status 
			- LRM_OP_PENDING) % DIMOF(status_msg)]);
		printf("op_status: %d\n", op->op_status);
	}
	printf("return code: %d\n", op->rc);
	printf("output data: \n%s\n", (op->output ? op->output : "[null]"));
	printf("---------------------------------------\n\n");
	ret_value = op->rc;	
}

static int 
resource_operation(ll_lrm_t * lrmd, char *rsc_id, int argc, int optind, char * argv[])
{
	GHashTable * params_ht = NULL;
	lrm_op_t op = lrm_zero_op;
	lrm_rsc_t * lrm_rsc;
	int call_id;
	
	if ((argc - optind) < 3) {
		cl_log(LOG_ERR,"Not enough parameters.");
		return -2;
	}

	lrm_rsc = lrmd->lrm_ops->get_rsc(lrmd, rsc_id);	
	if (!lrm_rsc) {
		return -1;
	}

	op.op_type = argv[optind];
	op.timeout = atoi(argv[optind+1]);

 	/* When op.timeout!=0, plus additional 1s. Or lrmadmin may time out before
	   the normal operation result returned from lrmd. This may be redudant, 
	   but harmless. */
	if (0 < op.timeout ) {
		TIMEOUT = op.timeout + 1000;
	}
	op.interval = atoi(argv[optind+2]);
	op.user_data = NULL;
	op.user_data_len = 0;
	if (0 == strcmp(argv[optind+3], "EVERYTIME")) {
		op.target_rc = EVERYTIME;
	}
	else
	if (0 == strcmp(argv[optind+3], "CHANGED")) {
		op.target_rc = CHANGED;
	}
	else {
		op.target_rc = atoi(argv[optind+3]);
	}

	if ((argc - optind) > 3) {
		if (0 > transfer_cmd_params(argc, optind+4, argv, 
				lrm_rsc->class, &params_ht) ) {
			return -2;
		}
	}
	op.params = params_ht;

	call_id = lrm_rsc->ops->perform_op(lrm_rsc, &op);
	lrm_free_rsc(lrm_rsc);
	if (params_ht) {
		g_hash_table_foreach(params_ht, free_stritem_of_hashtable, NULL);
		g_hash_table_destroy(params_ht);
	}
	return call_id;
}
static int
ra_metadata(ll_lrm_t * lrmd, int argc, int optind, char * argv[])
{
	const char * class = argv[optind-1];
	const char * type = argv[optind];
	const char * provider = argv[optind+1];
	char* metadata;

	if(argc < 5) {
		cl_log(LOG_ERR,"Not enough parameters.");
		return -2;
	}

	if (0 == strncmp(provider,"NULL",strlen("NULL"))) {
		provider=NULL;
	}

	metadata = lrmd->lrm_ops->get_rsc_type_metadata(lrmd, class, type, provider);
	if (NULL!=metadata) {
		printf ("%s\n", metadata);
		g_free (metadata);
	}
	return 0;
}

static int
ra_provider(ll_lrm_t * lrmd, int argc, int optind, char * argv[])
{
	const char * class = argv[optind-1];
	const char * type = argv[optind];
	GList* providers = NULL;
	GList* provider = NULL;
	
	if(argc < 4) {
		cl_log(LOG_ERR,"Not enough parameters.");
		return -2;
	}

	providers = lrmd->lrm_ops->get_rsc_provider_supported(lrmd,class,type);
	
	while (NULL != (provider = g_list_first(providers))) {
		printf("%s\n",(char*)provider->data);
		g_free(provider->data);
		providers = g_list_remove(providers, provider->data);
	}
	g_list_free(providers);
	return 0;
}

static int 
add_resource(ll_lrm_t * lrmd, char *rsc_id, int argc, int optind, char * argv[])
{
	const char * class = argv[optind];
	const char * type = argv[optind+1];
	const char * provider = argv[optind+2];
	GHashTable * params_ht = NULL;
	int tmp_ret;

	if ((argc - optind) < 3) {
		cl_log(LOG_ERR,"Not enough parameters.");
		return -2;
	}
	
	if (0 == strncmp(provider, "NULL", strlen("NULL"))) {
		provider=NULL;
	}
	
	/* delete Hashtable */
	if ((argc - optind) > 3) {
		if ( 0 > transfer_cmd_params(argc, optind+3, argv, class,
					&params_ht) ) {
			return -1;
		}
	}

	tmp_ret = lrmd->lrm_ops->add_rsc(lrmd, rsc_id, class, 
						type, provider, params_ht);

	/*delete params_ht*/
	if (params_ht) {
		g_hash_table_foreach(params_ht, free_stritem_of_hashtable, NULL);
		g_hash_table_destroy(params_ht);
	}

	return (tmp_ret ? 0 : -1); /* tmp_ret is HA_OK=1 or HA_FAIL=0 */
}

static int 
fail_resource(ll_lrm_t * lrmd, char *rsc_id, int optc, char *opts[])
{
	int fail_rc = 0;
	const char * reason = NULL;

	if (optc > 2) {
		cl_log(LOG_ERR,"Bad usage.");
		return -2;
	}

	if (optc >= 1)
		fail_rc = atoi(opts[0]);
	if (optc == 2)
		reason = opts[1];

	return lrmd->lrm_ops->fail_rsc(lrmd, rsc_id, fail_rc, reason);
}

static int 
get_param(ll_lrm_t * lrmd, int argc, int optind, char * argv[])
{
	const char *name = argv[optind-1];
	char *value;

	if ((argc - optind) != 0) {
		cl_log(LOG_ERR,"Bad usage.");
		return -2;
	}
	value = lrmd->lrm_ops->get_lrmd_param(lrmd, name);
	printf("%s: %s\n", name, value);
	return 0;
}

static int 
set_param(ll_lrm_t * lrmd, int argc, int optind, char * argv[])
{
	const char *name = argv[optind-1];
	const char *value = argv[optind];

	if ((argc - optind) != 1) {
		cl_log(LOG_ERR,"Bad usage.");
		return -2;
	}
	return lrmd->lrm_ops->set_lrmd_param(lrmd, name, value);
}

static int
transfer_cmd_params(int amount, int start, char * argv[], const char * class, 
GHashTable ** params_ht)
{
	int i, len_tmp;
	char * delimit, * key, * value;
	char buffer[21];

	if (amount < start) {
		return -1;
	}

	if ( strncmp("ocf", class, strlen("ocf"))==0
	    || strncmp("stonith", class, strlen("stonith"))==0) {
		*params_ht = g_hash_table_new(g_str_hash, g_str_equal);

		for (i=start; i<amount; i++) {
			delimit = strchr(argv[i], '=');
			if (!delimit) {
				cl_log(LOG_ERR, "Parameter %s is invalid for "
					"the OCF standard.", argv[i]);
				goto error_return; /* Have to */
			}

			len_tmp = strnlen(delimit+1, MAX_PARAM_LEN) + 1;
			value = g_new(gchar, len_tmp);
			strncpy(value, delimit+1, len_tmp);

			len_tmp = strnlen(argv[i], MAX_PARAM_LEN) - strnlen(delimit, MAX_PARAM_LEN);
			key = g_new(gchar, len_tmp+1);
			key[len_tmp] = '\0';
			strncpy(key, argv[i], len_tmp);
			
			g_hash_table_insert(*params_ht, key, value);
		}
	} else if ( strncmp("lsb", class, strlen("lsb")) == 0
		   || strncmp("heartbeat", class, strlen("heartbeat")) == 0 ) {

		/* Pay attention: for parameter ordring issue */
		*params_ht = g_hash_table_new(g_str_hash, g_str_equal);

		memset(buffer, '0', 21);
		for (i=start; i<amount; i++) {
			snprintf(buffer, 20, "%d", i-start+1);
			g_hash_table_insert( *params_ht, g_strdup(buffer), 
						g_strdup(argv[i]));
			/* printf("index: %d  value: %s \n", i-start+1, argv[i]); */
		}
	} else {
		fprintf(stderr, "Not supported resource agent class.\n");
		return -1;
	}

	return 0;

error_return:
	if (*params_ht) {
		g_hash_table_foreach(*params_ht, free_stritem_of_hashtable, NULL);
		g_hash_table_destroy(*params_ht);
		*params_ht = NULL;
	}
	return -1;
}

static char * 
params_hashtable_to_str(const char * class, GHashTable * ht)
{
	int i,ht_size;
	gchar * params_str = NULL;
	GString * gstr_tmp;
	gchar * tmp_str;

	if (!ht) {
		 return NULL;
	}

	if (   strncmp("ocf", class, strlen("ocf")) == 0 
	    || strncmp("stonith", class, strlen("stonith")) == 0) {
		gstr_tmp = g_string_new("");
		g_hash_table_foreach(ht, ocf_params_hash_to_str, &gstr_tmp);
		params_str = g_new(gchar, gstr_tmp->len+1);		
		strncpy(params_str, gstr_tmp->str, gstr_tmp->len+1);
		g_string_free(gstr_tmp, TRUE);
	} else if (   strncmp("lsb", class, strlen("lsb")) == 0
		   || strncmp("heartbeat", class, strlen("heartbeat")) == 0 ) {
		ht_size = g_hash_table_size(ht);
		if (ht_size == 0) {
			return NULL;
		}
		tmp_str = g_new(gchar, ht_size*ARGVI_MAX_LEN); 	
		memset(tmp_str, ' ', ht_size*ARGVI_MAX_LEN);
		tmp_str[ht_size*ARGVI_MAX_LEN-1] = '\0';
		g_hash_table_foreach(ht, normal_params_hash_to_str, &tmp_str);
		gstr_tmp = g_string_new("");
		for (i=0; i< ht_size; i++) {
			gstr_tmp = g_string_append(gstr_tmp
						, tmp_str + i*ARGVI_MAX_LEN );
			gstr_tmp = g_string_append(gstr_tmp, "  ");
		}
		params_str = g_new(gchar, gstr_tmp->len+1);		
		strncpy(params_str, gstr_tmp->str, gstr_tmp->len+1);
		g_string_free(gstr_tmp, TRUE);
	} else {
		fprintf(stderr, "Not supported resource agent class.\n");
	}

	return params_str;
}

static void
g_print_stringitem_and_free(gpointer data, gpointer user_data)
{
	printf("%s\n", (char*)data);
	g_free(data);
}

static void
g_print_rainfo_item_and_free(gpointer data, gpointer user_data)
{
	printf("%s\n", (char *)data);
	g_free(data);
}


static void
g_print_ops(gpointer data, gpointer user_data)
{
	lrm_op_t* op = (lrm_op_t*)data;
	GString * param_gstr;
	time_t run_at=0, rcchange_at=0;

	if (NULL == op) {
		cl_log(LOG_ERR, "%s:%d: op==NULL"
			, __FUNCTION__, __LINE__);
		return;
	}

	param_gstr = g_string_new("");
	g_hash_table_foreach(op->params, ocf_params_hash_to_str, &param_gstr);

	if( op->t_run )
		run_at=(time_t)op->t_run;
	if( op->t_rcchange )
		rcchange_at=(time_t)op->t_rcchange;
	printf("   operation '%s' [call_id=%d]:\n"
	       "      start_delay=%d, interval=%d, timeout=%d, app_name=%s\n"
	       "      rc=%d (%s), op_status=%d (%s)\n"
		, nullcheck(op->op_type), op->call_id
		, op->start_delay, op->interval, op->timeout
		, nullcheck(op->app_name), op->rc
		, rc_msg[(op->rc-EXECRA_EXEC_UNKNOWN_ERROR) % DIMOF(rc_msg)]
		, op->op_status
		, status_msg[(op->op_status-LRM_OP_PENDING) % DIMOF(status_msg)]
	);
	if( op->t_run || op->t_rcchange )
		printf("      run at: %s"
			   "      last rc change at: %s"
			   "      queue time: %lums, exec time: %lums\n"
			, op->t_run ? ctime(&run_at) : "N/A\n"
			, op->t_rcchange ? ctime(&rcchange_at) : "N/A\n"
			, op->queue_time, op->exec_time
		);
	printf("      parameters: %s\n", param_gstr->str);
	g_string_free(param_gstr, TRUE);
}

static void
g_get_rsc_description(gpointer data, gpointer user_data)
{
	ll_lrm_t* lrmd = (ll_lrm_t *)user_data;
	lrm_rsc_t * lrm_rsc;
	char rsc_id_tmp[RID_LEN];
	
	if (!(user_data)) {
		return;
	}

	memset(rsc_id_tmp, '\0', RID_LEN);
	strncpy(rsc_id_tmp, data, RID_LEN-1);

	lrm_rsc = lrmd->lrm_ops->get_rsc(lrmd, rsc_id_tmp);
	if (lrm_rsc) {
		print_rsc_inf(lrm_rsc);
		lrm_free_rsc(lrm_rsc); 
	} else
		cl_log(LOG_ERR, "Invalid resource id: %s.", 
			rsc_id_tmp);
	
	g_free(data);
}
static void
g_print_meta(gpointer key, gpointer value, gpointer user_data)
{
	printf("%s\n", (const char*)key);
	printf("%s\n", (const char*)value);
}
static void
print_rsc_inf(lrm_rsc_t * lrm_rsc)
{
	char rscid_str_tmp[RID_LEN];
	char * tmp = NULL;

	if (!lrm_rsc) {
		return;
	}

	rscid_str_tmp[RID_LEN-1] = '\0';
	strncpy(rscid_str_tmp, lrm_rsc->id, RID_LEN-1);
	printf("\nResource ID:%s\n", rscid_str_tmp);
	printf("Resource agent class:%s\n", lrm_rsc->class);
	printf("Resource agent type:%s\n", lrm_rsc->type);
	printf("Resource agent provider:%s\n"
		, lrm_rsc->provider?lrm_rsc->provider:"default");

	if (lrm_rsc->params) {
		tmp = params_hashtable_to_str(lrm_rsc->class, 
				lrm_rsc->params);
		printf("Resource agent parameters:%s\n"
			, (tmp == NULL) ? "No parameter" : tmp);
		if (tmp != NULL) {
			 g_free(tmp);
		}
	}
}

static void
free_stritem_of_hashtable(gpointer key, gpointer value, gpointer user_data)
{
	/*printf("key=%s   value=%s\n", (char *)key, (char *)value);*/
	g_free(key);
	g_free(value);
}

static void
ocf_params_hash_to_str(gpointer key, gpointer value, gpointer user_data)
{
	GString * gstr_tmp = *(GString **)user_data;
	gstr_tmp = g_string_append(gstr_tmp, (char*)key);
	gstr_tmp = g_string_append(gstr_tmp, "=");
	gstr_tmp = g_string_append(gstr_tmp, (char *)value);
	gstr_tmp = g_string_append(gstr_tmp, "  ");
}

static void
normal_params_hash_to_str(gpointer key, gpointer value, gpointer user_data)
{
	gint key_int;

	gchar * str_tmp = *(gchar **) user_data;
	if (str_tmp == NULL ) {
		return;
	}

	key_int = atoi((char *)key) - 1;
	if( key_int < 0 ) {
		return;
	}
	strncpy(str_tmp + key_int * ARGVI_MAX_LEN, (char*)value,
		ARGVI_MAX_LEN - 1);
}

static lrm_rsc_t * 
get_lrm_rsc(ll_lrm_t * lrmd, char * rscid)
{
	char uuid_str_tmp[RID_LEN];
	lrm_rsc_t * lrm_rsc;
	lrm_rsc = lrmd->lrm_ops->get_rsc(lrmd, rscid);
	if (!(lrm_rsc)) {
		uuid_str_tmp[RID_LEN-1] = '\0';
		strncpy(uuid_str_tmp, rscid, RID_LEN-1);
		cl_log(LOG_ERR,"Resource %s does not exist.", uuid_str_tmp);
	}
	return lrm_rsc;
}

