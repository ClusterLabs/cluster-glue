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
#include <portability.h>

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
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
#include <uuid/uuid.h>
#include <uuid/uuid.h>
#include <clplumbing/cl_log.h>
#include <lrm/lrm_api.h>
#include <lrm/raexec.h>
#include <clplumbing/lsb_exitcodes.h>

const char * optstring = "AD:dEF:d:Msg:c:S:LI:CT:h";

static struct option long_options[] = {
	{"daemon", 0, 0, 'd'},
	{"executera", 1, 0, 'E'},
	{"flush",1,0,'F'},
	{"monitor",0,0,'M'},
	{"status",1,0,'S'},
	{"listall",0,0,'L'},
	{"information",1,0,'I'},
	{"add",1,0,'A'},
	{"delete",1,0,'D'},
	{"raclass_supported",1,0,'C'},
	{"ratype_supported",1,0,'T'},
	{"help",0,0,'h'},
	{0,0,0,0}
};

GMainLoop *mainloop = NULL;
const char * lrmadmin_name = "lrmadmin";
/* 20 is the length limit for a argv[x] */
const int ARGVI_MAX_LEN = 20;

typedef enum {
	ERROR_OPTION = -1,
	NULL_OP,
 	DAEMON_OP,
	EXECUTE_RA,
	FLUSH,
	MONITOR,
	MONITOR_SET,
	MONITOR_GET,
	MONITOR_CLS,
	RSC_STATUS,
	LIST_ALLRSC,
	INF_RSC,
	ADD_RSC,
	DEL_RSC,
	RACLASS_SUPPORTED,
	RATYPE_SUPPORTED,
	HELP
} lrmadmin_cmd_t;

static const char * status_msg[5] = {
	"Succeed", 		  /* LRM_OP_DONE         */
        "Cancelled", 		  /* LRM_OP_CANCELLED    */
        "Timeout",		  /* LRM_OP_TIMEOUT 	 */
        "Not Supported",	  /* LRM_OP_NOTSUPPORTED */
        "Failed Due to a Error"   /* LRM_OP_ERROR	 */
};

static gboolean QUIT_GETOPT = FALSE;
static lrmadmin_cmd_t lrmadmin_cmd = NULL_OP;
static gboolean ASYN_OPS = FALSE; 
static int call_id = 0;

const char * simple_help_screen =
"lrmadmin {-d|--deamon}\n"
"         {-A|--add} <rscid> <raclass> <ratype> [<rsc_params_list>]\n"
"         {-D|--delete} <rscid>\n"
"         {-F|--flush} <rscid>\n"
"         {-E|--execute} <rscid> <operator> <timeout> [<operator_parameters_"
"list>]\n"\
"         {-M|--monitor} -s <rscid> <operator> <timeout> <interval> "
"[<operator_parameters_list>]\n"
"         {-M|--monitor} {-g|-c} <rscid>\n"
"         {-S|--status} <rscid>\n"
"         {-L|--listall}\n"
"         {-I|--information} <rsc_id>\n"
"         {-C|--raclass_supported}\n"
"         {-T|--ratype_supported} <raclss>\n"
"         {-h|--help}\n";

#define OPTION_OBSCURE_CHECK \
				if ( lrmadmin_cmd != NULL_OP ) { \
					cl_log(LOG_ERR,"Obscure options."); \
					return -1; \
				}

/* the begin of the internal used function list */
static int resource_operation(ll_lrm_t * lrmd, int argc, int optind, 
			      char * argv[]);
static int add_resource(ll_lrm_t * lrmd, int argc, int optind, char * argv[]);
static int transfer_cmd_params(int amount, int start, char * argv[], 
			   const char * class, GHashTable ** params_ht);
static void g_print_stringitem(gpointer data, gpointer user_data);
static void g_print_rainfo_item(gpointer data, gpointer user_data);
static void g_print_ops(gpointer data, gpointer user_data);
static void g_get_rsc_description(gpointer data, gpointer user_data);
static void print_rsc_inf(lrm_rsc_t * lrmrsc);
static char * params_hashtable_to_str(const char * class, GHashTable * ht);
static void free_stritem_of_hashtable(gpointer key, gpointer value, 
				      gpointer user_data);
static void ocf_params_hash_to_str(gpointer key, gpointer value, 
				   gpointer user_data);
static void normal_params_hash_to_str(gpointer key, gpointer value, 
				      gpointer user_data);
static lrm_rsc_t * get_lrm_rsc(ll_lrm_t * lrmd, rsc_id_t rscid);
static void g_print_monitor(gpointer lrm_mon, gpointer user_data);
static int set_monitor(ll_lrm_t * lrmd, int argc, int optind, char * argv[]);
/* the end of the internal used function list */

static void lrm_op_done_callback(lrm_op_t* op);
static void lrm_monitor_callback(lrm_mon_t* mon);

static gboolean post_query_call_result(gpointer data);

int main(int argc, char **argv)
{
	int option_char;
	rsc_id_t rscid_arg_tmp;
	int ret_value = 0; 
        ll_lrm_t* lrmd;
	lrm_rsc_t * lrm_rsc;
	GList 	*raclass_list = 0, 
		*ratype_list = 0,
		*rscid_list;
	char raclass[20];

	/* Prevent getopt_long to print error message on stderr isself */
	/*opterr = 0; */  
	
	if (argc == 1) {
		printf("%s",simple_help_screen);
		return 0;
	}
	
        cl_log_set_entity(lrmadmin_name);
	cl_log_enable_stderr(TRUE);
	cl_log_set_facility(LOG_USER);

	memset(rscid_arg_tmp, '\0', sizeof(rsc_id_t));
	do {
		option_char = getopt_long (argc, argv, optstring,
			long_options, NULL);

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
				break;

			case 'D':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = DEL_RSC;
				if (optarg) {
					uuid_parse(optarg, rscid_arg_tmp);
				}
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

			case 'F':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = FLUSH;
				if (optarg) {
					uuid_parse(optarg, rscid_arg_tmp);
				}
				break;

			case 'E':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = EXECUTE_RA;
				break;

			case 'M':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = MONITOR;
				break;

			case 's':
				if (lrmadmin_cmd != MONITOR) {
					cl_log(LOG_ERR,"Option error.");
					return -1;
				}
				lrmadmin_cmd = MONITOR_SET;
				break;

			case 'g':
				if (lrmadmin_cmd != MONITOR) {
					cl_log(LOG_ERR,"Option error.");
					return -1;
				}
				lrmadmin_cmd = MONITOR_GET;
				if (optarg) {
					uuid_parse(optarg, rscid_arg_tmp);
				}
				break;

			case 'c':
				if (lrmadmin_cmd != MONITOR) {
					cl_log(LOG_ERR,"Option error.");
					return -1;
				}
				lrmadmin_cmd = MONITOR_CLS;
				if (optarg) {
					uuid_parse(optarg, rscid_arg_tmp);
				}
				break;

			case 'S':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = RSC_STATUS;
				if (optarg) {
					uuid_parse(optarg, rscid_arg_tmp);
				}
				break;

			case 'L':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = LIST_ALLRSC;
				break;

			case 'I':
				OPTION_OBSCURE_CHECK 
				if (optarg) {
					uuid_parse(optarg, rscid_arg_tmp);
				}
				lrmadmin_cmd = INF_RSC;
				break;

			case 'h':
				OPTION_OBSCURE_CHECK 
				/* print detailed help screen? */
				printf("%s",simple_help_screen);
				return 0;

			case '?':
				/* cl_log(LOG_ERR,"There is a unrecognized 
				   option %s", optarg);
				*/
				printf("%s", simple_help_screen);
				return -1;

			default:
				cl_log(LOG_ERR,"Error:getopt returned character"\
					 " code %c.", option_char);
				return -1;
               }
	} while (!QUIT_GETOPT);

        lrmd = ll_lrm_new("lrm");

        if (NULL == lrmd) {
               	cl_log(LOG_ERR,"ll_lrn_new return null.");
               	return -2;
        }

        if (lrmd->lrm_ops->signon(lrmd, lrmadmin_name) != 1) { /* != HA_OK */
		if (lrmadmin_cmd == DAEMON_OP) { 
			printf("lrmd daemon is not running.\n");
			return 0;
		} else {
			cl_log(LOG_ERR,"Can't connect to lrmd, quit!");
			return -2;
		}
	}
	
	if (lrmadmin_cmd == DAEMON_OP) { 
		printf("lrmd daemon is running.\n");
		lrmd->lrm_ops->signoff(lrmd);
		return 0;
	}
	
	switch (lrmadmin_cmd) {
		case EXECUTE_RA:
			call_id = resource_operation(lrmd, argc, optind, argv);
			if (call_id < 0) {
				if ( call_id == -2 ) {
					cl_log(LOG_ERR, "Failed to operate "\
					   "resource %s due to parameter error."
					  , argv[optind]);
					ret_value = -3;
				}
				if ( call_id == -1 ) {
					cl_log(LOG_ERR, "Failed! no this "\
					   "resource %s.", argv[optind]);
					ret_value = -2;
				}
				cl_log(LOG_ERR, "Failed to operate "\
				   "resource %s due to unknown error."
				  , argv[optind]);
				ret_value = -3;
				ASYN_OPS = FALSE;
			} else { 
				/* Return value: HA_OK = 1 Or  HA_FAIL = 0 */
				if ( call_id == 0 ) {
					cl_log(LOG_ERR, "Resource operation "\
					"Failed." );
					ret_value = -3;
					ASYN_OPS = FALSE;
				} else { 
					ASYN_OPS = TRUE;
				}
			}
			break;	

		case ADD_RSC:
			if (add_resource(lrmd, argc, optind, argv) == 0) {
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
				printf("Succeeded in delete this resource.\n");
			} else {
				printf("Failed to delete this resource.\n");
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
					printf("Falied to flush.\n");
					ret_value = -3;
				}
			}

			ASYN_OPS = FALSE;
			break;	

		case RACLASS_SUPPORTED:
			raclass_list = lrmd->lrm_ops->
					get_rsc_class_supported(lrmd);
			printf("Support %d RA classes\n", 
					g_list_length(raclass_list));
			if (raclass_list) {
				g_list_foreach(raclass_list, g_print_stringitem,
						NULL);
				g_list_free(raclass_list);
			} else {
				printf("No any RA class is supported\n");
			}

			ASYN_OPS = FALSE;
			break;	

		case RATYPE_SUPPORTED:
		     	ratype_list = lrmd->lrm_ops->
				get_rsc_type_supported(lrmd, raclass);
			printf("List size: %d\n", g_list_length(ratype_list));
			if (ratype_list) {
				g_list_foreach(ratype_list, g_print_rainfo_item,
						NULL);
				//g_list_free(ratype_list);
			} else {
				printf("For this RA class, no any RA type is "
					"supported\n");
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
				printf("Currently no resource is managed by "\
					 "LRM.\n");

			ASYN_OPS = FALSE;
			break;	

		case INF_RSC:
			lrm_rsc = get_lrm_rsc(lrmd, rscid_arg_tmp);
			if (!(lrm_rsc)) {
				ret_value = -3;
			} else {
				print_rsc_inf(lrm_rsc);
				g_free(lrm_rsc);
			}

			ASYN_OPS = FALSE;
			break;	

		case RSC_STATUS: 
			lrm_rsc = get_lrm_rsc(lrmd, rscid_arg_tmp);
			if (!(lrm_rsc)) {
				ret_value = -3;
			} else { 
				state_flag_t cur_state;
				GList * ops_queue;
				ops_queue = lrm_rsc->ops->get_cur_state(lrm_rsc, 
								&cur_state);
				if (!ops_queue) {
					cl_log(LOG_ERR, "Operation queue "\
					  "pointer is null when try to get the"\
					  " operation status on a RA.");
					ret_value = -3;
				} else {
					if (cur_state == LRM_RSC_IDLE) {
						printf("No operation is doing"\
						 "on the resource, and the "\
						 "operation is the last one "\
						 "executed on the resource.\n");
					} else {
						printf("The following "\
						 "operations are those in the "\
						 "queue, and the first one is "\
						 "running now.\n");
					}
					g_list_foreach(ops_queue, g_print_ops, 
							NULL);
					g_list_free(ops_queue);
				}
			}

			ASYN_OPS = FALSE;
			break;

		case MONITOR: 
			fprintf(stderr, "Need one more definite option.\n");
			ret_value = -1;
			ASYN_OPS = FALSE;
			break;

		/* Don't finished ops */
	  	case MONITOR_SET: 
			call_id = set_monitor(lrmd, argc, optind, argv);
			if (call_id < 0) {
				cl_log(LOG_ERR, "There are invalid parameters");
				ret_value = -3;
				ASYN_OPS = FALSE;
			} else { 
				/* Return value: HA_OK = 1 Or  HA_FAIL = 0 */
				if ( call_id == 0 ) {
					cl_log(LOG_ERR, "Monitor settting "\
					"Failed." );
					ret_value = -3;
					ASYN_OPS = FALSE;
				} else { 
					ASYN_OPS = TRUE;
				}
			}
			break;

		case MONITOR_GET: 
			lrm_rsc = get_lrm_rsc(lrmd, rscid_arg_tmp);
			if (!(lrm_rsc)) {
				ret_value = -3;
			} else { 
				GList* monitor_list = NULL;
				monitor_list = 
					lrm_rsc->ops->get_monitors(lrm_rsc);
				if ( monitor_list == NULL) {
					printf("No monitor on this resource.\n");
				} else {
					printf("Monitors on this resource:\n");
					g_list_foreach(monitor_list, 
						g_print_monitor, NULL);
					g_list_free(monitor_list);
				}
			}
			
			ASYN_OPS = FALSE;
			break;

		case MONITOR_CLS: 
			lrm_rsc = get_lrm_rsc(lrmd, rscid_arg_tmp);
			if (!(lrm_rsc)) {
				ret_value = -3;
			} else { 
				lrm_mon_t mon_ops;
				mon_ops.mode = LRM_MONITOR_CLEAR;
				if (lrm_rsc->ops->set_monitor(lrm_rsc, &mon_ops)
					== 1 ) { /* HA_OK */
					printf("Be trying to clearing all "\
						"monitors on this resource.\n");
					ASYN_OPS = TRUE;
				} else {
					fprintf(stderr, "Failed to clear all "\
						"monitors on this resource.\n");
					ret_value = -1;
					ASYN_OPS = FALSE;
				}
			}
			
			break;

		default:
			fprintf(stderr, "This option is not supported yet.\n");
			ret_value = -1;
			ASYN_OPS = FALSE;
			break;	
	}

	if (ASYN_OPS) {
		lrmd->lrm_ops->set_lrm_callback(lrmd, lrm_op_done_callback, 
			lrm_monitor_callback);

		mainloop = g_main_new(FALSE);
		cl_log(LOG_DEBUG, "%s waiting for calling result from the lrmd.",
			 lrmadmin_name);

		g_idle_add(post_query_call_result, lrmd);
		g_main_run(mainloop);
	}

	lrmd->lrm_ops->signoff(lrmd);
	return ret_value;
}


static void
lrm_op_done_callback(lrm_op_t* op)
{
	char * tmp;

	if (!op) {
		cl_log(LOG_ERR, "In callback function, op is NULL pointer.");
		return;
	}

	printf("Operation result: %s\n", status_msg[op->status-LRM_OP_DONE]);
	printf("Operation type: %s\n", op->op_type);
	tmp = params_hashtable_to_str(op->rsc->class, op->params);
	printf("Opration parameters: %s\n", tmp);
	g_free(tmp);
	printf("Meta data is as following:\n%s\n", op->data);

	printf("\nThe corresponding resource description as below\n");
	print_rsc_inf(op->rsc);
	/* Don't need ? 
	 * g_free(op->rsc);  
	 * g_free(op);
	 */
}

static void
lrm_monitor_callback(lrm_mon_t* mon)
{
	if (mon) {
		g_print_monitor(mon, NULL);
	}
}

static gboolean
post_query_call_result(gpointer data)
{
	ll_lrm_t * lrmd = (ll_lrm_t *) data;

	if  (!(lrmd->lrm_ops->msgready(lrmd)) )  {
		return TRUE;
	}

	if (0 > lrmd->lrm_ops->rcvmsg(lrmd, TRUE)) {
		cl_log(LOG_ERR, "Error when post query calling result.");
	}

	g_main_quit(mainloop);

	return FALSE;
}

static int 
resource_operation(ll_lrm_t * lrmd, int argc, int optind, char * argv[])
{
	rsc_id_t rsc_id;
	GHashTable * params_ht = NULL;
	lrm_op_t op;
	lrm_rsc_t * lrm_rsc;
	int call_id;
	
	if ((argc - optind) < 3) {
		cl_log(LOG_ERR,"No enough parameters.");
		return -2;
	}
	
	uuid_parse(argv[optind], rsc_id);
	lrm_rsc = lrmd->lrm_ops->get_rsc(lrmd, rsc_id);	
	if (!lrm_rsc) {
		return -1;
	}

	op.op_type = argv[optind+1];
	op.timeout = atoi(argv[optind+2]);

	if ((argc - optind) > 3) {
		if (0 > transfer_cmd_params(argc, optind+3, argv, 
				lrm_rsc->class, &params_ht) ) {
			return -2;
		}
	}
	op.params = params_ht;

	call_id = lrm_rsc->ops->perform_op(lrm_rsc, &op);
	/* g_free(lrm_rsc);   don't need to free it ? */
	if (params_ht) {
		g_hash_table_foreach(params_ht, free_stritem_of_hashtable, NULL);
		g_hash_table_destroy(params_ht);
	}
	return call_id;
}

static int 
add_resource(ll_lrm_t * lrmd, int argc, int optind, char * argv[])
{
	rsc_id_t rsc_id;
	const char * class = argv[optind+1];
	const char * type = argv[optind+2];
	int tmp_ret;

	if ((argc - optind) < 3) {
		cl_log(LOG_ERR,"No enough parameters.");
		return -2;
	}

	uuid_parse(argv[optind], rsc_id);

	GHashTable * params_ht = NULL;
	/* delete Hashtable */
	if ((argc - optind) > 3) {
		if ( 0 > transfer_cmd_params(argc, optind+3, argv, class,
					&params_ht) ) {
			return -1;
		}
	}

	tmp_ret = lrmd->lrm_ops->add_rsc(lrmd, rsc_id, class, 
						type, params_ht);

	/*delete params_ht*/
	if (params_ht) {
		g_hash_table_foreach(params_ht, free_stritem_of_hashtable, NULL);
		g_hash_table_destroy(params_ht);
	}

	return (tmp_ret ? 0 : -1); /* tmp_ret is HA_OK=1 or HA_FAIL=0 */
}

static int
transfer_cmd_params(int amount, int start, char * argv[], const char * class, 
GHashTable ** params_ht)
{
	if (amount < start) {
		return -1;
	}

	if (strncmp("ocf", class, 4)==0) {
		int i;
		char * delimit, * key, * value;
		*params_ht = g_hash_table_new(g_str_hash, g_str_equal);

		for (i=start; i<amount; i++) {
			int len_tmp;
			delimit = strchr(argv[i], '=');
			if (!delimit) {
				cl_log(LOG_ERR, "parameter %s is invalid for " \
					"OCF standard.", argv[i]);
				goto error_return; /* Have to */
			}

			/* lack error handling for g_new. Exception ? */
			len_tmp = strnlen(delimit+1, 80) + 1;
			value = g_new(gchar, len_tmp);
			strncpy(value, delimit+1, len_tmp);

			len_tmp = strnlen(argv[i], 80) - strnlen(delimit, 80);
			key = g_new(gchar, len_tmp+1);
			key[len_tmp] = '\0';
			strncpy(key, argv[i], len_tmp);
			
			g_hash_table_insert(*params_ht, key, value);
		}
	} else if ( strncmp("lsb", class, 4) == 0 || 
		    strncmp("heartbeat", class, 10) == 0 ) {
		int i;
		char buffer[21];

		/* Pay attention: for parameter ordring issue */
		*params_ht = g_hash_table_new(g_str_hash, g_str_equal);

		buffer[20] = '\0';
		for (i=start; i<amount; i++) {
			snprintf(buffer, 20, "%d", i-start+1);
			g_hash_table_insert( *params_ht, g_strdup(buffer), 
						g_strdup(argv[i]));
			//printf("index: %d  value: %s \n", i-start+1, argv[i]);
		}
	} else {
		fprintf(stderr, "Not supported resource agency class.\n");
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
	gchar * params_str = NULL;
	GString * gstr_tmp;

	if (!ht) {
		 return NULL;
	}

	if (strncmp("ocf", class, 4)==0) {
		gstr_tmp = g_string_new("");
		g_hash_table_foreach(ht, ocf_params_hash_to_str, &gstr_tmp);
		params_str = g_new(gchar, gstr_tmp->len+1);		
		strncpy(params_str, gstr_tmp->str, gstr_tmp->len+1);
		g_string_free(gstr_tmp, TRUE);
	} else if ( strncmp("lsb", class, 4) == 0 || 
		    strncmp("heartbeat", class, 10) == 0 ) {
		int i;
		int ht_size = g_hash_table_size(ht);
		gchar * tmp_str = g_new(gchar, ht_size*ARGVI_MAX_LEN); 	
		memset(tmp_str, '\0', ht_size*ARGVI_MAX_LEN);
		g_hash_table_foreach(ht, normal_params_hash_to_str, &tmp_str);
		gstr_tmp = g_string_new("");
		for (i=0; i< ht_size; i++) {
			g_string_append(gstr_tmp, tmp_str + i*ARGVI_MAX_LEN );
		}
		params_str = g_new(gchar, gstr_tmp->len+1);		
		strncpy(params_str, gstr_tmp->str, gstr_tmp->len+1);
		g_string_free(gstr_tmp, TRUE);
	} else {
		fprintf(stderr, "Not supported resource agency class.\n");
	}

	return params_str;
}

static void
g_print_stringitem(gpointer data, gpointer user_data)
{
	printf("%s\n", (char*)data);
	g_free(data);  /*  ?  */
}

static void
g_print_rainfo_item(gpointer data, gpointer user_data)
{
/*	rsc_info_t * rsc_info = (rsc_info_t *) data; */
	printf("RA type name: %s\n", (char *)data);
/*
	printf("RA type name: %s  Version: %s\n", 
		rsc_info->rsc_type, rsc_info->version);
*/
	g_free(data); /*  ?  */
}

static void
g_print_ops(gpointer data, gpointer user_data)
{
	printf("%s  ", (char*)data);
	g_free(data);  /*  ?  */
}

static void
g_get_rsc_description(gpointer data, gpointer user_data)
{
	ll_lrm_t* lrmd = (ll_lrm_t *)user_data;
	lrm_rsc_t * lrm_rsc;
	rsc_id_t rsc_id_tmp;
	
	if (!(user_data)) {
		return;
	}

	memset(rsc_id_tmp, '\0', sizeof(rsc_id_t));
	strncpy(rsc_id_tmp, data, sizeof(rsc_id_t));

	lrm_rsc = lrmd->lrm_ops->get_rsc(lrmd, rsc_id_tmp);
	if (lrm_rsc) {
		print_rsc_inf(lrm_rsc);
		g_free(lrm_rsc);   /* ? */
	} else
		cl_log(LOG_ERR, "There is a invalid resource id %s.", 
			rsc_id_tmp);
	
	g_free(data); /* ? */
}

static void
print_rsc_inf(lrm_rsc_t * lrm_rsc)
{
	char rscid_str_tmp[40];
	char * tmp = NULL;

	if (!lrm_rsc) {
		return;
	}

	uuid_unparse(lrm_rsc->id, rscid_str_tmp);
	printf("Resource ID:                %s\n", rscid_str_tmp);
	printf("Resource agency class:       %s\n", lrm_rsc->class);
	printf("Resource agency type:       %s\n", lrm_rsc->type);

	if (lrm_rsc->params) {
		tmp = params_hashtable_to_str(lrm_rsc->class, 
				lrm_rsc->params);
	}
	printf("Resource agency parameters: %s\n", tmp);
	g_free(tmp);
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
	g_string_append(gstr_tmp, (char*)key);
	g_string_append(gstr_tmp, "=");
	g_string_append(gstr_tmp, (char *)value);
	g_string_append(gstr_tmp, "\n");
}

static void
normal_params_hash_to_str(gpointer key, gpointer value, gpointer user_data)
{
	gchar * str_tmp = *(gchar **) user_data;
	if (str_tmp == NULL ) {
		return;
	}
	strncpy(str_tmp + *(gint *)key * ARGVI_MAX_LEN, (char*)value,
		ARGVI_MAX_LEN - 1);
}

static lrm_rsc_t * 
get_lrm_rsc(ll_lrm_t * lrmd, rsc_id_t rscid)
{
	char uuid_str_tmp[40];
	lrm_rsc_t * lrm_rsc;
	lrm_rsc = lrmd->lrm_ops->get_rsc(lrmd, rscid);
	if (!(lrm_rsc)) {
		uuid_unparse(rscid, uuid_str_tmp);
		cl_log(LOG_ERR,"No this resource %s.", uuid_str_tmp);
	}
	return lrm_rsc;
}

static void
g_print_monitor(gpointer data, gpointer user_data)
{
	/* Don't need to free it */
	lrm_mon_t * lrm_mon = (lrm_mon_t *) data;
	if (lrm_mon) {
		char * tmp;
		printf("MONITOR:\n");
		printf("Mode: %d\n", lrm_mon->mode);
		printf("Interval: %d\n", lrm_mon->interval);
		printf("Target: %d\n", lrm_mon->target);
		printf("Operation type: %s\n", lrm_mon->op_type);
		printf("Timeout: %d\n", lrm_mon->timeout);
		tmp = params_hashtable_to_str(lrm_mon->rsc->class, 
						lrm_mon->params);
		printf("Parameters: %s\n", tmp);
		g_free(tmp);
		/* Other fields ? */
	}
}

static int 
set_monitor(ll_lrm_t * lrmd, int argc, int optind, char * argv[])
{
	rsc_id_t rsc_id;
	GHashTable * params_ht = NULL;
	lrm_mon_t mon;
	lrm_rsc_t * lrm_rsc;
	int call_id;
	
	if ((argc - optind) < 4) {
		cl_log(LOG_ERR,"No enough parameters.");
		return -2;
	}
	
	uuid_parse(argv[optind], rsc_id);
	lrm_rsc = lrmd->lrm_ops->get_rsc(lrmd, rsc_id);	
	if (!lrm_rsc) {
		return -1;
	}

	mon.mode = LRM_MONITOR_SET;
	mon.op_type = argv[optind+1];
	mon.timeout = atoi(argv[optind+2]);
	mon.interval = atoi(argv[optind+3]);

	if ((argc - optind) > 4) {
		if ( 0 > transfer_cmd_params(argc, optind+4, argv, 
				lrm_rsc->class, &params_ht) ) {
			return -1;
		}
	}
	mon.params = params_ht;

	call_id = lrm_rsc->ops->set_monitor(lrm_rsc, &mon);
	/* g_free(lrm_rsc);  Don't need to free it? */
	if (params_ht) {
		g_hash_table_foreach(params_ht, free_stritem_of_hashtable, NULL);
		g_hash_table_destroy(params_ht);
	}
	return call_id;
}
