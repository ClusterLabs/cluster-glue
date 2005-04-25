/* $Id: lrmadmin.c,v 1.31 2005/04/25 05:47:54 zhenh Exp $ */
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
#include <clplumbing/cl_log.h>
#include <lrm/lrm_api.h>
#include <lrm/raexec.h>
#include <clplumbing/lsb_exitcodes.h>
#include <clplumbing/GSource.h>
#include <clplumbing/Gmain_timeout.h>

const char * optstring = "AD:dEF:d:sg:M:P:c:S:LI:CT:h";

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
	{"metadata",1,0,'M'},
	{"provider",1,0,'P'},
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
	RSC_STATE,
	LIST_ALLRSC,
	INF_RSC,
	ADD_RSC,
	DEL_RSC,
	RACLASS_SUPPORTED,
	RATYPE_SUPPORTED,
	RA_METADATA,
	RA_PROVIDER,
	HELP
} lrmadmin_cmd_t;

static const char * status_msg[5] = {
	"succeed", 		  /* LRM_OP_DONE         */
        "cancelled", 		  /* LRM_OP_CANCELLED    */
        "timeout",		  /* LRM_OP_TIMEOUT 	 */
        "not Supported",	  /* LRM_OP_NOTSUPPORTED */
        "failed due to an error"   /* LRM_OP_ERROR	 */
};

static gboolean QUIT_GETOPT = FALSE;
static lrmadmin_cmd_t lrmadmin_cmd = NULL_OP;
static gboolean ASYN_OPS = FALSE; 
static int call_id = 0;
static int TIMEOUT = -1; /* the unit is ms */

const char * simple_help_screen =
"lrmadmin {-d|--deamon}\n"
"         {-A|--add} <rscid> <raclass> <ratype> <provider|NULL> [<rsc_params_list>]\n"
"         {-D|--delete} <rscid>\n"
"         {-F|--flush} <rscid>\n"
"         {-E|--execute} <rscid> <operator> <timeout> <interval> <target_rc|EVERYTIME|CHANGED> [<operator_parameters_list>]\n"
"         {-S|--state} <rscid>\n"
"         {-L|--listall}\n"
"         {-I|--information} <rsc_id>\n"
"         {-C|--raclass_supported}\n"
"         {-T|--ratype_supported} <raclss>\n"
"         {-M|--metadata} <raclss> <ratype> <provider|NULL>\n"
"         {-P|--provider} <raclss> <ratype>\n"
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
static lrm_rsc_t * get_lrm_rsc(ll_lrm_t * lrmd, char * rscid);

static int ra_metadata(ll_lrm_t * lrmd, int argc, int optind, char * argv[]);
static int ra_provider(ll_lrm_t * lrmd, int argc, int optind, char * argv[]);
static gboolean lrmd_output_dispatch(int fd, gpointer user_data);
static gboolean lrm_op_timeout(gpointer data);

/* the end of the internal used function list */

static void lrm_op_done_callback(lrm_op_t* op);

int ret_value = 0; 
int main(int argc, char **argv)
{
	int option_char;
	char rscid_arg_tmp[RID_LEN];
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
	cl_log_enable_stderr(FALSE);
	cl_log_set_facility(LOG_USER);

	memset(rscid_arg_tmp, '\0', RID_LEN);
	memset(raclass, '\0', 20);
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
					strncpy(rscid_arg_tmp, optarg, RID_LEN-1);
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
					strncpy(rscid_arg_tmp, optarg, RID_LEN-1);
				}
				break;

			case 'E':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = EXECUTE_RA;
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
				if (optarg) {
					strncpy(rscid_arg_tmp, optarg, RID_LEN-1);
				}
				break;

			case 'L':
				OPTION_OBSCURE_CHECK 
				lrmadmin_cmd = LIST_ALLRSC;
				break;

			case 'I':
				OPTION_OBSCURE_CHECK 
				if (optarg) {
					strncpy(rscid_arg_tmp, optarg, RID_LEN-1);
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
				cl_log(LOG_ERR,"Error:getopt returned character"
					 " code %c.", option_char);
				return -1;
               }
	} while (!QUIT_GETOPT);

        lrmd = ll_lrm_new("lrm");

        if (NULL == lrmd) {
               	cl_log(LOG_ERR,"ll_lrn_new return null.");
               	return -2;
        }

	lrmd->lrm_ops->set_lrm_callback(lrmd, lrm_op_done_callback);

        if (lrmd->lrm_ops->signon(lrmd, lrmadmin_name) != 1) { /* != HA_OK */
		printf("lrmd daemon is not running.\n");
		if (lrmadmin_cmd == DAEMON_OP) { 
			return LSB_STATUS_STOPPED;
		} else {
			cl_log(LOG_WARNING,"Can't connect to lrmd, quit!");
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
					cl_log(LOG_ERR, "Failed to operate "
					   "resource %s due to parameter error."
					  , argv[optind]);
					ret_value = -3;
				}
				if ( call_id == -1 ) {
					cl_log(LOG_WARNING, "Failed! no this "
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
					"Failed." );
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
					printf("Failed to flush.\n");
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
				ret_value = LSB_EXIT_OK;
			} else {
				printf("No any RA class is supported\n");
				ret_value = -3;
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
				/* g_list_free(ratype_list); */
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
				printf("Currently no resource is managed by "
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
								
				if (ops_queue) {
					g_list_foreach(ops_queue, g_print_ops, 
							NULL);
					g_list_free(ops_queue);
				}
			}

			ASYN_OPS = FALSE;
			break;


		default:
			fprintf(stderr, "This option is not supported yet.\n");
			ret_value = -1;
			ASYN_OPS = FALSE;
			break;	
	}

	if (ASYN_OPS) {
        	G_main_add_fd(G_PRIORITY_LOW, lrmd->lrm_ops->inputfd(lrmd),
			FALSE, lrmd_output_dispatch, lrmd, NULL);
		if (TIMEOUT > 0) {
			Gmain_timeout_add(TIMEOUT, lrm_op_timeout, &ret_value);
		}

		mainloop = g_main_new(FALSE);
		printf( "waiting for calling result from the lrmd.\n");
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
lrmd_output_dispatch(int fd, gpointer user_data)
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
		printf("operation status:%s\n", status_msg[LRM_OP_DONE]);
	} else {
		printf("operation status:%s\n", status_msg[(op->op_status 
			- LRM_OP_DONE) % DIMOF(status_msg)]);
	}
	printf("op_status: %d\n", op->op_status);
	printf("return code: %d\n", op->rc);
	printf("output data: \n%s\n", op->output);
	printf("---------------------------------------\n\n");
	ret_value = op->op_status;	
}

static int 
resource_operation(ll_lrm_t * lrmd, int argc, int optind, char * argv[])
{
	char rsc_id[RID_LEN];
	GHashTable * params_ht = NULL;
	lrm_op_t op = lrm_zero_op;
	lrm_rsc_t * lrm_rsc;
	int call_id;
	
	if ((argc - optind) < 3) {
		cl_log(LOG_ERR,"No enough parameters.");
		return -2;
	}

	rsc_id[RID_LEN-1] = '\0';
	strncpy(rsc_id, argv[optind], RID_LEN-1);
	lrm_rsc = lrmd->lrm_ops->get_rsc(lrmd, rsc_id);	
	if (!lrm_rsc) {
		return -1;
	}

	op.op_type = argv[optind+1];
	op.timeout = atoi(argv[optind+2]);

 	/* Plus addtional 1s, make here the timeout normally takes place 
	   after the lrmd's */
	if (0 < op.timeout ) {
		TIMEOUT = op.timeout + 1000;
	} else {
		TIMEOUT = 60000;
	}		
	op.interval = atoi(argv[optind+3]);
	op.user_data = NULL;
	op.user_data_len = 0;
	if (0 == strcmp(argv[optind+4], "EVERYTIME")) {
		op.target_rc = EVERYTIME;
	}
	else
	if (0 == strcmp(argv[optind+4], "CHANGED")) {
		op.target_rc = CHANGED;
	}
	else {
		op.target_rc = atoi(argv[optind+4]);
	}

	if ((argc - optind) > 3) {
		if (0 > transfer_cmd_params(argc, optind+5, argv, 
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
ra_metadata(ll_lrm_t * lrmd, int argc, int optind, char * argv[])
{
	const char * class = argv[optind-1];
	const char * type = argv[optind];
	const char * provider = argv[optind+1];
	char* metadata;

	if(argc < 5) {
		cl_log(LOG_ERR,"No enough parameters.");
		return -2;
	}

	if (0 == strncmp(provider,"NULL",strlen("NULL"))) {
		provider=NULL;
	}

	metadata = lrmd->lrm_ops->get_rsc_type_metadata(lrmd, class, type, provider);
	if (NULL!=metadata) {
		printf ("metadata of %s(%s) is: %s\n",type,class,metadata);
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
		cl_log(LOG_ERR,"No enough parameters.");
		return -2;
	}

	providers = lrmd->lrm_ops->get_rsc_provider_supported(lrmd,class,type);
	
	while (NULL != (provider = g_list_first(providers))) {
		printf("%s\n",(char*)provider->data);
		providers = g_list_remove(providers, provider->data);
		g_free(provider->data);
	}
	g_list_free(providers);
	return 0;
}

static int 
add_resource(ll_lrm_t * lrmd, int argc, int optind, char * argv[])
{
	char rsc_id[RID_LEN];
	const char * class = argv[optind+1];
	const char * type = argv[optind+2];
	const char * provider = argv[optind+3];
	GHashTable * params_ht = NULL;
	int tmp_ret;

	if ((argc - optind) < 4) {
		cl_log(LOG_ERR,"No enough parameters.");
		return -2;
	}
	
	rsc_id[RID_LEN-1]='\0';
	strncpy(rsc_id, argv[optind], RID_LEN-1);

	if (0 == strncmp(provider, "NULL", strlen("NULL"))) {
		provider=NULL;
	}
	
	/* delete Hashtable */
	if ((argc - optind) > 4) {
		if ( 0 > transfer_cmd_params(argc, optind+4, argv, class,
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
				cl_log(LOG_ERR, "parameter %s is invalid for "
					"OCF standard.", argv[i]);
				goto error_return; /* Have to */
			}

			len_tmp = strnlen(delimit+1, 80) + 1;
			value = g_new(gchar, len_tmp);
			strncpy(value, delimit+1, len_tmp);

			len_tmp = strnlen(argv[i], 80) - strnlen(delimit, 80);
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
	char rsc_id_tmp[RID_LEN];
	
	if (!(user_data)) {
		return;
	}

	memset(rsc_id_tmp, '\0', RID_LEN);
	strncpy(rsc_id_tmp, data, RID_LEN-1);

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
	char rscid_str_tmp[RID_LEN];
	char * tmp = NULL;

	if (!lrm_rsc) {
		return;
	}

	rscid_str_tmp[RID_LEN-1] = '\0';
	strncpy(rscid_str_tmp, lrm_rsc->id, RID_LEN-1);
	printf("\nResource ID:%s\n", rscid_str_tmp);
	printf("Resource agency class:%s\n", lrm_rsc->class);
	printf("Resource agency type:%s\n", lrm_rsc->type);
	printf("Resource agency provider:%s\n", lrm_rsc->provider?lrm_rsc->provider:"default");

	if (lrm_rsc->params) {
		tmp = params_hashtable_to_str(lrm_rsc->class, 
				lrm_rsc->params);
		printf("Resource agency parameters:%s\n", tmp);
		g_free(tmp);
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
		cl_log(LOG_ERR,"No this resource %s.", uuid_str_tmp);
	}
	return lrm_rsc;
}

/*
 * $Log: lrmadmin.c,v $
 * Revision 1.31  2005/04/25 05:47:54  zhenh
 * when user did not give timeout of op, use 60s as timeout of lrmadmin, if user gave one, add 1s as timeout of lrmadmin
 *
 * Revision 1.30  2005/04/22 06:08:50  alan
 * Put in a fix for an uninitialized variable -- added a new
 * const lrm_op_t object lrm_zero_op - which can be used as an initializer for
 * lrm_op_t objects so this doesn't happen.
 *
 * Revision 1.29  2005/04/18 15:47:41  alan
 * Fixed a compile error (warning) in lrmadmin.
 *
 * Revision 1.28  2005/04/18 09:42:20  sunjd
 * have its own timeout watching, now lrmadmin should not be blocked when no result from LRMd
 *
 * Revision 1.27  2005/02/28 10:34:36  zhenh
 * change the log from LOG_ERR TO LOG_WARNING
 *
 * Revision 1.26  2005/02/28 08:52:46  zhenh
 * no such resource should be a warning instead of error
 *
 * Revision 1.25  2004/12/09 07:16:58  sunjd
 * add the support to stonith RA; some minor polish
 *
 * Revision 1.24  2004/12/05 13:18:32  sunjd
 * add the support to stonith RAs
 *
 * Revision 1.23  2004/11/23 20:58:18  andrew
 * Commit zhenh's patch for preserving user data across connections
 * Only supports flat objects (ie. char* or structs without pointers in them)
 *
 * Revision 1.22  2004/10/24 12:38:33  lge
 * -pedantic-errors fixes take one:
 * * error: ISO C89 forbids mixed declarations and code
 *
 * Revision 1.21  2004/10/11 02:11:07  zhenh
 * remove comment line with //
 *
 * Revision 1.20  2004/10/10 09:27:53  zhenh
 * change some output information to make it more clear
 *
 * Revision 1.19  2004/10/08 04:47:54  zhenh
 * fix a bug: checking the return value of get_rsc_type_metadata
 *
 * Revision 1.18  2004/09/16 06:16:45  sunjd
 * BEAM bug fix: passing NULL to argument 1 of g_free
 *
 * Revision 1.17  2004/09/14 09:17:35  sunjd
 * fix two pointer bugs found by BEAM
 *
 * Revision 1.16  2004/09/10 10:25:50  sunjd
 * Minor polish to message format
 *
 * Revision 1.15  2004/09/10 00:28:17  zhenh
 * change the usage information
 *
 * Revision 1.14  2004/09/09 03:32:50  zhenh
 * fix a mis type
 *
 * Revision 1.13  2004/09/03 01:29:44  zhenh
 * add provider for resource
 *
 * Revision 1.12  2004/08/30 03:17:40  msoffen
 * Fixed more comments from // to standard C comments
 *
 * Revision 1.11  2004/08/29 04:42:03  msoffen
 * Added missing ID and Log
 *
 */
