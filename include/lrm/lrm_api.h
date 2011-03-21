/*
 * Client-side Local Resource Manager API.
 *
 * Author: Huang Zhen <zhenh@cn.ibm.com>
 * Copyright (C) 2004 International Business Machines
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

/*
 *
 * By Huang Zhen <zhenhltc@cn.ibm.com> 2004/2/23
 *
 * It is based on the works of Alan Robertson, Lars Marowsky Bree,
 * Andrew Beekhof.
 *
 * The Local Resource Manager needs to provide the following functionalities:
 * 1. Provide the information of the resources holding by the node to its
 *    clients, including listing the resources and their status.
 * 2. Its clients can add new resources to lrm or remove from it.
 * 3. Its clients can ask lrm to operate the resources, including start,
 *    restart, stop and so on.
 * 4. Provide the information of the lrm itself, including what types of
 *    resource are supporting by lrm.
 *
 * The typical clients of lrm are crm and lrmadmin.
 */
 
 /*
 * Notice:
 * "status" indicates the exit status code of "status" operation
 * its value is defined in LSB, OCF...
 *
 * "state" indicates the state of resource, maybe LRM_RSC_BUSY, LRM_RSC_IDLE
 *
 * "op_status" indicates how the op exit. like LRM_OP_DONE,LRM_OP_CANCELLED,
 * LRM_OP_TIMEOUT,LRM_OP_NOTSUPPORTED.
 *
 * "rc" is the return code of an opertioan. it's value is in following enum 
 * which is defined in "raexec.h"
  * enum UNIFORM_RET_EXECRA {
 *	EXECRA_EXEC_UNKNOWN_ERROR = -2,
 *	EXECRA_NO_RA = -1,
 *	EXECRA_OK = 0,
 *	EXECRA_UNKNOWN_ERROR = 1,
 *	EXECRA_INVALID_PARAM = 2,
 *	EXECRA_UNIMPLEMENT_FEATURE = 3,
 *	EXECRA_INSUFFICIENT_PRIV = 4,
 *	EXECRA_NOT_INSTALLED = 5,
 *	EXECRA_NOT_CONFIGURED = 6,
 *	EXECRA_NOT_RUNNING = 7,
 *		
 *	EXECRA_RA_DEAMON_DEAD1 = 11,
 *	EXECRA_RA_DEAMON_DEAD2 = 12,
 *	EXECRA_RA_DEAMON_STOPPED = 13,
 *	EXECRA_STATUS_UNKNOWN = 14
 * };	
 */

#ifndef __LRM_API_H
#define __LRM_API_H 1

#include <glib.h>
#include <lrm/raexec.h>
#include <clplumbing/GSource.h>

#define LRM_PROTOCOL_MAJOR 0
#define LRM_PROTOCOL_MINOR 1
#define LRM_PROTOCOL_VERSION ((LRM_PROTCOL_MAJOR << 16) | LRM_PROTOCOL_MINOR)

#define RID_LEN 	128

/*lrm's client uses this structure to access the resource*/
typedef struct 
{
	char*	id;
	char*	type;
	char*	class;
	char*	provider;
	GHashTable* 	params;
	struct rsc_ops*	ops;
}lrm_rsc_t;


/*used in struct lrm_op_t to show how an operation exits*/
typedef enum {
	LRM_OP_PENDING = -1,
	LRM_OP_DONE,
	LRM_OP_CANCELLED,
	LRM_OP_TIMEOUT,
	LRM_OP_NOTSUPPORTED,
	LRM_OP_ERROR
}op_status_t;

/*for all timeouts: in milliseconds. 0 for no timeout*/

/*this structure is the information of the operation.*/

#define EVERYTIME -1
#define CHANGED   -2

/* Notice the interval and target_rc
 *
 * when interval==0, the operation will be executed only once
 * when interval>0, the operation will be executed repeatly with the interval
 *
 * when target_rc==EVERYTIME, the client will be notified every time the
 * 	operation executed.
 * when target_rc==CHANGED, the client will be notified when the return code
 *	is different with the return code of last execute of the operation
 * when target_rc is other value, only when the return code is the same of
 *	target_rc, the client will be notified.
 */

typedef struct{
	/*input fields*/
	char* 			op_type;
	GHashTable*		params;
	int			timeout;
	char*			user_data;
	int			user_data_len;
	int			interval;
	int			start_delay;
	int			copyparams; /* copy parameters to the rsc */
	int			target_rc;

	/*output fields*/
	op_status_t		op_status;
	int			rc;
	int			call_id;
	char*			output;
	char*			rsc_id;
	char*			app_name;
	char*			fail_reason;
	unsigned long		t_run; /* when did the op run (as age) */
	unsigned long		t_rcchange; /* last rc change (as age) */
	unsigned long		exec_time; /* time it took the op to run */
	unsigned long		queue_time; /* time spent in queue */
	int			rsc_deleted; /* resource just deleted? */
}lrm_op_t;

extern const lrm_op_t lrm_zero_op;	/* an all-zeroes lrm_op_t value */

lrm_op_t* lrm_op_new(void);
void lrm_free_op(lrm_op_t* op);
void lrm_free_rsc(lrm_rsc_t* rsc);
void lrm_free_str_list(GList* list);
void lrm_free_op_list(GList* list);
void lrm_free_str_table(GHashTable* table);


/*this enum is used in get_cur_state*/
typedef enum {
	LRM_RSC_IDLE,
	LRM_RSC_BUSY
}state_flag_t;

/* defaults for the asynchronous resource failures */
enum { DEFAULT_FAIL_RC = EXECRA_UNKNOWN_ERROR };
#define DEFAULT_FAIL_REASON "asynchronous monitor error"
#define ASYNC_OP_NAME "asyncmon"

/* in addition to HA_OK and HA_FAIL */
#define	HA_RSCBUSY		2

struct rsc_ops
{
/*
 *perform_op:	Performs the operation on the resource.
 *Notice: 	op is the operation which need to pass to RA and done asyn
 *
 *op:		the structure of the operation. Caller can create the op by
 *		lrm_op_new() and release the op using lrm_free_op()
 *
 *return:	All operations will be asynchronous.
 *		The call will return the call id or failed code immediately.
 *		The call id will be passed to the callback function
 *		when the operation finished later.
 */
	int (*perform_op) (lrm_rsc_t*, lrm_op_t* op);


/*
 *cancel_op:	cancel the operation on the resource.
 *
 *callid:	the call id returned by perform_op()
 *
 *return:	HA_OK for success, HA_FAIL for failure op not found
 *				or other failure
 *			NB: the client always gets a notification over callback
 *				even for operations which were idle (of course, if
 *				the request has been accepted for processing)
 */
	int (*cancel_op) (lrm_rsc_t*, int call_id);

/*
 *flush_ops:	throw away all operations queued for this resource,
 *		and return them as cancelled.
 *
 *return:	HA_OK for success, HA_FAIL for failure
 *		NB: op is not flushed unless it is idle;
 *       	in that case this call will block
 */
	int (*flush_ops) (lrm_rsc_t*);

/*
 *get_cur_state:
 *		return the current state of the resource
 *
 *cur_state:	current state of the resource
 *
 *return:	cur_state should be in LRM_RSC_IDLE or LRM_RSC_BUSY.
 *		and the function returns a list of ops.
 *		the list includes:
 *		1. last ops for each type (start/stop/etc) from current client
 *		2. current pending ops
 *		3. all recurring ops waiting to execute
 *		the list is sorted by the call_id of ops.
 *		client can release the list using lrm_free_op_list()
 */
	GList* (*get_cur_state) (lrm_rsc_t*, state_flag_t* cur_state);
	
/*
 *get_last_result:
 *		return the last op of given type from current client
 *
 *op_type:	the given type
 *
 *return:	the last op. if there is no such op, return NULL.
 *		client can release the op using lrm_free_op()
 */
	lrm_op_t* (*get_last_result)(lrm_rsc_t*, const char *op_type);
};


/*
 *lrm_op_done_callback_t:
 *		this type of callback functions are called when some
 *		asynchronous operation is done.
 *		client can release op by lrm_free_op()
 */
typedef void (*lrm_op_done_callback_t)	(lrm_op_t* op);


typedef struct ll_lrm
{
	struct lrm_ops*	lrm_ops;
}ll_lrm_t;

struct lrm_ops
{
	int		(*signon)  	(ll_lrm_t*, const char * app_name);

	int		(*signoff) 	(ll_lrm_t*);

	int		(*delete)  	(ll_lrm_t*);

	int		(*set_lrm_callback) (ll_lrm_t*,
			lrm_op_done_callback_t op_done_callback_func);

/*
 *set_lrmd_param:	set lrmd parameter
 *get_lrmd_param:	get lrmd parameter
 *
 *return:	HA_OK for success, HA_FAIL for failure
 *		NB: currently used only for max_child_count
 */
	int	(*set_lrmd_param)(ll_lrm_t*, const char *name, const char *value);
	char* (*get_lrmd_param)(ll_lrm_t*, const char *name);

/*
	int		(*set_parameters)(ll_lrm_t*, const GHashTable* option);

	GHashTable*     (*get_all_parameters)(ll_lrm_t*);

	char * 		(*get_parameter)(ll_lrm_t *, const char * paramname);

	char *		(*get_parameter_description)(ll_lrm_t*);
*/

/*
 *get_rsc_class_supported:
 *		Returns the resource classes supported.
 *		e.g. ocf, heartbeat,lsb...
 *
 *return:	a list of the names of supported resource classes.
 *		caller can release the list by lrm_free_str_list().
 */
	GList* 	(*get_rsc_class_supported)(ll_lrm_t*);

/*
 *get_rsc_type_supported:
 *		Returns the resource types supported of class rsc_class.
 *		e.g. drdb, apache,IPaddr...
 *
 *return:	a list of the names of supported resource types.
 *		caller can release the list by lrm_free_str_list().
 */
	GList* 	(*get_rsc_type_supported)(ll_lrm_t*, const char* rsc_class);

/*
 *get_rsc_provider_supported:
 *		Returns the provider list of the given resource types 
 *		e.g. heartbeat, failsafe...
 *
 *rsc_provider:	if it is null, the default one will used.
 *
 *return:	a list of the names of supported resource provider.
 *		caller can release the list by lrm_free_str_list().
 */
	GList* 	(*get_rsc_provider_supported)(ll_lrm_t*,
		const char* rsc_class, const char* rsc_type);

/*
 *get_rsc_type_metadata:
 *		Returns the metadata of the resource type
 *
 *rsc_provider:	if it is null, the default one will used.
 *
 *return:	the metadata. use g_free() to free.
 *		
 */
	char* (*get_rsc_type_metadata)(ll_lrm_t*, const char* rsc_class,
			const char* rsc_type, const char* rsc_provider);

/*
 *get_all_type_metadatas:
 *		Returns all the metadata of the resource type of the class
 *
 *return:	A GHashtable, the key is the RA type,
 *		the value is the metadata.
 *		Now only default RA's metadata will be returned.
 *		please use lrm_free_str_table() to free the return value.
 */
	GHashTable* (*get_all_type_metadata)(ll_lrm_t*, const char* rsc_class);

/*
 *get_all_rscs:
 *		Returns all resources.
 *
 *return:	a list of id of resources.
 *		caller can release the list by lrm_free_str_list().
 */
	GList*	(*get_all_rscs)(ll_lrm_t*);


/*
 *get_rsc:	Gets one resource pointer by the id
 *
 *return:	the lrm_rsc_t type pointer, NULL for failure
 *		caller can release the pointer by lrm_free_rsc().
 */
	lrm_rsc_t* (*get_rsc)(ll_lrm_t*, const char* rsc_id);

/*
 *add_rsc:	Adds a new resource to lrm.
 *		lrmd holds nothing when it starts.
 *		crm or lrmadmin should add resources to lrm using
 *		this function.
 *
 *rsc_id:	An id which sould be generated by client,
 *		128byte(include '\0') UTF8 string
 *
 *class: 	the class of the resource
 *
 *type:		the type of the resource.
 *
 *rsc_provider:	if it is null, the default provider will used.
 *	
 *params:	the parameters for the resource.
 *
 *return:	HA_OK for success, HA_FAIL for failure
 */
	int	(*add_rsc)(ll_lrm_t*, const char* rsc_id, const char* class,
	 	const char* type, const char* provider, GHashTable* params);

/*
 *delete_rsc:	delete the resource by the rsc_id
 *
 *return:	HA_OK for success, HA_FAIL for failure
 *		NB: resource removal is delayed until all operations are
 *		removed; the client, however, gets the reply immediately
 */
	int	(*delete_rsc)(ll_lrm_t*, const char* rsc_id);

/*
 *fail_rsc:	fail a resource
 *		Allow asynchronous monitor failures. Notifies all clients
 *		which have operations defined for the resource.
 *		The fail_rc parameter should be set to one of the OCF
 *		return codes (if non-positive it defaults to
 *		OCF_ERR_GENERIC). The fail_reason parameter should
 *		contain the description of the failure (i.e. "daemon
 *		panicked" or similar). If NULL is passed or empty string,
 *		it defaults to "asynchronous monitor failure".
 *
 *return:	HA_OK for success, HA_FAIL for failure
 */
	int (*fail_rsc)(ll_lrm_t* lrm, const char* rsc_id,
		const int fail_rc, const char* fail_reason);
/*
 *ipcchan:	Return the IPC channel which can be used for determining
 *		when messages are ready to be read.
 *return:	the IPC Channel
 */

   IPC_Channel*	(*ipcchan)(ll_lrm_t*);

/*
 *msgready:	Returns TRUE (1) when a message is ready to be read.
 */
	gboolean (*msgready)(ll_lrm_t*);

/*
 *rcvmsg:	Cause the next message to be read - activating callbacks for
 *		processing the message.  If no callback processes the message
 *		it will be ignored.  The message is automatically disposed of.
 *
 *return:	the count of message was received.
 */
	int	(*rcvmsg)(ll_lrm_t*, int blocking);

};

/*
 *ll_lrm_new:
 *		initializes the lrm client library.
 *
 *llctype:	"lrm"
 *
 */
ll_lrm_t* ll_lrm_new(const char * llctype);

/*
 *execra_code2string:
 *		Translate the return code of the operation to string
 *
 *code:		the rc field in lrm_op_t structure
 */
const char *execra_code2string(uniform_ret_execra_t code); 
#endif /* __LRM_API_H */

