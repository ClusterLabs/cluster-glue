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
 * By Huang Zhen <zhenh@cn.ibm.com> 2004/2/23
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
 * 5. Notify the clients if they want when the status of a certain resource
 *    changed.
 *
 * The typical clients of lrm are crm and lrmadmin.
 */
 
 /*
 * Notice:
 *"status" indicates the exit status code of "status" operation
 * its value is defined in LSB, OCF...
 *
 *"state" indicates the state of resource, maybe LRM_RSC_BUSY, LRM_RSC_IDLE
 *
 *"op_status" indicates how the op exit. like LRM_OP_DONE,LRM_OP_CANCELLED,
 * LRM_OP_TIMEOUT,LRM_OP_NOTSUPPORTED.
 */

#ifndef __LRM_API_H
#define __LRM_API_H 1

#include <portability.h>

#include <glib.h>

#define	LRM_PROTOCOL_VERSION	0.1

#ifndef NULL
#define NULL ((void*)0)
#endif

#define RID_LEN 	128

/*lrm's client uses this structure to access the resource*/
typedef struct 
{
	const char*	id;
	const char*	type;
	const char*	class;
	GHashTable* 	params;
	struct rsc_ops*	ops;
}lrm_rsc_t;

/*
 *mon_mode_t is used in lrm_mon_t to indicate its behave.
 *LRM_MONITOR_SET: callback will be called when the target status is set.
 *LRM_MONITOR_CHANGE: callback will be called when the status is changed.
 *LRM_MONITOR_CLEAR: the monitors set on this resource will be all cleared.
 */
typedef enum {
	LRM_MONITOR_SET = 0,
	LRM_MONITOR_CHANGE,
	LRM_MONITOR_CLEAR,
}mon_mode_t;

/*used in struct lrm_op_t to show how an operation exits*/
typedef enum {
	LRM_OP_DONE,
	LRM_OP_CANCELLED,
	LRM_OP_TIMEOUT,
	LRM_OP_NOTSUPPORTED,
	LRM_OP_ERROR,
}op_status_t;

/*for all timeouts: in seconds. 0 for no timeout*/

/*this structure is used to represent the monitor*/
typedef struct{
	//input fields
	mon_mode_t		mode;
	int			interval;
	int			target;
	gpointer 		user_data;
	//op_type here normally should be "status"
	const char* 		op_type;
	GHashTable*		params;
	int			timeout;

	//output fields
	lrm_rsc_t*		rsc;
	op_status_t		status;
	int			rc;
	int			call_id;
}lrm_mon_t;


/*this structure is the information of the operation.*/                        
typedef struct{
	/*input fields*/
	const char* 		op_type;
	GHashTable*		params;
	int			timeout;
	gpointer		user_data;

	/*output fields*/
	lrm_rsc_t*		rsc;
	op_status_t		status;
	char*			app_name;
	char*			data;
	int			rc;
	int			call_id;
}lrm_op_t;

/*this enum is used in get_cur_state*/
typedef enum {
	LRM_RSC_IDLE,
	LRM_RSC_BUSY,
}state_flag_t;

struct rsc_ops
{
/*
 *perform_op:	Performs the operation on the resource.
 *Notice: 	op is the operation which need to pass to RA and done asyn
 *
 *op:		the structure of the operation. caller should release
 *		the memory.
 *
 *return:	All operations will be asynchronous.
 *		The call will return the call id or failed code immediately.
 *		The call id will be passed to the callback function
 *		when the operation finished later.
 */
	int (*perform_op) (lrm_rsc_t*, lrm_op_t* op);


/*
 *flush_ops:	throw away all operations queued for this resource,
 *		and return them as cancelled.
 *return:	HA_OK for success, HA_FAIL for failure
 */
	int (*flush_ops) (lrm_rsc_t*);

/*
 *set_monitor:
 *		add a monitor to a resource.
 *
 *mon:		the pointer to monitor structure.
 *
 *return: 	the monitor_id used in the callback function.
 */
	int (*set_monitor) (lrm_rsc_t*, lrm_mon_t* mon);

/*
 * get_monitors:
 *		return the monitor list on this resource.
 *
 */
	GList* (*get_monitors) (lrm_rsc_t*);

/*
 *get_cur_state:
 *		return the current state of the resource
 *
 *cur_state:	current state of the resource
 *
 *return:	a list of lrm_op_t*.
 *		if cur_state == LRM_RSC_IDLE, the first and the only element
 *		of the list is the last op executed.
 *		if cur_state == LRM_RSC_BUSY, the first op of the list is the
 *		current running opertaion and others are the pending operations
 *
 *		client should release the memory of ops
 */
	GList* (*get_cur_state) (lrm_rsc_t*, state_flag_t* cur_state);

};


/*
 *lrm_op_done_callback_t:
 *		this type of callback functions are called when some
 *		asynchronous operation is done.
 *
 *op:		the informtion of the finished opeartion.
 *
 */
typedef void (*lrm_op_done_callback_t)	(lrm_op_t* op);

/*
 *lrm_monitor_callback_t:
 *		this type of callback functions are called when the status
 *		of resource changed in a monitored mode.
 *
 *mon:		the monitor invoked
 *
 */
typedef void (*lrm_monitor_callback_t)	(lrm_mon_t* mon);

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
			lrm_op_done_callback_t op_done_callback_func,
	 		lrm_monitor_callback_t montior_callback_func);


/*
 *get_rsc_class_supported:
 *		Returns the resource classes supported.
 *		e.g. ocf, heartbeat,lsb...
 *
 *return:	a list of the names of supported resource classes.
 *
 */
	GList* 	(*get_rsc_class_supported)(ll_lrm_t*);

/*
 *get_rsc_type_supported:
 *		Returns the resource types supported of class rsc_class.
 *		e.g. drdb, apache,IPaddr...
 *
 *return:	a list of the names of supported resource types.
 *
 */
	GList* 	(*get_rsc_type_supported)(ll_lrm_t*, const char* rsc_class);

/*
 *get_all_rscs:
 *		Returns all resources.
 *
 *return:	a list of id of resources.
 *
 */
	GList*	(*get_all_rscs)(ll_lrm_t*);


/*
 *get_rsc:	Gets one resource pointer by the id
 *
 *return:	the lrm_rsc_t type pointer, NULL for failure
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
 *type:	the type of the resource.
 *
 *params:	the parameters for the resource.
 *
 *return:	HA_OK for success, HA_FAIL for failure
 */
	int	(*add_rsc)(ll_lrm_t*, const char* rsc_id, const char* class,
	 	const char* type, GHashTable* params);

/*
 *delete_rsc:	delete the resource by the rsc_id
 *
 *return:	HA_OK for success, HA_FAIL for failure
 */
	int	(*delete_rsc)(ll_lrm_t*, const char* rsc_id);

/*
 *inputfd:	Return fd which can be given to select(2) or poll(2)
 *		for determining when messages are ready to be read.
 *return:	the fd
 */

	int	(*inputfd)(ll_lrm_t*);

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
 *set_debug_level:
 *		set the level of the message print out from the client library.
 *		if this function is not called, nothing will be printed out.
 *
 *level:	0: nothing will be printed out.
 *		LOG_ERR: print LOG_ERR messages.
 *		LOG_INFO: print out LOG_INFO and LOG_ERR messages
 */
 void	set_debug_level(int level);
 
#endif /* __LRM_API_H */

