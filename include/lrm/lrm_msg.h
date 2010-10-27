/*
 * Message Define For Local Resource Manager
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
 * By Huang Zhen <zhenh@cn.ibm.com> 2004/2/23
 *
 */
/*
 * Notice:
 *"status" indicates the exit status code of "status" operation
 * its value is defined in LSB
 *"state" indicates the state of resource, maybe LRM_RSC_BUSY, LRM_RSC_IDLE
 *"opstate" indicates how the op exit.like LRM_OP_DONE,LRM_OP_CANCELLED,
 * LRM_OP_TIMEOUT,LRM_OP_NOTSUPPORTED.
 */	
#ifndef __LRM_MSG_H
#define __LRM_MSG_H 1

#include <lrm/lrm_api.h>

#define LRM_CMDPATH 		HA_VARRUNDIR"/heartbeat/lrm_cmd_sock"
#define LRM_CALLBACKPATH 	HA_VARRUNDIR"/heartbeat/lrm_callback_sock"

/*define the field type used by lrm*/
#define F_LRM_TYPE		"lrm_t"
#define F_LRM_APP		"lrm_app"
#define F_LRM_PID		"lrm_pid"
#define	F_LRM_UID		"lrm_uid"
#define F_LRM_GID		"lrm_gid"
#define F_LRM_RID		"lrm_rid"
#define F_LRM_RTYPE		"lrm_rtype"
#define F_LRM_RTYPES		"lrm_rtypes"
#define F_LRM_RCLASS		"lrm_rclass"
#define F_LRM_RPROVIDER		"lrm_rprovider"
#define F_LRM_RPROVIDERS	"lrm_rproviders"
#define F_LRM_PARAM		"lrm_param"
#define F_LRM_COPYPARAMS	"lrm_copyparams"
#define F_LRM_TIMEOUT		"lrm_timeout"
#define F_LRM_OP		"lrm_op"
#define F_LRM_OPCNT		"lrm_opcount"
#define F_LRM_OPSTATUS		"lrm_opstatus"
#define F_LRM_RC		"lrm_rc"
#define F_LRM_RET		"lrm_ret"
#define F_LRM_CALLID		"lrm_callid"
#define F_LRM_RCOUNT		"lrm_rcount"
#define F_LRM_RIDS		"lrm_rids"
#define F_LRM_DATALEN		"lrm_datalen"
#define F_LRM_DATA		"lrm_data"
#define F_LRM_STATE		"lrm_state"
#define F_LRM_INTERVAL		"lrm_interval"
#define F_LRM_TARGETRC		"lrm_targetrc"
#define F_LRM_LASTRC		"lrm_lastrc"
#define F_LRM_STATUS		"lrm_status"
#define F_LRM_RSCDELETED		"lrm_rscdeleted"
#define F_LRM_METADATA		"lrm_metadata"
#define F_LRM_USERDATA		"lrm_userdata"
#define F_LRM_DELAY		"lrm_delay"
#define F_LRM_T_RUN		"lrm_t_run"
#define F_LRM_T_RCCHANGE	"lrm_t_rcchange"
#define F_LRM_EXEC_TIME		"lrm_exec_time"
#define F_LRM_QUEUE_TIME	"lrm_queue_time"
#define F_LRM_FAIL_REASON	"lrm_fail_reason"
#define F_LRM_ASYNCMON_RC	"lrm_asyncmon_rc"
#define F_LRM_LRMD_PARAM_NAME	"lrm_lrmd_param_name"
#define F_LRM_LRMD_PARAM_VAL	"lrm_lrmd_param_val"

#define	PRINT 	printf("file:%s,line:%d\n",__FILE__,__LINE__);


/*define the message typs between lrmd and client lib*/
#define REGISTER		"reg"
#define GETRSCCLASSES		"rclasses"
#define GETRSCTYPES		"rtypes"
#define GETPROVIDERS		"rproviders"
#define GETRSCMETA		"rmetadata"
#define GETALLRCSES		"getall"
#define GETRSC			"getrsc"
#define GETLASTOP		"getlastop"
#define GETRSCSTATE		"getstate"
#define	SETMONITOR		"setmon"
#define	GETMONITORS		"getmons"
#define FLUSHRSC		"flush"
#define ADDRSC			"addrsc"
#define DELRSC			"delrsc"
#define FAILRSC			"failrsc"
#define PERFORMOP		"op"
#define ISOPSUPPORT		"opspt"
#define OPDONE			"opdone"
#define MONITOR			"monitor"
#define RETURN			"return"
#define FLUSHOPS		"flushops"
#define CANCELOP		"cancelop"
#define	SETLRMDPARAM	"setparam"
#define	GETLRMDPARAM	"getparam"

#define MAX_INT_LEN 		64
#define MAX_NAME_LEN 		255
#define MAX_VALUE_LEN 		255
#define MAX_PARAM_LEN 		1024


GHashTable* copy_str_table(GHashTable* hash_table);
GHashTable* merge_str_tables(GHashTable* old, GHashTable* new);
void free_str_table(GHashTable* hash_table);

 /*  
 * message for no parameter, like unreg,types,getall 
 * they do not include any paramters 
 */ 
struct ha_msg* create_lrm_msg(const char*  msg);

/*
 * message for only one parameter - resource id,
 * like getrsc,delrsc,flush,getstate,getmons
 */
struct ha_msg* create_lrm_rsc_msg(const char* rid, const char* msg);

/* register client message */ 
struct ha_msg* create_lrm_reg_msg(const char* app_name);

/* 	
 * add new resource
 * according to the opinion of Lars, it is awkward that we combine all
 * parameters in to one string. I think so too. So this call may changed soon
 */ 
struct ha_msg* create_lrm_addrsc_msg(const char* rid, const char* class,
	const char* type, const char* provider, GHashTable* parameter);

/*  
 *
 *the return message from lrmd for reg,unreg,addrsc,delrsc,isopsupport. 
 *these return messages only include return code. 
 * 
 */ 
struct ha_msg* create_lrm_ret(int rc, int fields);
 

/*  
 * the return message for a status change monitoring. 
 */ 

struct ha_msg* create_rsc_perform_op_msg (const char* rid, lrm_op_t* op);
		
#endif /* __LRM_MSG_H */
