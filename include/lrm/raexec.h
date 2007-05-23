/*
 * raexec.h: The universal interface of RA Execution Plugin
 *
 * Author: Sun Jiang Dong <sunjd@cn.ibm.com>
 * Copyright (c) 2004 International Business Machines
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
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef RAEXEC_H
#define RAEXEC_H
#include <glib.h>
#include <lrm/racommon.h>

/* Uniform return value of executing RA */
enum UNIFORM_RET_EXECRA {
	EXECRA_EXEC_UNKNOWN_ERROR = -2,
	EXECRA_NO_RA = -1,
	EXECRA_OK = 0,
	EXECRA_UNKNOWN_ERROR = 1,
	EXECRA_INVALID_PARAM = 2,
	EXECRA_UNIMPLEMENT_FEATURE = 3,
	EXECRA_INSUFFICIENT_PRIV = 4,
	EXECRA_NOT_INSTALLED = 5,
	EXECRA_NOT_CONFIGURED = 6,
	EXECRA_NOT_RUNNING = 7,
	EXECRA_RUNNING_MASTER = 8,
	EXECRA_FAILED_MASTER = 9,
		
	/* For status command only */
	EXECRA_RA_DEAMON_DEAD1 = 11,
	EXECRA_RA_DEAMON_DEAD2 = 12,
	EXECRA_RA_DEAMON_STOPPED = 13,
	EXECRA_STATUS_UNKNOWN = 14
};
typedef enum UNIFORM_RET_EXECRA uniform_ret_execra_t;

#define RA_MAX_NAME_LENGTH	240
#define RA_MAX_DIRNAME_LENGTH	200
#define RA_MAX_BASENAME_LENGTH	40

/* 
 * RA Execution Interfaces 
 * The plugin usage is divided into two step. First to send out a command to
 * execute a resource agent via calling function execra. Execra is a unblock
 * function, always return at once. Then to call function post_query_result to
 * get the RA exection result.     
*/
struct RAExecOps { 
        /* 
	 * Description: 
	 * 	Launch a exection of a resource agent -- normally is a script
	 *
	 * Parameters:
	 *	rsc_id:    The resource instance id.
	 * 	rsc_type:  The basename of a RA.
	 *	op_type:   The operation that hope RA to do, such as "start",
	 *		    "stop" and so on.
	 *	cmd_params: The command line parameters need to be passed to 
	 *		      the RA for a execution. 
	 *	env_params: The enviroment parameters need to be set for 
	 *		      affecting the action of a RA execution. As for 
	 *		      OCF style RA, it's the only way to pass 
	 *		      parameter to the RA.
	 *
	 * Return Value:
	 *	0:  RA execution is ok, while the exec_key is a valid value.
	 *	-1: The RA don't exist.
	 * 	-2: There are invalid command line parameters.
	 *	-3: Other unkown error when launching the execution.
	 */
	int (*execra)(
		const char * rsc_id,
		const char * rsc_type,
		const char * provider,
		const char * op_type,
		const int    timeout,
		GHashTable * params);

	/*
	 * Description:
	 *	Map the specific ret value to a uniform value.
	 *
	 * Parameters:
	 *	ret_execra: the RA type specific ret value. 
	 *	op_type:    the operation type
	 *	std_output: the output which the RA write to stdout.
	 *	
	 * Return Value:
	 *	A uniform value without regarding RA type.
	 */
	uniform_ret_execra_t (*map_ra_retvalue)(
				  int ret_execra
				, const char * op_type
				, const char * std_output);

	/*
	 * Description:
	 * 	List all resource info of this class 
	 *
	 * Parameters:
	 *	rsc_info: a GList which item data type is rsc_info_t as 
	 *		  defined above, containing all resource info of
	 *		  this class in the local machine.
	 *
	 * Return Value:
	 *	>=0 : succeed. the RA type number of this RA class
	 *	-1: failed due to invalid RA directory such as not existing.
	 *	-2: failed due to other factors
	 */
	int (*get_resource_list)(GList ** rsc_info);
	
	/*
	 * Description:
	 * 	List all providers of this type
	 *
	 * Parameters:
	 *	providers: a GList which item data type is string.
	 *		   the name of providers of the resource agent
	 *
	 * Return Value:
	 *	>=0 : succeed. the provider number of this RA
	 *	-1: failed due to invalid RA directory such as not existing.
	 *	-2: failed due to other factors
	 */
	int (*get_provider_list)(const char* ra_type, GList ** providers);

	/*
	 * Description:
	 * 	List the metadata of the resource agent this class
	 *
	 * Parameters:
	 *	rsc_type: the type of the ra 
	 *
	 * Return Value:
	 *	!NULL : succeed. the RA metadata.
	 *	NULL: failed
	 */
	char* (*get_resource_meta)(const char* rsc_type, const char* provider);
};

#define RA_EXEC_TYPE	RAExec
#define RA_EXEC_TYPE_S	"RAExec"

#endif /* RAEXEC_H */
