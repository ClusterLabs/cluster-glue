/*
 * raexec.h: The universal interface of RA Execution Plugin
 *
 * Author: Sun Jiang Dong <sunjd@cn.ibm.com>
 * Copyright (c) 2004 International Business Machines
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef RAEXEC_H
#define RAEXEC_H
#include <glib.h>

const int EXECRA_OK  = 0,
	  EXECRA_BAD = -1;

/* 
 * RA Execution Interfaces 
 * The plugin usage is divided into two step. First to send out a command to
 * execute a resource agency via calling function execra. Execra is a unblock
 * function, always return at once. Then to call function post_query_result to
 * get the RA exection result.     
*/
struct RAExecOps { 
        /* 
	 * Description: 
	 * 	Launch a exection of a resource agency -- normally is a script
	 *
	 * Parameters:
	 * 	ra_name:  The basename of a RA.
	 *	op:	  The operation that hope RA to do, such as "start",
	 *		    "stop" and so on.
	 *	cmd_params: The command line parameters need to be passed to 
	 *		      the RA for a execution. 
	 *	env_params: The enviroment parameters need to be set for 
	 *		      affecting the action of a RA execution. As for 
	 *		      OCF style RA, it's the only way to pass 
	 *		      parameter to the RA.
	 *	need_stdout_data: If need get the output to stdout from this
	 *		    executon of the RA, especially the meta_data for
	 *		    OCF style RA.
	 *	exec_key: A key set by this function, the caller should pass it
	 *		    to the function post_query_result for querying the 
	 *		    exection result. 
	 * Return Value:
	 *	0:  RA execution is ok, while the exec_key is a valid value.
	 *	-1: The RA don't exist.
	 * 	-2: There are invalid command line parameters.
	 *	-3: Other unkown error when launching the execution.
	 */
	int (*execra)(
		const char * ra_name,	
		const char * op,
		GHashTable * cmd_params,
		GHashTable * env_params,
		gboolean need_stdout_data,
		int * exec_key);

	/*
	 * Description:
	 *	Query a RA execution distiguished by exec_key.
	 *
	 * Parameters:
	 *	exec_key: The only key to distinguish a RA execution, get from
	 *		    the former calling to execra.
	 *	result:	  The exit status directly from RA in this execution.
	 *	stdout_data: The output to stdout during this RA execution. 
	 *	
	 * Return Value:
	 * 	0: The execution isn't finished yet, can query it next time.
	 *	>0:The execution is finished. can't query any more.
	 *	<0:The query failed. For example, the exec_key is invalid, no
	 *	     a corresponding execution.
	 */
	int (*post_query_result)(int exec_key, int * result, char ** stdout_data);

};

#define RA_EXEC_TYPE	RAExec
#define RA_EXEC_TYPE_S	MKSTRING(RAExec)

#endif /* RAEXEC_H */
