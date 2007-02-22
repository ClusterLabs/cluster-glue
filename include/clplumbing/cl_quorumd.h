/*
 * quorum.h: head file for quorum module
 *
 * Author: Huang Zhen <zhenhltc@cn.ibm.com>
 * Copyright (C) 2006 International Business Machines
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

#ifndef _QUORUMD_H_
#define _QUORUMD_H_ 

#define HB_QUORUMD_TYPE		quorumd
#define HB_QUORUMD_TYPE_S	"quorumd"

#define CONFIGFILE	HA_HBCONF_DIR"/quorumd.conf"
#define MAX_DN_LEN 256
#define quorum_log(priority, fmt...); \
                cl_log(priority, fmt); \

#define quorum_debug(priority, fmt...); \
        if ( debug_level > 0 ) { \
                cl_log(priority, fmt); \
	}

/* List of functions provided by implementations of the quorumd interface. */
struct hb_quorumd_fns {
	int (*test) (void);
	int (*init) (void);
	int (*load_config_file) (void);
	int (*dump_data) (int priority);
	int (*on_connect) (int sock, gnutls_session session, const char* CN);
};


#endif
