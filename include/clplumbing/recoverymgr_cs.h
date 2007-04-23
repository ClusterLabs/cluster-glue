/*
 * Copyright (C) 2002 Intel Corporation
 * and
 * Copyright (C) 2002 Alan Robertson <alanr@unix.sh>
 * since the original code was taken from apphb_cs.h
 * and modified for use with the recovery manager.
 *
 *
 * This software licensed under the GNU LGPL.
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

#ifndef _CLPLUMBING_RECOVERYMGR_CS_H
#define _CLPLUMBING_RECOVERYMGR_CS_H

/* Internal client-server messages for recovery manager */

#ifndef HA_VARLIBDIR
#define HA_VARLIBDIR "/var/lib"
#endif
#define RECOVERYMGRSOCKPATH	HA_VARLIBDIR "/heartbeat/recoverymgr.comm" 

#define RECOVERYMGR_TLEN	8
#define RECOVERYMGR_OLEN	256

#define	RECOVERYMGR_CONNECT 	"conn"
#define	RECOVERYMGR_DISCONNECT	"disconn"
#define RECOVERYMGR_EVENT	"event"

#include <apphb_notify.h>

/** Generic (no parameter) recovery manager message */
struct recoverymgr_msg {
	char msgtype [RECOVERYMGR_TLEN];
};

/** Recovery manager connection message */
struct recoverymgr_connectmsg {
	char msgtype [RECOVERYMGR_TLEN];
	char appname [RECOVERYMGR_OLEN];
	char appinstance [RECOVERYMGR_OLEN];
	pid_t	pid;
	uid_t	uid;
	gid_t	gid;
};

/** 
 * The notification message used by 
 * the plugin to the recovery manager.
 * Message contains the *client's* information, not the 
 * recovery manager's info
 */
struct recoverymgr_event_msg {
	char msgtype [RECOVERYMGR_TLEN];
	char appname [RECOVERYMGR_OLEN];
	char appinstance [RECOVERYMGR_OLEN];
	pid_t	pid;
	uid_t	uid;
	gid_t	gid;
	apphb_event_t 	event;	
};

/** Recovery manager return code (errno) */
struct recoverymgr_rc {
	int	rc;
};
#endif /*  _CLPLUMBING_RECOVERYMGR_CS_H */

