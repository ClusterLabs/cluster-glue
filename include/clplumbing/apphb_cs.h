/* $Id: apphb_cs.h,v 1.9 2004/11/08 09:07:51 sunjd Exp $ */
/*
 * Copyright (C) 2002 Alan Robertson <alanr@unix.sh>
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

#ifndef _CLPLUMBING_APPHB_CS_H
#define _CLPLUMBING_APPHB_CS_H

/* Internal client-server messages for APP heartbeat service */

#ifndef HA_VARLIBDIR
#define HA_VARLIBDIR "/var/lib"
#endif
#define APPHBSOCKPATH		HA_VARLIBDIR "/heartbeat/apphb.comm"

#define APPHB_TLEN	8
#define APPHB_OLEN	256

#define	REGISTER	"reg"
#define	UNREGISTER	"unreg"
#define	HEARTBEAT	"hb"
#define	SETINTERVAL	"setint"
#define	SETWARNTIME	"setwarn"

/*
 * These messages are really primitive.
 * They don't have any form of version control, they're in host byte order,
 * and they're all in binary...
 *
 * Fortunately, this is a very simple local service ;-)
 */

/* Generic (no parameter) App heartbeat message */
struct apphb_msg {
	char msgtype [APPHB_TLEN];
};

/* App heartbeat Registration message */
struct apphb_signupmsg {
	char msgtype [APPHB_TLEN];
	char appname [APPHB_OLEN];
	char appinstance [APPHB_OLEN];
	char curdir [APPHB_OLEN];
	pid_t	pid;
	uid_t	uid;
	gid_t	gid;
};

/* App heartbeat setinterval / setwarn message */
struct apphb_msmsg {
	char	msgtype [APPHB_TLEN];
	unsigned long	ms;
};

/* App heartbeat server return code (errno) */
struct apphb_rc {
	int	rc;
};
#endif
