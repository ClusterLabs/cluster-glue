/*
 * setproctitle.h
 *
 * The code in this file, setproctitle.h is heavily based on code from
 * proftpd, please see the licening information below.
 *
 * This file added to the heartbeat tree by Horms <horms@vergenet.net>
 *
 * Code to portably change the title of a programme as displayed
 * by ps(1).
 *
 * heartbeat: Linux-HA heartbeat code
 *
 * Copyright (C) 1999,2000,2001 Alan Robertson <alanr@unix.sh>
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

/*
 * ProFTPD - FTP server daemon
 * Copyright (c) 1997, 1998 Public Flood Software
 * Copyright (C) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
 *  
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, Public Flood Software/MacGyver aka Habeeb J. Dihu
 * and other respective copyright holders give permission to link this program
 * with OpenSSL, and distribute the resulting executable, without including
 * the source code for OpenSSL in the source distribution.
 */

#ifndef _HA_SETPROCTITLE_H
#define _HA_SETPROCTITLE_H

#include <glib.h>
int init_set_proc_title(int argc, char *argv[], char *envp[]);

void set_proc_title(const char *fmt,...) G_GNUC_PRINTF(1,2);

#endif /* _HA_SETPROCTITLE_H */
