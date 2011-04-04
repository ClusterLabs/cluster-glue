/* 
 * Copyright (C) 2007 Andrew Beekhof <andrew@beekhof.net>
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
#undef _GNU_SOURCE  /* in case it was defined on the command line */
#define _GNU_SOURCE
#include <lha_internal.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <glib.h>
#include <clplumbing/cl_log.h>
#include <clplumbing/cl_poll.h>
#include <clplumbing/GSource.h>
#include <clplumbing/ipc.h>
#include <clplumbing/realtime.h>
#include <clplumbing/lsb_exitcodes.h>
#include <errno.h>

#define	MAXERRORS	1000
#define MAX_IPC_FAIL    10
#define FIFO_LEN        1024

extern const char *procname;

extern const char *commdir;

void trans_getargs(int argc, char **argv);

void default_ipctest_input_destroy(gpointer user_data);

IPC_Message * create_simple_message(const char *text, IPC_Channel *ch);
