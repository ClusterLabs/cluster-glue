/*
 * Basic Core dump control functions.
 *
 * Copyright (C) 2004 IBM Corporation
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
#ifndef _CLPLUMBING_COREFILES_H
#	define _CLPLUMBING_COREFILES_H 1
	/* Set the root directory of our core directory hierarchy */
int cl_set_corerootdir(const char * dir);
	/* Change directory to the directory our core file needs to go in */
	/* Call after you establish the userid you're running under */
int cl_cdtocoredir(void);
	/* Enable/disable core dumps for ourselves and our child processes */
int cl_enable_coredumps(int truefalse);
void cl_untaint_coredumps(void);
void cl_set_coredump_signal_handler(int nsig);
void cl_set_all_coredump_signal_handlers(void);

#endif
