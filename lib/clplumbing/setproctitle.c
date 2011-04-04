/*
 * setproctitle.c
 *
 * The code in this file, setproctitle.c is heavily based on code from
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

#include <lha_internal.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>

#define PF_ARGV_NONE            0
#define PF_ARGV_NEW             1
#define PF_ARGV_WRITEABLE       2
#define PF_ARGV_PSTAT           3
#define PF_ARGV_PSSTRINGS       4

#if PF_ARGV_TYPE == PF_ARGV_PSTAT
#	include <pstat.h>
#endif

#include <clplumbing/setproctitle.h>

#if PF_ARGV_TYPE != PF_ARGV_NONE
static char **Argv = NULL;
static char *LastArgv = NULL;
#endif /* PF_ARGV_TYPE != PF_ARGV_NONE */

extern char **environ;

#ifdef HAVE___PROGNAME
extern char *__progname;
extern char *__progname_full;
#endif /* HAVE___PROGNAME */

int 
init_set_proc_title(int argc, char *argv[], char *envp[])
{
#if PF_ARGV_TYPE == PF_ARGV_NONE
	return 0;
#else
	int i;
	int envpsize;
	char **p;
  
	/* Move the environment so setproctitle can use the space.
	 */
	for(i = envpsize = 0; envp[i] != NULL; i++) {
		envpsize += strlen(envp[i]) + 1;
	}
  
	p = (char **) malloc((i + 1) * sizeof(char *));
	if (p == NULL) {
		return -1;
	}

	environ = p;

	for(i = 0; envp[i] != NULL; i++) {
		environ[i] = strdup(envp[i]);
		if(environ[i] == NULL) {
			goto error_environ;
		}
	}
	environ[i] = NULL;
  
	Argv = argv;
  
	for(i = 0; i < argc; i++) {
		if(!i || (LastArgv + 1 == argv[i]))
			LastArgv = argv[i] + strlen(argv[i]);
	}
  
	for(i = 0; envp[i] != NULL; i++) {
		if((LastArgv + 1) == envp[i]) {
			LastArgv = envp[i] + strlen(envp[i]);
		}
	}
  
#ifdef HAVE___PROGNAME
  	/* Set the __progname and __progname_full variables so glibc and 
	 * company don't go nuts. - MacGyver
	 */
	
	__progname = strdup("heartbeat");
	if (__progname == NULL) {
		goto error_environ;
	}
	__progname_full = strdup(argv[0]);
	if (__progname_full == NULL) {
		goto error_environ;
	}
#endif /* HAVE___PROGNAME */
  
	return 0;

error_environ:
	for(i = 0; environ[i] != NULL; i++) {
      		free(environ[i]);
	}
	free(environ);
	return -1;
#endif /* PF_ARGV_TYPE == PF_ARGV_NONE */
}    

void set_proc_title(const char *fmt,...)
{
#if PF_ARGV_TYPE != PF_ARGV_NONE
  va_list msg;
  static char statbuf[BUFSIZ];
  
#ifndef HAVE_SETPROCTITLE
#if PF_ARGV_TYPE == PF_ARGV_PSTAT
   union pstun pst;
#endif /* PF_ARGV_PSTAT */
  int i,maxlen = (LastArgv - Argv[0]) - 2;
  char *p;
#endif /* HAVE_SETPROCTITLE */

  va_start(msg,fmt);

  memset(statbuf, 0, sizeof(statbuf));


#ifdef HAVE_SETPROCTITLE
# if __FreeBSD__ >= 4 && !defined(FREEBSD4_0) && !defined(FREEBSD4_1)
  /* FreeBSD's setproctitle() automatically prepends the process name. */
  vsnprintf(statbuf, sizeof(statbuf), fmt, msg);

# else /* FREEBSD4 */
  /* Manually append the process name for non-FreeBSD platforms. */
  vsnprintf(statbuf + strlen(statbuf), sizeof(statbuf) - strlen(statbuf),
    fmt, msg);

# endif /* FREEBSD4 */
  setproctitle("%s", statbuf);

#else /* HAVE_SETPROCTITLE */
  /* Manually append the process name for non-setproctitle() platforms. */
  vsnprintf(statbuf + strlen(statbuf), sizeof(statbuf) - strlen(statbuf),
    fmt, msg);

#endif /* HAVE_SETPROCTITLE */

  va_end(msg);
  
#ifdef HAVE_SETPROCTITLE
  return;
#else
  i = strlen(statbuf);

#if PF_ARGV_TYPE == PF_ARGV_NEW
  /* We can just replace argv[] arguments.  Nice and easy.
   */
  Argv[0] = statbuf;
  Argv[1] = NULL;
#endif /* PF_ARGV_NEW */

#if PF_ARGV_TYPE == PF_ARGV_WRITEABLE
  /* We can overwrite individual argv[] arguments.  Semi-nice.
   */
  snprintf(Argv[0], maxlen, "%s", statbuf);
  p = &Argv[0][i];
  
  while(p < LastArgv)
    *p++ = '\0';
  Argv[1] = NULL;
#endif /* PF_ARGV_WRITEABLE */

#if PF_ARGV_TYPE == PF_ARGV_PSTAT
  pst.pst_command = statbuf;
  pstat(PSTAT_SETCMD, pst, i, 0, 0);
#endif /* PF_ARGV_PSTAT */

#if PF_ARGV_TYPE == PF_ARGV_PSSTRINGS
  PS_STRINGS->ps_nargvstr = 1;
  PS_STRINGS->ps_argvstr = statbuf;
#endif /* PF_ARGV_PSSTRINGS */

#endif /* HAVE_SETPROCTITLE */

#endif /* PF_ARGV_TYPE != PF_ARGV_NONE */
}
