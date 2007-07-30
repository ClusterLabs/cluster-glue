/*
 * stonith_plugin_common.h: common macros easing the writing of STONITH
 * 			    plugins. Only a STONITH plugin should
 * 			    include this header!
 *
 * Copyright (C) 2004 Lars Marowsky-Bree <lmb@suse.de>
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
#ifndef _STONITH_PLUGIN_COMMON_H
#define _STONITH_PLUGIN_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <libintl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <netdb.h>
#ifdef HAVE_TERMIO_H
#	include <termio.h>
#endif
#ifdef HAVE_SYS_TERMIOS_H
#include <sys/termios.h>
#else
#ifdef HAVE_TERMIOS_H
#include <termios.h>
#endif
#endif
#include <glib.h>


#include <stonith/stonith.h>
#include <stonith/stonith_plugin.h>

#define LOG(w...)	PILCallLog(PluginImports->log, w)

#define MALLOC		PluginImports->alloc
#define REALLOC		PluginImports->mrealloc
#define STRDUP  	PluginImports->mstrdup
#define FREE		PluginImports->mfree
#define EXPECT_TOK	OurImports->ExpectToken
#define STARTPROC	OurImports->StartProcess

#ifdef MALLOCT
#	undef	MALLOCT
#endif
#define	ST_MALLOCT(t)      ((t *)(MALLOC(sizeof(t)))) 

#define N_(text)	(text)
#define _(text)		dgettext(ST_TEXTDOMAIN, text)

#define WHITESPACE	" \t\n\r\f"

#ifndef MIN
/* some macros */
#	define MIN( i, j ) ( i > j ? j : i )
#endif

#define	REPLSTR(s,v) {					\
			if ((s) != NULL) {			\
				FREE(s);			\
				(s)=NULL;			\
			}					\
			(s) = STRDUP(v);			\
			if ((s) == NULL) {			\
				PILCallLog(PluginImports->log,	\
				PIL_CRIT, "out of memory");	\
			} 					\
		     }

#ifndef DEVICE
#define DEVICE "Dummy"
#endif

#define PIL_PLUGINTYPE          STONITH_TYPE
#define PIL_PLUGINTYPE_S        STONITH_TYPE_S

#define	ISCORRECTDEV(i)	((i)!= NULL				\
	&& ((struct pluginDevice *)(i))->pluginid == pluginid)

#define ERRIFWRONGDEV(s, retval) if (!ISCORRECTDEV(s)) { \
    LOG(PIL_CRIT, "%s: invalid argument", __FUNCTION__); \
    return(retval); \
  }

#define VOIDERRIFWRONGDEV(s) if (!ISCORRECTDEV(s)) { \
    LOG(PIL_CRIT, "%s: invalid argument", __FUNCTION__); \
    return; \
  }

#define	ISCONFIGED(i)	(i->isconfigured)

#define ERRIFNOTCONFIGED(s,retval) ERRIFWRONGDEV(s,retval); \
    if (!ISCONFIGED(s)) { \
    LOG(PIL_CRIT, "%s: not configured", __FUNCTION__); \
    return(retval); \
  }

#define VOIDERRIFNOTCONFIGED(s) VOIDERRIFWRONGDEV(s); \
    if (!ISCONFIGED(s)) { \
    LOG(PIL_CRIT, "%s: not configured", __FUNCTION__); \
    return; \
  }

#endif

