/* $Id: stonith_plugin_common.h,v 1.1 2004/10/05 14:26:17 lars Exp $ */
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

#include <portability.h>
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
#include <sys/termios.h>
#include <glib.h>


#include <stonith/stonith.h>

#define LOG(w...)	PILCallLog(PluginImports->log, w)

#define MALLOC		PluginImports->alloc
#define STRDUP  	PluginImports->mstrdup
#define FREE		PluginImports->mfree
#define EXPECT_TOK	OurImports->ExpectToken
#define STARTPROC	OurImports->StartProcess

#ifndef MALLOCT
#	define     MALLOCT(t)      ((t *)(MALLOC(sizeof(t)))) 
#endif

#define N_(text)	(text)
#define _(text)		dgettext(ST_TEXTDOMAIN, text)

#define WHITESPACE	" \t\n\r\f"

#ifndef MIN
/* some macros */
#	define MIN( i, j ) ( i > j ? j : i )
#endif

#define	REPLSTR(s,v)	{					\
			if ((s) != NULL) {			\
				FREE(s);			\
				(s)=NULL;			\
			}					\
			(s) = STRDUP(v);			\
			if ((s) == NULL) {			\
				PILCallLog(PluginImports->log,PIL_CRIT, "%s",  _("out of memory"));\
			} 					\
			}

#ifndef DEVICE
#define DEVICE "Dummy"
#endif

#define PIL_PLUGINTYPE          STONITH_TYPE
#define PIL_PLUGINTYPE_S        STONITH_TYPE_S

#define	ISCORRECTDEV(i)	(((i)!= NULL && (i)->pinfo != NULL)	\
	&& ((struct pluginDevice *)(i->pinfo))->pluginid == pluginid)

#define ERRIFWRONGDEV(s,retval) if (!ISCORRECTDEV(s)) { \
    LOG(PIL_CRIT, "%s: invalid argument", __FUNCTION__); \
    return(retval); \
  }

#define VOIDERRIFWRONGDEV(s) if (!ISCORRECTDEV(s)) { \
    LOG(PIL_CRIT, "%s: invalid argument", __FUNCTION__); \
    return; \
  }

#define	ISCONFIGED(i)	(((struct pluginDevice *)(i->pinfo))->config)

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

