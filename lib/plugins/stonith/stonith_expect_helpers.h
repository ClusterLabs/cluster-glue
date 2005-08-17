/* $Id: stonith_expect_helpers.h,v 1.4 2005/08/17 04:04:43 alan Exp $ */
/*
 * stonith_expect_helpers.h: Some common expect defines.
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

/* This is still somewhat ugly. It needs to be included after the PILS
 * definitions so that it can access them, but the code reduction seemed
 * to justify this. Hopefully it can be made somewhat more elegant
 * eventually. */

/*
 *	Many expect/telnet plugins use these defines and functions.
 */

#define	SEND(fd,s)	{						\
				if (Debug) {				\
					LOG(PIL_DEBUG			\
					,	"Sending [%s] (len %d)"	\
					,	(s)		\
					,	(int)strlen(s));	\
				}					\
				(void)write((fd), (s), strlen(s));		\
			}

#define	EXPECT(fd,p,t)	{						\
			if (StonithLookFor(fd, p, t) < 0)		\
				return(errno == ETIMEDOUT		\
			?	S_TIMEOUT : S_OOPS);			\
			}

#define	NULLEXPECT(fd,p,t)	{					\
				if (StonithLookFor(fd, p, t) < 0)	\
					return(NULL);			\
			}

#define	SNARF(fd,s, to)	{						\
				if (StonithScanLine(fd,to,(s),sizeof(s))\
				!=	S_OK){				\
					return(S_OOPS);			\
				}					\
			}

#define	NULLSNARF(fd,s, to){						\
				if (StonithScanLine(fd,to,(s),sizeof(s))\
				!=	S_OK) {				\
					return(NULL);			\
				}					\
			}

/* Look for any of the given patterns.  We don't care which */
static int
StonithLookFor(int fd, struct Etoken * tlist, int timeout)
{
	int	rc;

	if ((rc = EXPECT_TOK(fd, tlist, timeout, NULL, 0, Debug)) < 0) {
		LOG(PIL_CRIT, "%s %s %s"
		,	"Did not find string", tlist[0].string
		,	"from " DEVICE ".");
	}
	return(rc);
}

#ifndef DOESNT_USE_STONITHSCANLINE
/* Accept either a CR/NL or an NL/CR */
static struct Etoken CRNL[] =		{ {"\n\r",0,0},{"\r\n",0,0},{NULL,0,0}};

static int
StonithScanLine(int fd, int timeout, char * buf, int max)
{
	if (EXPECT_TOK(fd, CRNL, timeout, buf, max, Debug) < 0) {
		LOG(PIL_CRIT, "Could not read line from" DEVICE ".");
		return(S_OOPS);
	}
	return(S_OK);
}
#endif

#ifndef DOESNT_USE_STONITHKILLCOMM
static void
Stonithkillcomm(int *rdfd, int *wrfd, int *pid)
{
        if ((rdfd != NULL) && (*rdfd >= 0)) {
		close(*rdfd);
		*rdfd = -1;
	}
        if ((wrfd != NULL) && (*wrfd >= 0)) {
		close(*wrfd);
		*wrfd = -1;
	}
	if ((pid != NULL) && (*pid > 0)) {
		STONITH_KILL(*pid, SIGKILL);
		(void)waitpid(*pid, NULL, 0);
		*pid = -1;
	}
}
#endif
