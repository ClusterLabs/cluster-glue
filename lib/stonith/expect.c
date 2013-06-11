/*
 * Simple expect module for the STONITH library
 *
 *	Copyright (c) 2000 Alan Robertson <alanr@unix.sh>
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

#include <lha_internal.h>
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stonith/st_ttylock.h>
#include <clplumbing/longclock.h>
#define ENABLE_PIL_DEFS_PRIVATE
#include <pils/plugin.h>

#ifdef _POSIX_PRIORITY_SCHEDULING
#	include <sched.h>
#endif

#include <stonith/stonith.h>
#include <stonith/stonith_plugin.h>

extern 	PILPluginUniv*	StonithPIsys;

#define	LOG(args...)   PILCallLog(StonithPIsys->imports->log, args)
#define DEBUG(args...) LOG(PIL_DEBUG, args)
#undef DEBUG
#define	DEBUG(args...) PILCallLog(StonithPIsys->imports->log, PIL_DEBUG, args)
#define MALLOC	       StonithPIsys->imports->alloc
#define REALLOC	       StonithPIsys->imports->mrealloc
#define STRDUP         StonithPIsys->imports->mstrdup
#define FREE(p)	       {StonithPIsys->imports->mfree(p); (p) = NULL;}

#ifdef	TIMES_ALLOWS_NULL_PARAM
#	define	TIMES_PARAM	NULL
#else
	static struct tms	dummy_longclock_tms_struct;
#	define	TIMES_PARAM	&dummy_longclock_tms_struct
#endif

static unsigned long
our_times(void)	/* Make times(2) behave rationally on Linux */
{
	clock_t		ret;
#ifndef DISABLE_TIMES_KLUDGE
	int		save_errno = errno;

	/*
	 * This code copied from clplumbing/longclock.c to avoid
	 * making STONITH depend on clplumbing.  See it for an explanation
	 */
	
	errno	= 0;
#endif /* DISABLE_TIMES_KLUDGE */

	ret	= times(TIMES_PARAM);

#ifndef DISABLE_TIMES_KLUDGE
	if (errno != 0) {
		ret = (clock_t) (-errno);
	}
	errno = save_errno;
#endif /* DISABLE_TIMES_KLUDGE */
	return (unsigned long)ret;
}

/*
 *	Look for ('expect') any of a series of tokens in the input
 *	Return the token type for the given token or -1 on error.
 */

static int
ExpectToken(int	fd, struct Etoken * toklist, int to_secs, char * savebuf
,	int maxline, int Debug)
{
	unsigned long	starttime;
	unsigned long	endtime;
	int		wraparound=0;
	unsigned	Hertz = sysconf(_SC_CLK_TCK);
	int		tickstousec = (1000000/Hertz);
	unsigned long	now;
	unsigned long	ticks;
	int		nchars = 1; /* reserve space for an EOS */
	struct timeval	tv;
	char *		buf = savebuf;

	struct Etoken *	this;

	/* Figure out when to give up.  Handle lbolt wraparound */

	starttime = our_times();
	ticks = (to_secs*Hertz);
	endtime = starttime + ticks;

	if (endtime < starttime) {
		wraparound = 1;
	}

	if (buf) {
		*buf = EOS;
	}

	for (this=toklist; this->string; ++this) {
		this->matchto = 0;
	}


	while (now = our_times(),
		(wraparound && (now > starttime || now <= endtime))
		||	(!wraparound && now <= endtime)) {

		fd_set infds;
		char	ch;
		unsigned long	timeleft;
		int		retval;

		timeleft = endtime - now;

		tv.tv_sec = timeleft / Hertz;
		tv.tv_usec = (timeleft % Hertz) * tickstousec;

		if (tv.tv_sec == 0 && tv.tv_usec < tickstousec) {
			/* Give 'em a little chance */
			tv.tv_usec = tickstousec;
		}

		/* Watch our FD to see when it has input. */
           	FD_ZERO(&infds);
           	FD_SET(fd, &infds);

		retval = select(fd+1, &infds, NULL, NULL, &tv); 
		if (retval <= 0) {
			errno = ETIMEDOUT;
			return(-1);
		}
		/* Whew!  All that work just to read one character! */
		
		if (read(fd, &ch, sizeof(ch)) <= 0) {
			return(-1);
		}
		/* Save the text, if we can */
		if (buf && nchars < maxline-1) {
			*buf = ch;
			++buf;
			*buf = EOS;
			++nchars;
		}
		if (Debug > 1) {
			DEBUG("Got '%c'", ch);
		}

		/* See how this character matches our expect strings */

		for (this=toklist; this->string; ++this) {

			if (ch == this->string[this->matchto]) {

				/* It matches the current token */

			 	++this->matchto;
				if (this->string[this->matchto] == EOS){
					/* Hallelujah! We matched */
					if (Debug) {
						DEBUG("Matched [%s] [%d]"
						,	this->string
						,	this->toktype);
						if (savebuf) {
							DEBUG("Saved [%s]"
							,	savebuf);
						}
					}
					return(this->toktype);
				}
			}else{

				/* It doesn't appear to match this token */

				int	curlen;
				int	nomatch=1;
				/*
				 * If we already had a match (matchto is
				 * greater than zero), we look for a match
				 * of the tail of the pattern matched so far
				 * (with the current character) against the
				 * head of the pattern.
				 */

				/*
				 * This is to make the string "aab" match
				 * the pattern "ab" correctly 
				 * Painful, but nice to do it right.
				 */

				for (curlen = (this->matchto)
				;	nomatch && curlen >= 0
				;	--curlen) 			{
					const char *	tail;
					tail=(this->string)
					+	this->matchto
					-	curlen;

					if (strncmp(this->string, tail
					,	curlen) == 0
					&&	this->string[curlen] == ch)  {
						
						if (this->string[curlen+1]==EOS){
							/* We matched!  */
							/* (can't happen?) */
							return(this->toktype);
						}
						this->matchto = curlen+1;
						nomatch=0;
					}
				}
				if (nomatch) {
					this->matchto = 0;
				}
			}
		}
	}
	errno = ETIMEDOUT;
	return(-1);
}

/*
 * Start a process with its stdin and stdout redirected to pipes
 * so the parent process can talk to it.
 */
static int
StartProcess(const char * cmd, int * readfd, int * writefd)
{
	pid_t	pid;
	int	wrpipe[2];	/* The pipe the parent process writes to */
				/* (which the child process reads from) */
	int	rdpipe[2];	/* The pipe the parent process reads from */
				/* (which the child process writes to) */

	if (pipe(wrpipe) < 0) {
		perror("cannot create pipe\n");
		return(-1);
	}
	if (pipe(rdpipe) < 0) {
		perror("cannot create pipe\n");
		close(wrpipe[0]);
		close(wrpipe[1]);
		return(-1);
	}
	switch(pid=fork()) {

		case -1:	perror("cannot StartProcess cmd");
				close(rdpipe[0]);
				close(wrpipe[1]);
				close(wrpipe[0]);
				close(rdpipe[1]);
				return(-1);

		case 0:		/* We are the child */

				/* Redirect stdin */
				close(0);
				dup2(wrpipe[0], 0);
				close(wrpipe[0]);
				close(wrpipe[1]);

				/* Redirect stdout */
				close(1);
				dup2(rdpipe[1], 1);
				close(rdpipe[0]);
				close(rdpipe[1]);
#if defined(SCHED_OTHER) && !defined(ON_DARWIN)
			{
				/*
				 * Try and (re)set our scheduling to "normal"
				 * Sometimes our callers run in soft
				 * real-time mode.  The program we exec might
				 * not be very well behaved - this is bad for
				 * operation in high-priority (soft real-time)
				 * mode.  In particular, telnet is prone to
				 * going into infinite loops when killed.
				 */
				struct sched_param	sp;
				memset(&sp, 0, sizeof(sp));
				sp.sched_priority = 0;
				sched_setscheduler(0, SCHED_OTHER, &sp);
			}
#endif
				execlp("/bin/sh", "sh", "-c", cmd, (const char *)NULL);
				perror("cannot exec shell!");
				exit(1);

		default:	/* We are the parent */
				*readfd = rdpipe[0];
				close(rdpipe[1]);

				*writefd = wrpipe[1];
				close(wrpipe[0]);
				return(pid);
	}
	/*NOTREACHED*/
	return(-1);
}

static char **
stonith_copy_hostlist(const char * const * hostlist)
{
	int hlleng = 1;
	const char * const * here = hostlist;
	char ** hret;
	char **	ret;

	for (here = hostlist; *here; ++here) {
		++hlleng;
	}
	ret = (char**)MALLOC(hlleng * sizeof(char *));
	if (ret == NULL) {
		return ret;
	}
	
	hret = ret;
	for (here = hostlist; *here; ++here,++hret) {
		*hret = STRDUP(*here);
		if (*hret == NULL) {
			stonith_free_hostlist(ret);
			return NULL; 
		}
	}
	*hret = NULL;
	return ret;
}

static char **
StringToHostList(const char * s)
{
	const char *	here;
	int		hlleng = 0;
	char **		ret;
	char **		hret;
	const char *	delims = " \t\n\f\r,";

	/* Count the number of strings (words) in the result */
	here = s;
	while (*here != EOS) {
		/* skip delimiters */
		here += strspn(here, delims);
		if (*here == EOS) {
			break;
		}
		/* skip over substring proper... */
		here += strcspn(here, delims);
		++hlleng;
	}


	/* Malloc space for the result string pointers */
	ret = (char**)MALLOC((hlleng+1) * sizeof(char *));
	if (ret == NULL) {
		return NULL;
	}
	
	hret = ret;
	here = s;

	/* Copy each substring into a separate string */
	while (*here != EOS) {
		int	slen;	/* substring length */

		/* skip delimiters */
		here += strspn(here, delims);
		if (*here == EOS) {
			break;
		}
		/* Compute substring length */
		slen = strcspn(here, delims);
		*hret = MALLOC((slen+1) * sizeof(char));
		if (*hret == NULL) {
			stonith_free_hostlist(hret);
			return NULL; 
		}
		/* Copy string (w/o EOS) */
		memcpy(*hret, here, slen);
		/* Add EOS to result string */
		(*hret)[slen] = EOS;
		strdown(*hret);
		here += slen;
		++hret;
	}
	*hret = NULL;
	return ret;
}


static const char *
GetValue(StonithNVpair* parameters, const char * name)
{
	while (parameters->s_name) {
		if (strcmp(name, parameters->s_name) == 0) {
			return parameters->s_value;
		}
		++parameters;
	}
	return NULL;
}

static int
CopyAllValues(StonithNamesToGet* output, StonithNVpair * input)
{
	int	j;
	int	rc;

	for (j=0; output[j].s_name; ++j) {
		const char * value = GetValue(input, output[j].s_name);
		if (value == NULL) {
			rc = S_INVAL;
			output[j].s_value = NULL;
			goto fail;
		}
		if ((output[j].s_value = STRDUP(value)) == NULL) {
			rc = S_OOPS;
			goto fail;
		}
	}
	return S_OK;

fail:
	for (j=0; output[j].s_value; ++j) {
		FREE(output[j].s_value);
	}
	return rc;
}


static int
OpenStreamSocket(const char * host, int port, const char * service)
{
	union s_un {
		struct sockaddr_in	si4;
		struct sockaddr_in6	si6;
	}sockun;
	int			sock;
	int			addrlen = -1;


	memset(&sockun, 0, sizeof(sockun));

	if (inet_pton(AF_INET, host, (void*)&sockun.si4.sin_addr) < 0) {
		sockun.si4.sin_family = AF_INET;
	}else if (inet_pton(AF_INET6, host, (void*)&sockun.si6.sin6_addr)<0){
		sockun.si6.sin6_family = AF_INET6;
	}else{
		struct hostent*	hostp = gethostbyname(host);
		if (hostp == NULL) {
			errno = EINVAL;
			return -1;
		}
		sockun.si4.sin_family = hostp->h_addrtype;
		memcpy(&sockun.si4.sin_addr, hostp->h_addr, hostp->h_length);
	}
	if ((sock = socket(sockun.si4.sin_family, SOCK_STREAM, 0)) < 0) {
		return -1;
	}
	if (service != NULL) {
		struct servent*	se = getservbyname(service, "tcp");
		if (se != NULL) {
			/* We convert it back later... */
			port = ntohs(se->s_port);
		}
	}
	if (port <= 0) {
		errno = EINVAL;
		return -1;
	}
	port = htons(port);
	if (sockun.si6.sin6_family == AF_INET6) {
		sockun.si6.sin6_port = port;
		addrlen = sizeof(sockun.si6);
	}else if (sockun.si4.sin_family == AF_INET) {
		sockun.si4.sin_port = port;
		addrlen = sizeof(sockun.si4);
	}else{
		errno = EINVAL;
		return -1;
	}
		
	if (connect(sock, (struct sockaddr*)(&sockun), addrlen)< 0){
		int	save = errno;
		perror("connect() failed");
		close(sock);
		errno = save;
		return -1;
	}
	return sock;
}

StonithImports		stonithimports = {
	ExpectToken,
	StartProcess,
	OpenStreamSocket,
	GetValue,
	CopyAllValues,
	StringToHostList,
	stonith_copy_hostlist,
	stonith_free_hostlist,
	st_ttylock,
	st_ttyunlock
};
