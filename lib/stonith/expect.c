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

#include <portability.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <libintl.h>
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
#ifdef _POSIX_PRIORITY_SCHEDULING
#	include <sched.h>
#endif

#include <stonith/stonith.h>


/*
 *	Look for ('expect') any of a series of tokens in the input
 *	Return the token type for the given token or -1 on error.
 */

static int
ExpectToken(int	fd, struct Etoken * toklist, int to_secs, char * buf
,	int maxline)
{
	/*
	 * We use unsigned long instead of clock_t here because it's signed,
	 * but the return value from times() is basically unsigned...
	 * This is broken, but according to POSIX ;-)
	 */
	unsigned long	starttime;
	unsigned long	endtime;
	int		wraparound=0;
	unsigned	hz =  sysconf(_SC_CLK_TCK);
	int		tickstousec = (1000000/hz);
	unsigned long	now;
	unsigned long	ticks;
	int		nchars = 1; /* reserve space for an EOS */
	struct timeval	tv;

	struct Etoken *	this;

	/* Figure out when to give up.  Handle lbolt wraparound */

	starttime = times(NULL);
	ticks = (to_secs*hz);
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


	while (now = times(NULL),
		(wraparound && (now > starttime || now <= endtime))
		||	(!wraparound && now <= endtime)) {

		fd_set infds;
		char	ch;
		unsigned long	timeleft;
		int		retval;

		timeleft = endtime - now;

		tv.tv_sec = timeleft / hz;
		tv.tv_usec = (timeleft % hz) * tickstousec;

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
#if 0
		fprintf(stderr, "%c", ch);
#endif

		/* See how this character matches our expect strings */

		for (this=toklist; this->string; ++this) {

			if (ch == this->string[this->matchto]) {

				/* It matches the current token */

			 	++this->matchto;
				if (this->string[this->matchto] == EOS){
					/* Hallelujah! We matched */
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
#if defined(SCHED_OTHER)
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

StonithImports		stonithimports = {
	ExpectToken,
	StartProcess,
};
