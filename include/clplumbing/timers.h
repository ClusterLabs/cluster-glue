/* $Id: timers.h,v 1.3 2004/02/17 22:11:58 lars Exp $ */
#ifndef _CLPLUMBING_TIMERS_H
#	define _CLPLUMBING_TIMERS_H
int	setmsrepeattimer(long ms);
int	setmsalarm(long ms);
int	cancelmstimer(void);
long	mssleep(long ms);
#endif
