#ifndef _CLPLUMBING_TIMERS_H
#	define _CLPLUMBING_TIMERS_H
int	setmsrepeattimer(long ms);
int	setmsalarm(long ms);
int	cancelmstimer(void);
long	mssleep(long ms);
#endif
