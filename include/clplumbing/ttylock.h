/* $Id: ttylock.h,v 1.1 2004/03/25 08:20:34 alan Exp $ */
#ifndef __CLPLUMBING_TTYLOCK_H
#	define __CLPLUMBING_LOCK_H
int	ttylock(const char *serial_device);
int	ttyunlock(const char *serial_device);
int	DoLock(const char * prefix, const char *lockname);
int	DoUnlock(const char * prefix, const char *lockname);
#endif	/* __CLPLUMBING_LOCK_H */
