/* $Id: ttylock.h,v 1.2 2005/01/05 04:04:01 alan Exp $ */
#ifndef __CLPLUMBING_TTYLOCK_H
#	define __CLPLUMBING_LOCK_H
int	ttylock(const char *serial_device);
int	ttyunlock(const char *serial_device);
#endif	/* __CLPLUMBING_LOCK_H */
