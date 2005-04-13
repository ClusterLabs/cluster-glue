/* $Id: st_ttylock.h,v 1.1 2005/04/13 23:21:47 alan Exp $ */
#ifndef __STONITH_ST_TTYLOCK_H
#	define __STONITH_ST_TTYLOCK_H
int	st_ttylock(const char *serial_device);
int	st_ttyunlock(const char *serial_device);
#endif	/*__STONITH_ST_TTYLOCK_H*/
