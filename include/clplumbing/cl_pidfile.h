#ifndef _LOCKFILE_H_
#define _LOCKFILE_H_

int	cl_read_pidfile(const char *filename);
int	cl_lock_pidfile(const char *filename);
int	cl_unlock_pidfile(const char *filename);

#endif
