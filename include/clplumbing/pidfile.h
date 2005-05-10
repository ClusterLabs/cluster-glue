#ifndef _LOCKFILE_H_
#define _LOCKFILE_H_

int	read_pidfile(const char *filename);
int	lock_pidfile(const char *filename);
int	unlock_pidfile(const char *filename);

#endif
