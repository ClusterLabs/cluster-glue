#ifndef CLPLUMBING_UIDS_H
#	define CLPLUMBING_UIDS_H
#include <sys/types.h>

int drop_privs(uid_t uid, gid_t gid);
int return_to_orig_privs(void);
int return_to_dropped_privs(void);
#endif
