#ifndef CLPLUMBING_UIDS_H
#	define CLPLUMBING_UIDS_H
#include <sys/types.h>

int become_nobody(uid_t uid);
int return_to_root(void);
#endif
