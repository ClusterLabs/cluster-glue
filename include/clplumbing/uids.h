/* $Id: uids.h,v 1.8 2004/02/17 22:11:58 lars Exp $ */
#ifndef CLPLUMBING_UIDS_H
#	define CLPLUMBING_UIDS_H
#include <sys/types.h>

/* Tell us who you want to be - or zero for nobody */
int drop_privs(uid_t uid, gid_t gid);

/* Return to original privileged state */
int return_to_orig_privs(void);

/* Drop down to (probably nobody) privileges again */
int return_to_dropped_privs(void);

/* Return TRUE if we have full privileges at the moment */
int cl_have_full_privs(void);
#endif
