#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>
#define	NOBODY	"nobody"

int become_nobody(uid_t uid);
int return_to_root(void);

int
become_nobody(uid_t uid)
{
	if (uid <= 0) {
		struct passwd*	p;

		p = getpwnam(NOBODY);

		if (p == NULL) {
			return -1;
		}
		uid = p->pw_uid;
	}
	return setuid(uid);
}

int
return_to_root()
{
	return setuid(0);
}
