/* $Id: mkstemp_mode.h,v 1.2 2004/02/17 22:11:58 lars Exp $ */
/*
 * A slightly safer version of mkstemp(3)
 *
 * In this version, the file is initially created mode 0, (using umask) and
 * then chmod-ed to the requested permissions after calling mkstemp(3).
 * This guarantees that the file is not even momentarily open beyond the
 * requested permissions.
 *
 * Return values:
 *
 * Like mkstemp, it returns the file descriptor of the open file, or -1
 * on error.
 *
 * In addition to the errno values documented for mkstemp(3), this functio
 * can also fail with any of the errno values documented for chmod(2).
 *
 */
int mkstemp_mode(char* template, mode_t requested_filemode);
