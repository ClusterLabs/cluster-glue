/*
 * Copyright (C) 2001 Alan Robertson <alanr@unix.sh>
 * This software licensed under the GNU LGPL.
 *
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA *
 */

#ifndef LHA_INTERNAL_H
#  define LHA_INTERNAL_H

#define	EOS			'\0'
#define	DIMOF(a)		((int) (sizeof(a)/sizeof(a[0])) )
#define	STRLEN_CONST(conststr)  ((size_t)((sizeof(conststr)/sizeof(char))-1))
#define	STRNCMP_CONST(varstr, conststr) strncmp((varstr), conststr, STRLEN_CONST(conststr)+1)
#define	STRLEN(c)		STRLEN_CONST(c)
#define MALLOCT(t)		((t *) malloc(sizeof(t)))

#define HADEBUGVAL	"HA_DEBUG"	/* current debug value (if nonzero) */
#define HALOGD		"HA_LOGD"	/* whether we use logging daemon or not */

/* Needs to be defined before any other includes, otherwise some system
 * headers do not behave as expected! Major black magic... */
#undef _GNU_SOURCE  /* in case it was defined on the command line */
#define _GNU_SOURCE

/* Please leave this as the first #include - Solaris needs it there */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>
#ifdef BSD
#	define SCANSEL_CAST	(void *)
#else
#	define SCANSEL_CAST	/* Nothing */
#endif

#if defined(ANSI_ONLY) && !defined(inline)
#	define inline	/* nothing */
#	undef	NETSNMP_ENABLE_INLINE
#	define	NETSNMP_NO_INLINE 1
#endif

#ifndef HAVE_DAEMON
  /* We supply a replacement function, but need a prototype */
int daemon(int nochdir, int noclose);
#endif /* HAVE_DAEMON */

#ifndef HAVE_SETENV
  /* We supply a replacement function, but need a prototype */
int setenv(const char *name, const char * value, int why);
#endif /* HAVE_SETENV */

#ifndef HAVE_UNSETENV
  /* We supply a replacement function, but need a prototype */
int unsetenv(const char *name);
#endif /* HAVE_UNSETENV */

#ifndef HAVE_STRERROR
  /* We supply a replacement function, but need a prototype */
char * strerror(int errnum);
#endif /* HAVE_STRERROR */

#ifndef HAVE_SCANDIR
  /* We supply a replacement function, but need a prototype */
#  include <dirent.h>
int
scandir (const char *directory_name,
	struct dirent ***array_pointer,
	int (*select_function) (const struct dirent *),
#ifdef USE_SCANDIR_COMPARE_STRUCT_DIRENT
	/* This is what the Linux man page says */
	int (*compare_function) (const struct dirent**, const struct dirent**)
#else
	/* This is what the Linux header file says ... */
	int (*compare_function) (const void *, const void *)
#endif
	);
#endif /* HAVE_SCANDIR */

#ifndef HAVE_ALPHASORT
#  include <dirent.h>
int
alphasort(const void *dirent1, const void *dirent2);
#endif /* HAVE_ALPHASORT */

#ifndef HAVE_INET_PTON
  /* We supply a replacement function, but need a prototype */
int
inet_pton(int af, const char *src, void *dst);

#endif /* HAVE_INET_PTON */

#ifndef HAVE_STRNLEN
	size_t strnlen(const char *s, size_t maxlen);
#else
#	define USE_GNU
#endif

#ifndef HAVE_STRNDUP
	char *strndup(const char *str, size_t len);
#else
#	define USE_GNU
#endif
#ifndef HAVE_STRLCPY
	size_t strlcpy(char * dest, const char *source, size_t len);
#endif
#ifndef HAVE_STRLCAT
	size_t strlcat(char * dest, const char *source, size_t len);
#endif

#ifndef HAVE_NFDS_T 
	typedef unsigned int nfds_t;
#endif

#ifdef HAVE_STRUCT_UCRED_DARWIN
#	include <sys/utsname.h>
#	ifndef SYS_NMLN
#		define SYS_NMLN _SYS_NAMELEN
#	endif /* SYS_NMLN */
#endif

#define	POINTER_TO_SIZE_T(p)	((size_t)(p)) /*pointer cast as size_t*/
#define	POINTER_TO_SSIZE_T(p)	((ssize_t)(p)) /*pointer cast as ssize_t*/
#define	POINTER_TO_ULONG(p)	((unsigned long)(p)) /*pointer cast as unsigned long*/
	/* Sometimes we get a const g_something *, but need to pass it internally
	 * to other functions taking a non-const g_something *, which results
	 * with gcc and -Wcast-qual in a compile time warning, and with -Werror
	 * even to a compile time error.
	 * Workarounds have been to e.g. memcpy(&list, _list); or similar,
	 * the reason of which is non-obvious to the casual reader.
	 * This macro achieves the same, and annotates why it is done.
	 */
#define UNCONST_CAST_POINTER(t, p)	((t)(unsigned long)(p))

#define	HAURL(url)	HA_URLBASE url

/*
 * Some compilers may not have defined __FUNCTION__.
 */
#ifndef __FUNCTION__

/* Sun studio compiler */
# ifdef __SUNPRO_C
#  define __FUNCTION__ __func__
# endif

/* Similarly add your compiler here ... */

#endif

/* You may need to change this for your compiler */
#ifdef HAVE_STRINGIZE
#	define	ASSERT(X)	{if(!(X)) ha_assert(#X, __LINE__, __FILE__);}
#else
#	define	ASSERT(X)	{if(!(X)) ha_assert("X", __LINE__, __FILE__);}
#endif

/* shamelessly stolen from linux kernel */
/* Force a compilation error if condition is true */
#define BUILD_BUG_ON(condition) ((void)BUILD_BUG_ON_ZERO(condition))
/* Force a compilation error if condition is true, but also produce a
 * result (of value 0 and type size_t), so the expression can be used
 * e.g. in a structure initializer (or where-ever else comma expressions
 * aren't permitted). */
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:-!!(e); }))
#define BUILD_BUG_ON_NULL(e) ((void *)sizeof(struct { int:-!!(e); }))

#endif /* LHA_INTERNAL_H */
