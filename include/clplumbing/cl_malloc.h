/* $Id: cl_malloc.h,v 1.6 2006/07/07 20:36:31 andrew Exp $ */
/*
 * ha_malloc.h: malloc utilities for the Linux-HA heartbeat program
 *
 * Copyright (C) 2000 Alan Robertson <alanr@unix.sh>
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
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#ifndef _CLPLUMBING_CLMALLOC_H
#define	 _CLPLUMBING_CLMALLOC_H

typedef struct cl_mem_stats_s {
	unsigned long		numalloc;	/* # of cl_malloc calls */
	unsigned long		numfree;	/* # of cl_free calls */
	unsigned long		numrealloc;	/* # of cl_realloc calls */
	unsigned long		nbytes_req;	/* # malloc bytes req'd */
	unsigned long		nbytes_alloc;	/* # bytes currently allocated
						 */
	unsigned long		mallocbytes;	/* total # bytes malloc()ed */
	unsigned long		arena;		/* Most recent mallinfo */
						/* arena value */
}cl_mem_stats_t;

/* This allows the code to track _all_ allocated memory, who allocated
 * it and from where in the code it was allocated. It is a very memory
 * expensive debugging tool and NOT! meant for production: */
#undef HA_MALLOC_TRACK

void*		cl_malloc(size_t size);
void*		cl_calloc(size_t nmemb, size_t size);
void*		cl_realloc(void* oldval, size_t newsize);
#ifdef HA_MALLOC_TRACK
void*		cl_malloc_track(size_t size, 
		const char *file, const char *function, const int line);
void*		cl_calloc_track(size_t nmemb, size_t size,
		const char *file, const char *function, const int line);
void*		cl_realloc_track(void* oldval, size_t newsize,
		const char *file, const char *function, const int line);
#ifndef	HA_MALLOC_ORIGINAL
#define		cl_malloc(s) cl_malloc_track(s, \
		__FILE__, __PRETTY_FUNCTION__, __LINE__)
#define		cl_calloc(n,s) cl_calloc_track(n,s, \
		__FILE__, __PRETTY_FUNCTION__, __LINE__)
#define		cl_realloc(o,s) cl_realloc_track(o,s, \
		__FILE__, __PRETTY_FUNCTION__, __LINE__)
#endif
#endif
char*		cl_strdup(const char *s);
void		cl_free(void *ptr);
int		cl_is_allocated(const void *ptr);
void		cl_malloc_report(void);
void		cl_malloc_setstats(volatile cl_mem_stats_t*);
volatile cl_mem_stats_t* cl_malloc_getstats(void);
void		cl_malloc_forced_for_glib(void);
		/* Call before using any glib functions(!) */
		/* See also: g_mem_set_vtable() */
#ifdef HA_MALLOC_TRACK
void		 cl_malloc_dump_allocated(int log_level, int filter_seen);
#endif

#define	MALLOCT(t)	((t *) cl_malloc(sizeof(t)))

/* Obsolescent names for cl_malloc, et al... */
#define	ha_malloc	cl_malloc
#define	ha_calloc	cl_calloc
#define	ha_strdup	cl_strdup
#define	ha_free		cl_free
#define	ha_is_allocated	cl_is_allocated
#define	ha_malloc_report	cl_malloc_report
#define	ha_malloc_setstats	cl_malloc_setstats

#endif /* _CLPLUMBING_CLMALLOC_H */
